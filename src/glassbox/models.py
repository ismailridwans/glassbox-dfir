"""Core data contracts for GLASSBOX.

These pydantic models are the *only* way findings, tool executions, and
provenance move through the system. The key invariant lives in :class:`Finding`:
a finding cannot exist without ``provenance`` pointing at the concrete
:class:`ToolExecution` (and the raw output span) that produced it. The
hallucination verifier (``glassbox.verify``) enforces that the cited span is
actually present in the captured raw output before any finding is allowed into
a report. That is the architectural anti-hallucination guarantee.
"""

from __future__ import annotations

import datetime as _dt
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with a trailing Z. Used for every audit record."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class ToolStatus(str, Enum):
    """Outcome of a single tool execution. DEGRADED/UNAVAILABLE drive graceful
    degradation in the orchestrator instead of crashing the run."""

    OK = "OK"
    DEGRADED = "DEGRADED"        # ran but partial/low-confidence output
    UNAVAILABLE = "UNAVAILABLE"  # underlying SIFT binary not installed
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class Confidence(str, Enum):
    """Verification verdict assigned by the hallucination gate.

    CONFIRMED   - directly observed in a tool's captured raw output.
    INFERRED    - derived/correlated from CONFIRMED facts (e.g. a discrepancy).
    UNVERIFIED  - claimed but not yet checked (must not appear in a final report).
    HALLUCINATED- claimed with no backing tool execution, or the cited value is
                  absent from the captured output. Quarantined, never reported as fact.
    """

    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNVERIFIED = "UNVERIFIED"
    HALLUCINATED = "HALLUCINATED"


class EpistemicType(str, Enum):
    """NABAOS-style epistemic source classification (arXiv 2603.10060).

    Tags every finding claim by its evidentiary basis so consumers can act
    appropriately without having to re-read the verifier note.

    PRATYAKSA  - Direct observation: value found verbatim in captured tool output.
    ANUMANA    - Inference: derived from PRATYAKSA facts by deterministic logic.
    ABHAVA     - Absence: the tool ran and returned zero results; absence is itself evidence.
    SABDA      - External authority: from a lookup/threat-feed call at runtime.
    UNGROUNDED - No evidentiary basis or contradicted by tool output.
    """

    PRATYAKSA  = "PRATYAKSA"   # Sanskrit: direct perception
    ANUMANA    = "ANUMANA"     # Sanskrit: inference
    ABHAVA     = "ABHAVA"      # Sanskrit: absence
    SABDA      = "SABDA"       # Sanskrit: authoritative testimony
    UNGROUNDED = "UNGROUNDED"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceType(str, Enum):
    DISK = "disk"
    MEMORY = "memory"
    EVTX = "evtx"
    PCAP = "pcap"
    REGISTRY = "registry"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# Provenance & tool execution
# --------------------------------------------------------------------------- #
class Provenance(BaseModel):
    """The unforgeable link from a finding to the tool output that produced it.

    ``raw_locator`` is a substring (or stable token) that the verifier will
    re-find inside the captured raw output for ``tool_exec_id``. If it is not
    present there, the finding is marked HALLUCINATED.
    """

    tool_exec_id: str = Field(description="ID of the ToolExecution that produced this fact")
    tool: str = Field(description="Name of the read-only tool function invoked")
    evidence_sha256: Optional[str] = Field(
        default=None, description="SHA-256 of the evidence file the tool read"
    )
    raw_locator: str = Field(
        description="Exact substring/token expected to appear in the captured raw output"
    )
    note: str = Field(default="", description="Optional human-readable provenance note")


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
        )


class ToolExecution(BaseModel):
    """A single, fully-logged invocation of a read-only MCP tool.

    The raw output is content-addressed (``stdout_sha256``) and stored verbatim
    in the RawStore so the verifier can re-read it. The parsed, structured
    summary is what is handed to the LLM (preventing context-window overload)."""

    tool_exec_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    evidence_path: Optional[str] = None
    evidence_sha256: Optional[str] = None
    command: Optional[str] = Field(default=None, description="Underlying CLI, for the audit trail")
    started_at: str = Field(default_factory=utcnow_iso)
    ended_at: Optional[str] = None
    duration_ms: Optional[int] = None
    exit_code: Optional[int] = None
    status: ToolStatus = ToolStatus.OK
    stdout_sha256: Optional[str] = None
    raw_output_ref: Optional[str] = Field(
        default=None, description="RawStore key (== tool_exec_id) for the verbatim output"
    )
    parsed_summary: dict[str, Any] = Field(default_factory=dict)
    stderr_excerpt: str = ""
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    agent: str = Field(default="system", description="Which specialist agent invoked the tool")


# --------------------------------------------------------------------------- #
# ATT&CK / IOC / Findings
# --------------------------------------------------------------------------- #
class AttackMapping(BaseModel):
    technique_id: str = Field(description="e.g. T1543.003")
    technique_name: str
    tactic_ids: list[str] = Field(default_factory=list, description="e.g. ['TA0003','TA0004']")
    tactic_names: list[str] = Field(default_factory=list)
    source: str = Field(default="glassbox.attack", description="How the mapping was derived")
    confidence: Confidence = Confidence.INFERRED


class IOC(BaseModel):
    type: str = Field(description="ipv4 | ipv6 | domain | url | sha256 | md5 | email | regpath | filepath")
    value: str
    defanged: str = Field(default="", description="Safe-to-render form, e.g. 1.2.3.4 -> 1[.]2[.]3[.]4")
    context: str = ""
    provenance: list[Provenance] = Field(default_factory=list)


class Finding(BaseModel):
    """A single triage finding. Cannot be reported as fact without provenance
    that survives the hallucination gate."""

    finding_id: str
    title: str
    description: str = ""
    evidence_type: EvidenceType = EvidenceType.UNKNOWN
    host: Optional[str] = None
    observed_at: Optional[str] = Field(default=None, description="When the artifact occurred (not when we found it)")
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.UNVERIFIED
    attack: list[AttackMapping] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    # The raw values that justify the finding; each should appear verbatim in a
    # cited tool output (the verifier checks these against provenance).
    cited_values: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)
    source_agent: str = "unknown"
    verifier_note: str = ""
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0,
                                     description="Numeric confidence 0.0-1.0 (updated by verifier)")
    iteration_found: int = Field(default=1, description="Which triage iteration first found this")
    # NABAOS epistemic classification (arXiv 2603.10060) — auto-assigned by verifier
    epistemic_type: Optional[EpistemicType] = Field(
        default=None,
        description="NABAOS epistemic source: PRATYAKSA (direct) | ANUMANA (inferred) | "
                    "ABHAVA (absence) | SABDA (external authority) | UNGROUNDED"
    )
    # Valhuntir-grade finding approval workflow
    approval_status: str = Field(
        default="AUTO_APPROVED",
        description="AUTO_APPROVED | PENDING_REVIEW | APPROVED | REJECTED"
    )
    requires_human_review: bool = Field(
        default=False,
        description="CRITICAL findings above threshold require human review before actioning"
    )

    def is_reportable(self) -> bool:
        return self.confidence in (Confidence.CONFIRMED, Confidence.INFERRED)


class Discrepancy(BaseModel):
    """A cross-source inconsistency (e.g. disk timeline vs. memory)."""

    discrepancy_id: str
    kind: str = Field(description="e.g. hidden_process | hash_mismatch | orphan_connection")
    description: str
    sources: list[EvidenceType] = Field(default_factory=list)
    severity: Severity = Severity.HIGH
    related_finding_ids: list[str] = Field(default_factory=list)
    provenance: list[Provenance] = Field(default_factory=list)
    confidence: Confidence = Confidence.INFERRED


# --------------------------------------------------------------------------- #
# Inter-agent messaging (multi-agent audit trail, deliverable #8)
# --------------------------------------------------------------------------- #
class A2AMessage(BaseModel):
    """Agent-to-agent (or node-to-node) message, logged with timestamps and
    token usage. Satisfies the 'agent-to-agent message logs' requirement for
    multi-agent submissions and the 'token usage' requirement for single-agent."""

    ts: str = Field(default_factory=utcnow_iso)
    seq: int = 0
    from_agent: str
    to_agent: str
    role: str = Field(default="status", description="plan | request | result | status | critique")
    summary: str = Field(description="Structured summary; NEVER a raw multi-MB dump")
    refs: list[str] = Field(default_factory=list, description="tool_exec_ids / finding_ids referenced")
    token_usage: TokenUsage = Field(default_factory=TokenUsage)


# --------------------------------------------------------------------------- #
# Run-level results
# --------------------------------------------------------------------------- #
class IntegrityRecord(BaseModel):
    """Before/after hashes proving zero spoliation for one evidence file."""

    path: str
    sha256_before: str
    sha256_after: Optional[str] = None
    bytes: int = 0
    unchanged: Optional[bool] = None


class TriageReport(BaseModel):
    case_id: str
    generated_at: str = Field(default_factory=utcnow_iso)
    glassbox_version: str = "0.1.0"
    summary: str = ""
    evidence_types: list[EvidenceType] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    discrepancies: list[Discrepancy] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    attack_coverage: list[AttackMapping] = Field(default_factory=list)
    quarantined: list[Finding] = Field(default_factory=list, description="HALLUCINATED, kept for transparency")
    integrity: list[IntegrityRecord] = Field(default_factory=list)
    iterations_used: int = 0
    max_iterations: int = 0
    degraded_tools: list[str] = Field(default_factory=list)
    total_tokens: TokenUsage = Field(default_factory=TokenUsage)
    audit_log_ref: Optional[str] = None
    audit_chain_valid: Optional[bool] = None
    timeline: list[dict] = Field(default_factory=list, description="Sorted cross-source event timeline")
    narrative: str = Field(default="", description="Auto-generated incident narrative")
    lessons_summary: dict = Field(default_factory=dict,
                                   description="Persistent learning loop state")

    # --- convenience rollups for the accuracy report -------------------------
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence == Confidence.CONFIRMED]

    def inferred(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence == Confidence.INFERRED]
