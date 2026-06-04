"""The hallucination gate.

This module is GLASSBOX's answer to the hackathon's stated core problem
("Protocol SIFT works. It also hallucinates more than we'd like.") and to
Anthropic's GTG-1002 finding that an autonomous agent "frequently overstated
findings and occasionally fabricated data."

The gate is **not** a prompt ("are you sure?"). It is deterministic code that,
for every finding the model proposes, re-opens the *captured raw output* of the
tool execution the finding cites and checks that the cited value is physically
present there. A finding gets one of:

* CONFIRMED   — every cited value is present in its cited tool output, and the
                producer claimed direct observation.
* INFERRED    — backing facts are present, but the finding is a derivation
                (e.g. a cross-source correlation / discrepancy).
* HALLUCINATED— no provenance, an unknown tool_exec_id, or a cited value that
                does not appear in the captured output. Quarantined; never
                reported as fact (kept for transparency in the accuracy report).

The verifier can only ever *downgrade* confidence. The model cannot talk its
way to CONFIRMED.
"""

from __future__ import annotations

from typing import Iterable, Optional

from pydantic import BaseModel

from glassbox.audit.rawstore import RawStore
from glassbox.models import Confidence, Discrepancy, EpistemicType, Finding


class VerificationOutcome(BaseModel):
    finding_id: str
    title: str
    declared: Confidence
    verdict: Confidence
    reasons: list[str] = []
    checked_locators: int = 0
    missing_locators: list[str] = []


class VerificationResult(BaseModel):
    verified: list[Finding] = []        # CONFIRMED or INFERRED — reportable
    quarantined: list[Finding] = []     # HALLUCINATED — not reportable
    outcomes: list[VerificationOutcome] = []

    @property
    def hallucination_count(self) -> int:
        return len(self.quarantined)

    def summary(self) -> dict[str, int]:
        c = sum(1 for f in self.verified if f.confidence == Confidence.CONFIRMED)
        i = sum(1 for f in self.verified if f.confidence == Confidence.INFERRED)
        return {
            "confirmed": c,
            "inferred": i,
            "hallucinated": len(self.quarantined),
            "total_proposed": len(self.verified) + len(self.quarantined),
        }


def _check_finding(
    finding: Finding,
    rawstore: RawStore,
    known_exec_ids: set[str],
) -> VerificationOutcome:
    reasons: list[str] = []
    missing: list[str] = []

    # 1) A finding with no provenance is an unsupported claim.
    if not finding.provenance:
        return VerificationOutcome(
            finding_id=finding.finding_id,
            title=finding.title,
            declared=finding.confidence,
            verdict=Confidence.HALLUCINATED,
            reasons=["no provenance: finding cites no tool execution"],
        )

    checked = 0
    for prov in finding.provenance:
        # 2) Provenance must reference a tool execution we actually performed.
        if prov.tool_exec_id not in known_exec_ids:
            reasons.append(f"unknown tool_exec_id '{prov.tool_exec_id}' (no such execution)")
            missing.append(prov.raw_locator)
            continue
        # 3) The cited locator must physically appear in that tool's raw output.
        checked += 1
        if not rawstore.contains(prov.tool_exec_id, prov.raw_locator):
            reasons.append(
                f"locator '{prov.raw_locator}' absent from output of {prov.tool_exec_id}"
            )
            missing.append(prov.raw_locator)

    # 4) Any extra human-facing cited_values must also be grounded somewhere
    #    among this finding's cited outputs.
    cited_exec_ids = [p.tool_exec_id for p in finding.provenance if p.tool_exec_id in known_exec_ids]
    for value in finding.cited_values:
        if not any(rawstore.contains(eid, value) for eid in cited_exec_ids):
            reasons.append(f"cited value '{value}' not found in any cited tool output")
            missing.append(value)

    if missing:
        return VerificationOutcome(
            finding_id=finding.finding_id,
            title=finding.title,
            declared=finding.confidence,
            verdict=Confidence.HALLUCINATED,
            reasons=reasons,
            checked_locators=checked,
            missing_locators=missing,
        )

    # Grounded. Honor the producer's declared class but never above CONFIRMED.
    verdict = (
        Confidence.INFERRED
        if finding.confidence == Confidence.INFERRED
        else Confidence.CONFIRMED
    )
    reasons.append(f"all {checked} cited locator(s) present in captured output")
    return VerificationOutcome(
        finding_id=finding.finding_id,
        title=finding.title,
        declared=finding.confidence,
        verdict=verdict,
        reasons=reasons,
        checked_locators=checked,
    )


def verify_findings(
    findings: Iterable[Finding],
    rawstore: RawStore,
    known_exec_ids: Iterable[str],
    audit=None,  # optional AuditChain
) -> VerificationResult:
    """Verify a batch of findings against captured tool output.

    Mutates each finding's ``confidence`` and ``verifier_note`` in place, then
    partitions into reportable vs quarantined. Every verdict is logged to the
    audit chain when one is supplied.
    """
    known = set(known_exec_ids)
    result = VerificationResult()
    for finding in findings:
        outcome = _check_finding(finding, rawstore, known)
        finding.confidence = outcome.verdict
        finding.verifier_note = "; ".join(outcome.reasons)

        # ---- NABAOS epistemic typing (arXiv 2603.10060) ----
        # Assign the epistemic source classification based on verification result.
        if outcome.verdict == Confidence.HALLUCINATED:
            finding.epistemic_type = EpistemicType.UNGROUNDED
            finding.confidence_score = 0.0
        elif finding.confidence == Confidence.CONFIRMED:
            # Direct observation in tool output — Pratyaksa
            finding.epistemic_type = EpistemicType.PRATYAKSA
            finding.confidence_score = min(1.0, 0.75 + 0.083 * min(outcome.checked_locators, 3))
        elif finding.confidence == Confidence.INFERRED:
            # Derived from confirmed facts — Anumana
            finding.epistemic_type = EpistemicType.ANUMANA
            finding.confidence_score = 0.65
        else:
            finding.epistemic_type = EpistemicType.UNGROUNDED
            finding.confidence_score = 0.0

        # ---- Approval workflow ----
        # CRITICAL findings with unverified epistemic type require human review.
        from glassbox.models import Severity
        if (finding.severity == Severity.CRITICAL and
                finding.epistemic_type == EpistemicType.ANUMANA):
            finding.requires_human_review = True
            finding.approval_status = "PENDING_REVIEW"
        else:
            finding.requires_human_review = False
            finding.approval_status = "AUTO_APPROVED"

        result.outcomes.append(outcome)
        if outcome.verdict == Confidence.HALLUCINATED:
            result.quarantined.append(finding)
        else:
            result.verified.append(finding)
        if audit is not None:
            audit.append(
                "verification",
                finding_id=finding.finding_id,
                declared=outcome.declared.value,
                verdict=outcome.verdict.value,
                epistemic_type=finding.epistemic_type.value if finding.epistemic_type else None,
                confidence_score=round(finding.confidence_score, 3),
                requires_human_review=finding.requires_human_review,
                checked_locators=outcome.checked_locators,
                missing=outcome.missing_locators,
                reasons=outcome.reasons,
            )
    return result


def verify_discrepancies(
    discrepancies: Iterable[Discrepancy],
    reportable_finding_ids: Iterable[str],
    rawstore: RawStore,
    known_exec_ids: Iterable[str],
    audit=None,
) -> tuple[list[Discrepancy], list[Discrepancy]]:
    """A discrepancy is INFERRED and survives only if (a) its positive locators
    are present in captured output and (b) every related finding it points at
    is itself reportable. Returns ``(kept, dropped)``."""
    known = set(known_exec_ids)
    reportable = set(reportable_finding_ids)
    kept: list[Discrepancy] = []
    dropped: list[Discrepancy] = []
    for d in discrepancies:
        ok = True
        reasons: list[str] = []
        for prov in d.provenance:
            if prov.tool_exec_id not in known or not rawstore.contains(
                prov.tool_exec_id, prov.raw_locator
            ):
                ok = False
                reasons.append(f"locator '{prov.raw_locator}' not grounded in {prov.tool_exec_id}")
        for fid in d.related_finding_ids:
            if fid not in reportable:
                ok = False
                reasons.append(f"related finding {fid} is not reportable")
        if ok:
            d.confidence = Confidence.INFERRED
            kept.append(d)
        else:
            d.confidence = Confidence.HALLUCINATED
            dropped.append(d)
        if audit is not None:
            audit.append(
                "discrepancy_verification",
                discrepancy_id=d.discrepancy_id,
                verdict=d.confidence.value,
                reasons=reasons or ["grounded"],
            )
    return kept, dropped
