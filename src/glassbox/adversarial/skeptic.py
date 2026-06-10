"""Skeptic perspectives for the Adversarial Verification Panel.

Each skeptic challenges a finding from a distinct angle and returns a vote
(UPHOLD / REFUTE / UNCERTAIN) with a reason. The rules below encode genuine
DFIR false-positive knowledge gathered from practitioner sources — they are not
toy heuristics. Diversity of perspective is the point: a finding that survives
*four independent challenges* is far more trustworthy than one that merely
passed a string-match gate.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel

from glassbox.models import Finding, Severity

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PID_RE = re.compile(r"\bPID\s+(\d+)\b|\b(\d{2,6})\b")
_FILE_RE = re.compile(r"\b[\w\-]+\.(?:exe|dll|sys|bat|ps1|vbs)\b", re.IGNORECASE)


class Vote(str, Enum):
    UPHOLD = "UPHOLD"
    REFUTE = "REFUTE"
    UNCERTAIN = "UNCERTAIN"


class SkepticVote(BaseModel):
    perspective: str
    vote: Vote
    reason: str
    weight: float = 1.0
    veto: bool = False  # authoritative REFUTE (e.g. known-benign infra) — overrides the tally


def finding_entities(f: Finding) -> set[str]:
    """Extract the key entities (IPs, PIDs, filenames) a finding references —
    used by the corroboration skeptic to detect cross-tool agreement."""
    blob = f"{f.title} {f.description} {' '.join(f.cited_values)}"
    ents: set[str] = set()
    ents.update(_IP_RE.findall(blob))
    for fn in _FILE_RE.findall(blob):
        ents.add(fn.lower())
    for m in _PID_RE.finditer(blob):
        pid = m.group(1) or m.group(2)
        if pid and 1 < len(pid) <= 6:
            ents.add(f"pid:{pid}")
    for v in f.cited_values:
        ents.add(str(v).lower())
    return {e for e in ents if e}


class AdversarialContext:
    """Cross-finding lookups shared by all skeptics in a panel run."""

    def __init__(self, findings: list[Finding], rawstore=None, known_exec_ids=None):
        self.findings = findings
        self.rawstore = rawstore
        self.known = set(known_exec_ids or [])
        # entity -> set of (finding_id, tool)
        self.entity_index: dict[str, set[tuple[str, str]]] = {}
        for f in findings:
            tool = f.provenance[0].tool if f.provenance else "?"
            for ent in finding_entities(f):
                self.entity_index.setdefault(ent, set()).add((f.finding_id, tool))

    def corroborating_tools(self, f: Finding) -> set[str]:
        """Distinct tools (other than this finding's own) that reference the same entities."""
        own = f.provenance[0].tool if f.provenance else "?"
        tools: set[str] = set()
        for ent in finding_entities(f):
            for fid, tool in self.entity_index.get(ent, set()):
                if fid != f.finding_id:
                    tools.add(tool)
        tools.discard(own)
        return tools

    def has_critical_referencing(self, f: Finding) -> bool:
        """Is any CRITICAL finding referencing the same entity?"""
        for ent in finding_entities(f):
            for fid, _ in self.entity_index.get(ent, set()):
                if fid == f.finding_id:
                    continue
                other = next((x for x in self.findings if x.finding_id == fid), None)
                if other and other.severity == Severity.CRITICAL:
                    return True
        return False


# --------------------------------------------------------------------------- #
# Skeptic perspectives
# --------------------------------------------------------------------------- #
class Skeptic:
    name = "skeptic"

    def challenge(self, f: Finding, ctx: AdversarialContext) -> SkepticVote:
        raise NotImplementedError


class BenignExplanationSkeptic(Skeptic):
    """Knows what normal system activity looks like. Refutes low-signal findings
    that have an obvious benign explanation and no malicious corroboration."""

    name = "benign_explanation"

    # phrases that, on their own, describe baseline / informational activity
    _BASELINE = (
        "discovery:", "processes enumerated", "connections in memory",
        "timeline:", "partition table:", "entries analysed", "events analysed",
        "no suspicious",
    )
    _LEGIT = (
        ("svchost.exe", "netsvcs"),         # svchost -k netsvcs is legitimate
        ("svchost.exe", "system32"),
    )
    # Well-known benign public infrastructure (DNS resolvers, NTP) — not C2.
    _BENIGN_INFRA = {
        "8.8.8.8", "8.8.4.4",                 # Google DNS
        "1.1.1.1", "1.0.0.1",                 # Cloudflare DNS
        "9.9.9.9", "149.112.112.112",         # Quad9
        "208.67.222.222", "208.67.220.220",   # OpenDNS
        "time.windows.com", "time.nist.gov",  # NTP
    }

    def challenge(self, f: Finding, ctx: AdversarialContext) -> SkepticVote:
        t = f.title.lower()
        d = f.description.lower()
        blob = t + " " + d
        # Known-benign public infrastructure — refute with strong weight so it
        # overrides naive cross-tool "corroboration" (same benign IP seen twice).
        for infra in self._BENIGN_INFRA:
            if infra in blob:
                return SkepticVote(perspective=self.name, vote=Vote.REFUTE, weight=2.5, veto=True,
                                   reason=f"'{infra}' is well-known benign public infrastructure "
                                          "(public DNS/NTP resolver), not attacker C2. A senior analyst dismisses it.")
        # Pure enumeration/context findings → refute (demote to context)
        if any(b in t for b in self._BASELINE):
            return SkepticVote(perspective=self.name, vote=Vote.REFUTE,
                               reason="Enumeration/coverage artifact is baseline system activity, "
                                      "not evidence of compromise on its own.")
        # Legitimate svchost pattern
        for a, b in self._LEGIT:
            if a in t + d and b in (t + d):
                if not ctx.has_critical_referencing(f):
                    return SkepticVote(perspective=self.name, vote=Vote.REFUTE,
                                       reason=f"'{a}' with '{b}' matches the standard legitimate "
                                              "Windows service host pattern.")
        # Lone DNS query with no C2 correlation
        if t.startswith("dns query:") and not ctx.has_critical_referencing(f):
            return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                               reason="A single DNS query may be legitimate unless it correlates "
                                      "with a known-bad domain or C2 IP.")
        # Low/INFO severity findings rarely indicate evil alone
        if f.severity in (Severity.INFO, Severity.LOW) and not ctx.has_critical_referencing(f):
            return SkepticVote(perspective=self.name, vote=Vote.REFUTE,
                               reason="Low-severity observation with no corroborating high-severity "
                                      "finding — treat as context, not a finding.")
        # No benign explanation found — abstain (let corroboration decide).
        return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                           reason="No benign explanation matched; no objection from this perspective.")


class FalsePositiveSkeptic(Skeptic):
    """Knows tool-specific quirks that masquerade as malice."""

    name = "false_positive_pattern"

    def challenge(self, f: Finding, ctx: AdversarialContext) -> SkepticVote:
        t = f.title.lower()
        d = f.description.lower()
        blob = t + " " + d
        # SSDT UNKNOWN is frequently AV/EDR (CrowdStrike, Carbon Black, Cylance)
        if "ssdt" in blob and "unknown" in blob:
            return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                               reason="SSDT entries resolving to UNKNOWN are commonly EDR/AV hooks "
                                      "(CrowdStrike, Carbon Black). Corroborate with driverscan before asserting rootkit.")
        # malfind RWX inside a .NET/CLR process is often JIT, not injection
        if ("inject" in blob or "rwx" in blob or "malfind" in blob) and \
           any(clr in blob for clr in ("clr.dll", "mscorwks", "dotnet", ".net", "w3wp")):
            return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                               reason="RWX private memory in a .NET/CLR process is frequently JIT "
                                      "compilation, not injection. Verify the page contents.")
        # generic YARA match alone is weak
        if t.startswith("yara match: generic") and not ctx.has_critical_referencing(f):
            return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                               reason="A generic YARA rule match is weak without a specific-rule or "
                                      "cross-source corroboration.")
        # No FP pattern matched — abstain.
        return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                           reason="Does not match a known tool false-positive pattern; no objection.")


class CorroborationSkeptic(Skeptic):
    """Demands cross-source / cross-tool support for serious claims."""

    name = "corroboration"

    def challenge(self, f: Finding, ctx: AdversarialContext) -> SkepticVote:
        corro = ctx.corroborating_tools(f)
        if len(corro) >= 2:
            return SkepticVote(perspective=self.name, vote=Vote.UPHOLD, weight=2.0,
                               reason=f"Corroborated across {len(corro)} independent tools "
                                      f"({', '.join(sorted(corro)[:4])}) — strong multi-source support.")
        if len(corro) == 1:
            return SkepticVote(perspective=self.name, vote=Vote.UPHOLD,
                               reason=f"Corroborated by a second tool ({next(iter(corro))}).")
        # No corroboration: serious claims become uncertain
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                               reason="High-severity claim rests on a single tool with no "
                                      "cross-source corroboration — seek a second source.")
        return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                           reason="No cross-tool corroboration found.")


class AttributionSkeptic(Skeptic):
    """Checks ATT&CK mapping correctness and severity proportionality."""

    name = "attribution"

    # discovery techniques should not carry HIGH/CRITICAL severity on their own
    _LOW_SIGNAL_TECHS = {"T1057", "T1082", "T1083", "T1049", "T1012", "T1518"}

    def challenge(self, f: Finding, ctx: AdversarialContext) -> SkepticVote:
        tech_ids = {m.technique_id for m in f.attack}
        # Severity disproportionate to a pure discovery technique
        if tech_ids and tech_ids.issubset(self._LOW_SIGNAL_TECHS) \
                and f.severity in (Severity.HIGH, Severity.CRITICAL):
            return SkepticVote(perspective=self.name, vote=Vote.REFUTE,
                               reason=f"Severity {f.severity.value} is disproportionate for "
                                      f"discovery technique(s) {sorted(tech_ids)} — discovery is low-signal.")
        # High/critical finding with no ATT&CK mapping is suspicious of over-claiming
        if f.severity in (Severity.HIGH, Severity.CRITICAL) and not tech_ids:
            return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                               reason="High-severity finding with no ATT&CK technique mapped — "
                                      "verify the attribution before reporting.")
        # Mapping present and proportionate — no objection (abstain; corroboration drives uphold).
        return SkepticVote(perspective=self.name, vote=Vote.UNCERTAIN,
                           reason="ATT&CK attribution and severity are proportionate; no objection.")


DEFAULT_SKEPTICS: list[Skeptic] = [
    BenignExplanationSkeptic(),
    FalsePositiveSkeptic(),
    CorroborationSkeptic(),
    AttributionSkeptic(),
]
