"""The Adversarial Verification Panel.

Runs every finding past the skeptic panel, aggregates the votes by weight, and
assigns an adversarial verdict:

* UPHELD   — survived the red-team (no net refutation); confidence boosted and
             tagged RED-TEAM VERIFIED. The highest-trust tier.
* DEMOTED  — mixed/uncertain or mildly refuted; kept but severity lowered to
             reflect reduced confidence. Still reported, in a separate tier.
* REFUTED  — net refuted by the panel; moved out of primary findings into a
             "context / refuted" bucket (kept for transparency, never reported
             as an active finding).

The verdict logic is deterministic, so an offline run is fully reproducible.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from glassbox.adversarial.skeptic import (
    DEFAULT_SKEPTICS,
    AdversarialContext,
    SkepticVote,
    Vote,
)
from glassbox.models import Confidence, Finding, Severity

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _demote_severity(sev: Severity, steps: int = 1) -> Severity:
    idx = _SEV_ORDER.index(sev)
    return _SEV_ORDER[max(0, idx - steps)]


class FindingVerdict(BaseModel):
    finding_id: str
    title: str
    verdict: str               # UPHELD | DEMOTED | REFUTED
    uphold_weight: float
    refute_weight: float
    votes: list[SkepticVote] = Field(default_factory=list)


class PanelResult(BaseModel):
    upheld: list[Finding] = Field(default_factory=list)
    demoted: list[Finding] = Field(default_factory=list)
    refuted: list[Finding] = Field(default_factory=list)
    verdicts: list[FindingVerdict] = Field(default_factory=list)

    def summary(self) -> dict:
        return {
            "total": len(self.upheld) + len(self.demoted) + len(self.refuted),
            "upheld": len(self.upheld),
            "demoted": len(self.demoted),
            "refuted": len(self.refuted),
        }


class AdversarialPanel:
    def __init__(self, skeptics=None):
        self.skeptics = skeptics or DEFAULT_SKEPTICS

    def review(
        self,
        findings: list[Finding],
        *,
        rawstore=None,
        known_exec_ids=None,
        audit=None,
    ) -> PanelResult:
        # Restore each finding to its ORIGINAL severity before challenging, so the
        # skeptics never see a severity already demoted by a prior iteration's
        # review (which would otherwise cause escalating, incorrect refutation).
        for f in findings:
            if f.base_severity is not None:
                f.severity = f.base_severity

        ctx = AdversarialContext(findings, rawstore=rawstore, known_exec_ids=known_exec_ids)
        result = PanelResult()

        for f in findings:
            votes = [sk.challenge(f, ctx) for sk in self.skeptics]
            uphold = sum(v.weight for v in votes if v.vote == Vote.UPHOLD)
            refute = sum(v.weight for v in votes if v.vote == Vote.REFUTE)
            vetoed = any(v.veto and v.vote == Vote.REFUTE for v in votes)

            if vetoed:
                # Authoritative refutation (e.g. known-benign infrastructure) — overrides tally.
                verdict = "REFUTED"
            elif refute > uphold:
                # net refuted
                hard = refute >= 2 * max(uphold, 0.5) or f.severity in (Severity.INFO, Severity.LOW)
                verdict = "REFUTED" if hard else "DEMOTED"
            elif uphold > 0 and refute == 0:
                verdict = "UPHELD"
            else:
                verdict = "DEMOTED"  # mixed / all-uncertain

            self._apply(f, verdict, votes)
            fv = FindingVerdict(
                finding_id=f.finding_id, title=f.title, verdict=verdict,
                uphold_weight=uphold, refute_weight=refute, votes=votes,
            )
            result.verdicts.append(fv)
            if verdict == "UPHELD":
                result.upheld.append(f)
            elif verdict == "DEMOTED":
                result.demoted.append(f)
            else:
                result.refuted.append(f)

            if audit is not None:
                audit.append(
                    "adversarial_review",
                    finding_id=f.finding_id,
                    verdict=verdict,
                    uphold_weight=round(uphold, 2),
                    refute_weight=round(refute, 2),
                    votes=[{"perspective": v.perspective, "vote": v.vote.value,
                            "reason": v.reason} for v in votes],
                )
        return result

    @staticmethod
    def _apply(f: Finding, verdict: str, votes: list[SkepticVote]) -> None:
        # Remember the original severity once, so re-review across self-correction
        # iterations is idempotent (demote from base, never compound).
        if f.base_severity is None:
            f.base_severity = f.severity
        base = f.base_severity
        note = " | ".join(f"{v.perspective}:{v.vote.value}" for v in votes)
        if verdict == "UPHELD":
            f.severity = base
            f.confidence_score = min(1.0, f.confidence_score + 0.10)
            f.adversarial_verdict = "UPHELD"
            f.verifier_note = (f.verifier_note + f" || RED-TEAM VERIFIED ({note})").strip(" |")
        elif verdict == "DEMOTED":
            f.severity = _demote_severity(base, 1)
            f.confidence_score = round(f.confidence_score * 0.7, 3)
            f.adversarial_verdict = "DEMOTED"
            f.verifier_note = (f.verifier_note + f" || adversarial: DEMOTED ({note})").strip(" |")
        else:  # REFUTED
            f.severity = Severity.INFO
            f.confidence_score = round(f.confidence_score * 0.4, 3)
            f.adversarial_verdict = "REFUTED"
            f.verifier_note = (f.verifier_note + f" || adversarial: REFUTED ({note})").strip(" |")
        f.skeptic_votes = [{"perspective": v.perspective, "vote": v.vote.value, "reason": v.reason}
                           for v in votes]
