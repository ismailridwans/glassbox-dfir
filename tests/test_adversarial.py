"""Adversarial Verification Panel tests — the flagship red-team USP."""

import pytest

from glassbox.adversarial import AdversarialPanel, Vote
from glassbox.adversarial.skeptic import (
    AdversarialContext,
    AttributionSkeptic,
    BenignExplanationSkeptic,
    CorroborationSkeptic,
    finding_entities,
)
from glassbox.attack.mapping import technique
from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
from glassbox.util import stable_id


def _f(title, *, severity=Severity.HIGH, attack_ids=None, cited=None, tool="mem_x",
       confidence=Confidence.CONFIRMED, desc=""):
    attack = [technique(t) for t in (attack_ids or []) if technique(t)]
    return Finding(
        finding_id=stable_id("F", title),
        title=title, description=desc,
        evidence_type=EvidenceType.MEMORY, severity=severity, confidence=confidence,
        attack=attack, cited_values=cited or [],
        provenance=[Provenance(tool_exec_id="TE1", tool=tool, raw_locator="x")],
        source_agent="test", confidence_score=0.8,
    )


class TestBenignSkeptic:
    def test_google_dns_vetoed(self):
        f = _f("External destination 8.8.8.8", severity=Severity.MEDIUM)
        ctx = AdversarialContext([f])
        vote = BenignExplanationSkeptic().challenge(f, ctx)
        assert vote.vote == Vote.REFUTE
        assert vote.veto is True

    def test_enumeration_refuted(self):
        f = _f("Process discovery: 9 processes enumerated", severity=Severity.INFO)
        ctx = AdversarialContext([f])
        vote = BenignExplanationSkeptic().challenge(f, ctx)
        assert vote.vote == Vote.REFUTE

    def test_real_c2_not_refuted(self):
        f = _f("External network connection to 41.168.5.140:8080")
        ctx = AdversarialContext([f])
        vote = BenignExplanationSkeptic().challenge(f, ctx)
        assert vote.vote != Vote.REFUTE


class TestCorroborationSkeptic:
    def test_multi_tool_corroboration_upholds(self):
        # Same PID 1640 referenced by 3 different tools
        f1 = _f("Injected code in PID 1640", tool="mem_malfind", cited=["1640"])
        f2 = _f("Suspicious cmdline PID 1640", tool="mem_cmdline", cited=["1640"])
        f3 = _f("Hidden process PID 1640", tool="mem_psscan", cited=["1640"])
        ctx = AdversarialContext([f1, f2, f3])
        vote = CorroborationSkeptic().challenge(f1, ctx)
        assert vote.vote == Vote.UPHOLD
        assert vote.weight >= 1.0

    def test_single_tool_high_severity_uncertain(self):
        f = _f("Lone critical finding", severity=Severity.CRITICAL, cited=["unique_xyz"])
        ctx = AdversarialContext([f])
        vote = CorroborationSkeptic().challenge(f, ctx)
        assert vote.vote == Vote.UNCERTAIN


class TestAttributionSkeptic:
    def test_discovery_at_high_severity_refuted(self):
        f = _f("Process discovery", severity=Severity.HIGH, attack_ids=["T1057"])
        ctx = AdversarialContext([f])
        vote = AttributionSkeptic().challenge(f, ctx)
        assert vote.vote == Vote.REFUTE


class TestPanelIntegration:
    def test_google_dns_refuted_by_panel(self):
        f = _f("External destination 8.8.8.8", severity=Severity.MEDIUM)
        result = AdversarialPanel().review([f])
        assert len(result.refuted) == 1
        assert f.adversarial_verdict == "REFUTED"

    def test_corroborated_finding_upheld(self):
        f1 = _f("Injected/RWX code in PID 1640", tool="mem_malfind", cited=["1640"],
                attack_ids=["T1055"])
        f2 = _f("C2 named pipe in PID 1640", tool="mem_handles", cited=["1640"],
                attack_ids=["T1071.001"], severity=Severity.CRITICAL)
        f3 = _f("Suspicious cmdline PID 1640", tool="mem_cmdline", cited=["1640"])
        result = AdversarialPanel().review([f1, f2, f3])
        assert f1.adversarial_verdict == "UPHELD"
        assert f1.confidence_score > 0.8  # boosted

    def test_idempotent_across_reviews(self):
        """Re-reviewing must not compound severity demotion."""
        f = _f("Process discovery", severity=Severity.MEDIUM, attack_ids=["T1057"], cited=["unique1"])
        panel = AdversarialPanel()
        panel.review([f])
        sev1 = f.severity
        panel.review([f])
        sev2 = f.severity
        assert sev1 == sev2  # idempotent

    def test_verdict_logged_to_audit(self, store_and_audit):
        store, audit = store_and_audit
        f = _f("External destination 8.8.8.8", severity=Severity.MEDIUM)
        AdversarialPanel().review([f], audit=audit)
        ok, errors = audit.verify_self()
        assert ok, errors
        # the adversarial_review event should be in the chain
        import json
        lines = [json.loads(x) for x in audit.path.read_text("utf-8").splitlines() if x.strip()]
        assert any(r["event"]["type"] == "adversarial_review" for r in lines)


class TestEntityExtraction:
    def test_extracts_ip_pid_filename(self):
        f = _f("Injected code in PID 1640 (reader_sl.exe) to 41.168.5.140",
               cited=["reader_sl.exe"])
        ents = finding_entities(f)
        assert "41.168.5.140" in ents
        assert "reader_sl.exe" in ents
        assert "pid:1640" in ents
