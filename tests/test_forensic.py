"""Sprint 6 USP tests: deterministic replay, court-admissible bundle,
ATT&CK Navigator export, speed report, guardrail self-test."""

import json
import shutil
from pathlib import Path

import pytest

DEMO_CASE = Path(__file__).parent.parent / "demo_case"


@pytest.fixture
def live_case(tmp_path):
    """Run a real triage so we have audit.jsonl + raw/ + report to operate on."""
    from glassbox.config import GlassboxConfig
    from glassbox.context import CaseContext
    from glassbox.orchestrator import run_triage
    dst = tmp_path / "demo-cridex-evtx"
    shutil.copytree(DEMO_CASE, dst)
    cfg = GlassboxConfig.for_case(dst, evidence_dir=dst / "evidence",
                                  replay_dir=dst / "fixtures", max_iterations=3)
    ctx = CaseContext(cfg, replay=True)
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    return dst, rep


# ---------------------------------------------------------------- replay --
class TestReplay:
    def test_findings_reproduce_from_audit(self, live_case):
        from glassbox.forensic import replay_verify
        case_dir, rep = live_case
        report_json = next((case_dir / "reports").glob("*.report.json"))
        result = replay_verify(case_dir / "case.audit.jsonl", case_dir / "raw", report_json)
        assert result.audit_chain_valid
        assert result.reproducible
        assert result.findings_reproduced == result.findings_checked
        assert result.findings_reproduced > 0

    def test_replay_detects_tampered_audit(self, live_case):
        from glassbox.forensic import replay_verify
        case_dir, rep = live_case
        # tamper with the audit log
        audit = case_dir / "case.audit.jsonl"
        lines = audit.read_text("utf-8").splitlines()
        rec = json.loads(lines[2]); rec["event"]["tool"] = "TAMPERED"
        lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report_json = next((case_dir / "reports").glob("*.report.json"))
        result = replay_verify(audit, case_dir / "raw", report_json)
        assert not result.audit_chain_valid
        assert not result.reproducible


# ---------------------------------------------------------------- bundle --
class TestBundle:
    def test_build_and_verify_bundle(self, live_case, tmp_path):
        from glassbox.forensic.bundle import build_bundle, verify_bundle
        case_dir, rep = live_case
        reports = case_dir / "reports"
        cid = rep.case_id
        bundle = build_bundle(
            cid,
            report_md=reports / f"{cid}.report.md",
            report_json=reports / f"{cid}.report.json",
            audit_log=case_dir / "case.audit.jsonl",
            out_dir=tmp_path / "bundle",
        )
        assert bundle.bundle_hash
        assert "report.json" in bundle.components
        ok, errors = verify_bundle(tmp_path / "bundle")
        assert ok, errors

    def test_bundle_detects_tampering(self, live_case, tmp_path):
        from glassbox.forensic.bundle import build_bundle, verify_bundle
        case_dir, rep = live_case
        reports = case_dir / "reports"
        cid = rep.case_id
        build_bundle(cid, report_md=reports / f"{cid}.report.md",
                     report_json=reports / f"{cid}.report.json",
                     audit_log=case_dir / "case.audit.jsonl",
                     out_dir=tmp_path / "bundle")
        # tamper with a component
        (tmp_path / "bundle" / "report.md").write_text("ALTERED", encoding="utf-8")
        ok, errors = verify_bundle(tmp_path / "bundle")
        assert not ok
        assert any("altered" in e.lower() for e in errors)


# ------------------------------------------------------------- navigator --
class TestNavigator:
    def test_layer_has_techniques(self, live_case):
        from glassbox.attack.navigator import to_navigator_layer
        case_dir, rep = live_case
        report = json.loads(next((case_dir / "reports").glob("*.report.json")).read_text("utf-8"))
        layer = to_navigator_layer(report)
        assert layer["domain"] == "enterprise-attack"
        assert len(layer["techniques"]) > 5
        # every technique entry has the required Navigator fields
        for t in layer["techniques"]:
            assert "techniqueID" in t and "score" in t and "color" in t

    def test_diamond_model(self, live_case):
        from glassbox.attack.navigator import to_diamond_model
        case_dir, rep = live_case
        report = json.loads(next((case_dir / "reports").glob("*.report.json")).read_text("utf-8"))
        diamond = to_diamond_model(report)
        assert "adversary" in diamond and "capability" in diamond
        assert "infrastructure" in diamond and "victim" in diamond


# ----------------------------------------------------------------- speed --
class TestSpeed:
    def test_speed_report(self):
        from glassbox.perf import speed_report
        class FakeTE:
            def __init__(self, tool, ms): self.tool = tool; self.duration_ms = ms
        execs = [FakeTE("mem_pslist", 50), FakeTE("mem_psscan", 80), FakeTE("evtx_hunt", 120)]
        rep = speed_report(execs, total_duration_ms=500, iterations=2)
        assert rep["tool_executions"] == 3
        assert rep["self_correction_iterations"] == 2
        assert "vs_adversary_breakout" in rep
        assert rep["vs_adversary_breakout"]["CrowdStrike fastest observed breakout"]["glassbox_faster_x"] > 1


# ------------------------------------------------------------- guardrail --
class TestGuardrailSelftest:
    def test_all_guardrails_pass(self):
        from glassbox.guardrail import run_guardrail_selftest
        rep = run_guardrail_selftest()
        assert rep.all_passed, [c.model_dump() for c in rep.checks if not c.passed]
        names = {c.name for c in rep.checks}
        assert {"NO_WRITE_TOOL", "PATH_TRAVERSAL", "AUDIT_TAMPER",
                "HALLUCINATION", "HMAC_APPROVAL"}.issubset(names)
