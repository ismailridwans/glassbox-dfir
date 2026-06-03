"""End-to-end demo run: full pipeline with replay fixtures.

This test exercises the complete path:
  CaseContext → orchestrator → specialist analysts → correlator →
  hallucination gate → report renderer → audit chain verification.

No SIFT binaries required (replay=True).
"""

import json
import tempfile
import shutil
from pathlib import Path

import pytest

from glassbox.config import GlassboxConfig
from glassbox.context import CaseContext
from glassbox.orchestrator import run_triage
from glassbox.audit.chain import AuditChain


DEMO_CASE = Path(__file__).parent.parent / "demo_case"


@pytest.fixture
def case_copy(tmp_path):
    """A fresh copy of demo_case for each test run."""
    dst = tmp_path / "case"
    shutil.copytree(DEMO_CASE, dst)
    return dst


@pytest.fixture
def ctx(case_copy):
    cfg = GlassboxConfig.for_case(
        case_copy,
        evidence_dir=case_copy / "evidence",
        replay_dir=case_copy / "fixtures",
        max_iterations=3,
    )
    return CaseContext(cfg, replay=True)


def test_triage_completes(ctx):
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    assert rep is not None
    assert rep.iterations_used >= 1


def test_confirmed_findings_present(ctx):
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    # With cridex fixtures: connections to 41.168.5.140 + EVTX detections expected
    confirmed = rep.confirmed()
    assert len(confirmed) >= 1, "expected at least one CONFIRMED finding"


def test_hallucination_gate_quarantines_overclaim(ctx):
    """The '2.3 GB exfil' claim must be quarantined — it's not in any tool output."""
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    quarantined_titles = [f.title.lower() for f in rep.quarantined]
    assert any("2.3 gb" in t or "exfiltration" in t or "assessment" in t
               for t in quarantined_titles), (
        f"Expected the overclaim to be quarantined; quarantined: {quarantined_titles}"
    )


def test_audit_chain_valid_after_run(ctx):
    run_triage(ctx, demo_overclaim=True, write=True)
    ok, errors = AuditChain.verify(ctx.config.audit_path)
    assert ok, f"Audit chain invalid after run: {errors}"


def test_report_files_written(ctx):
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    reports = list(ctx.config.reports_dir.glob("*.report.md"))
    assert len(reports) >= 1, "Markdown report not written"
    logs = list(ctx.config.reports_dir.glob("*.execution_log.jsonl"))
    assert len(logs) >= 1, "Execution log not written"


def test_integrity_not_spoilated(ctx):
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    assert not any(r.unchanged is False for r in rep.integrity), \
        "Spoliation detected — evidence was modified during triage!"


def test_attack_coverage_populated(ctx):
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    assert len(rep.attack_coverage) >= 1, "No ATT&CK techniques mapped"


def test_self_correction_loop_bounded(ctx):
    """Iterations must never exceed max_iterations."""
    rep = run_triage(ctx, demo_overclaim=True, write=True)
    assert rep.iterations_used <= ctx.config.max_iterations
