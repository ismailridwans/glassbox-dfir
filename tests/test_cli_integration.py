"""CLI integration tests: benchmark, verify-audit, check-spoliation, demo.

These tests exercise the actual CLI commands end-to-end (no mocks).
They run in the same offline replay mode as the demo and are fast (<5s).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
DEMO_CASE = REPO / "demo_case"


@pytest.fixture
def tmp_demo(tmp_path):
    dst = tmp_path / "demo-cridex-evtx"
    shutil.copytree(DEMO_CASE, dst)
    return dst


def _run(*args, check: bool = True, **kwargs):
    """Run a glassbox CLI command via python -m glassbox.cli."""
    result = subprocess.run(
        [sys.executable, "-m", "glassbox.cli"] + list(args),
        capture_output=True, text=True, cwd=str(REPO), **kwargs
    )
    if check and result.returncode != 0:
        pytest.fail(f"Command failed: {' '.join(args)}\n{result.stdout}\n{result.stderr}")
    return result


# ─── demo ────────────────────────────────────────────────────────────────────

def test_demo_runs(tmp_path):
    """Full offline demo completes and writes reports."""
    result = _run("demo", "--output", str(tmp_path / "out"))
    assert "Complete" in result.stdout
    reports = list((tmp_path / "out").glob("*.report.json"))
    assert len(reports) >= 1, "Expected at least one JSON report"


def test_demo_quarantines_overclaim(tmp_path):
    result = _run("demo", "--output", str(tmp_path / "out"))
    assert "QUARANTINED" in result.stdout
    assert "2.3 GB" in result.stdout


def test_demo_shows_audit_chain_valid(tmp_path):
    result = _run("demo", "--output", str(tmp_path / "out"))
    # robust to spacing/label changes — just confirm the chain is reported valid
    assert "Audit chain valid" in result.stdout
    assert "YES" in result.stdout
    assert "RED-TEAM VERIFIED" in result.stdout


# ─── verify-audit ────────────────────────────────────────────────────────────

def test_verify_audit_valid_chain(tmp_path):
    """verify-audit on a chain produced by a real demo run should report VALID."""
    out_dir = tmp_path / "out"
    _run("demo", "--output", str(out_dir))
    # Find the audit log in the temp case dirs
    audit_files = list(tmp_path.rglob("*.audit.jsonl"))
    if not audit_files:
        pytest.skip("No audit log found (demo ran in temp dir outside tmp_path)")
    result = _run("verify-audit", str(audit_files[0]))
    assert "[OK]" in result.stdout or "VALID" in result.stdout


def test_verify_audit_from_audit_module(tmp_path):
    """verify-audit works directly on an AuditChain-generated file."""
    from glassbox.audit.chain import AuditChain
    chain = AuditChain(tmp_path / "test.audit.jsonl")
    chain.append("event_a", x=1)
    chain.append("event_b", x=2)
    chain.append("event_c", x=3)
    result = _run("verify-audit", str(tmp_path / "test.audit.jsonl"))
    assert "[OK]" in result.stdout


def test_verify_audit_detects_tamper(tmp_path):
    """verify-audit returns exit code 1 on a tampered chain."""
    import json as _json
    from glassbox.audit.chain import AuditChain
    chain = AuditChain(tmp_path / "tampered.audit.jsonl")
    chain.append("event_a"); chain.append("event_b")
    path = tmp_path / "tampered.audit.jsonl"
    lines = path.read_text("utf-8").splitlines()
    rec = _json.loads(lines[0])
    rec["event"]["x"] = "TAMPERED"
    lines[0] = _json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = _run("verify-audit", str(path), check=False)
    assert result.returncode != 0
    assert "INVALID" in result.stdout or "INVALID" in result.stderr


# ─── check-spoliation ────────────────────────────────────────────────────────

def test_check_spoliation_clean(tmp_path):
    """check-spoliation passes on a vault with read-only files."""
    ev = tmp_path / "evidence"
    ev.mkdir()
    f = ev / "test.vmem"
    f.write_bytes(b"FAKE_MEMORY" * 1000)
    import os, stat
    os.chmod(f, stat.S_IREAD)  # make read-only
    result = _run("check-spoliation", str(ev))
    assert "all_writes_blocked" in result.stdout


# ─── benchmark ───────────────────────────────────────────────────────────────

def test_benchmark_scores_demo_output(tmp_path):
    """Run benchmark against demo output and assert reasonable scores."""
    out_dir = tmp_path / "out"
    _run("demo", "--output", str(out_dir))
    # Verify we have a report to benchmark
    reports = list(out_dir.glob("*.report.json"))
    assert reports, "Demo must produce a report.json"

    bench_report = tmp_path / "bench.json"
    result = _run("benchmark",
                  str(DEMO_CASE / "ground_truth"),
                  str(out_dir),
                  "--report", str(bench_report))
    assert bench_report.exists(), "Benchmark report not written"
    data = json.loads(bench_report.read_text("utf-8"))
    assert data["cases_scored"] >= 1
    # Technique recall should be >= 0.5 with ground truth
    assert data["avg_technique_recall"] >= 0.5, (
        f"Technique recall too low: {data['avg_technique_recall']}"
    )
    # Hallucination rate should be < 0.2
    assert data["avg_hallucination_rate"] < 0.2, (
        f"Hallucination rate too high: {data['avg_hallucination_rate']}"
    )
    print(f"Benchmark: precision={data['avg_technique_precision']:.2f} "
          f"recall={data['avg_technique_recall']:.2f} "
          f"hallucination={data['avg_hallucination_rate']:.2f}")
