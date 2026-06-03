"""GLASSBOX command-line interface.

Commands:
  triage            Run full autonomous triage on a case directory.
  verify-audit      Verify a case's hash-chained audit log for integrity.
  check-spoliation  Run the write-probe against evidence to confirm no modification is possible.
  benchmark         Score the agent against ground-truth (EVTX-ATTACK-SAMPLES / cridex / etc.).
  mcp-serve         Launch the read-only MCP server over stdio (for Claude Code / Claude Desktop).
  demo              Run the offline demo case (no SIFT required — uses replay fixtures).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ------------------------------------------------------------------ helpers --
def _print_json(obj):
    print(json.dumps(obj, indent=2, default=str))


def _build_ctx(case_dir: str, evidence_dir: str | None = None,
               replay: bool = False, max_iter: int | None = None,
               replay_dir: str | None = None):
    from glassbox.config import GlassboxConfig
    from glassbox.context import CaseContext
    cfg = GlassboxConfig.for_case(
        case_dir,
        evidence_dir=evidence_dir,
        replay_dir=replay_dir,
        max_iterations=max_iter,
    )
    return CaseContext(cfg, replay=replay)


# ------------------------------------------------------------------ commands --
def cmd_triage(args):
    print(f"[GLASSBOX] Starting triage: case={args.case}, evidence={args.evidence}")
    ctx = _build_ctx(args.case, args.evidence, max_iter=args.max_iter)
    ctx.integrity.snapshot()

    from glassbox.orchestrator import run_triage
    rep = run_triage(ctx, demo_overclaim=args.demo_overclaim, write=True)
    paths_msg = f"  Reports in: {ctx.config.reports_dir}"
    print(f"\n[GLASSBOX] Triage complete — {rep.iterations_used} iteration(s)")
    print(f"  Reportable findings : {len(rep.findings)}")
    print(f"  Confirmed           : {len(rep.confirmed())}")
    print(f"  Inferred            : {len(rep.inferred())}")
    print(f"  Quarantined (hallu) : {len(rep.quarantined)}")
    print(f"  Discrepancies       : {len(rep.discrepancies)}")
    print(f"  IOCs                : {len(rep.iocs)}")
    print(f"  Audit chain valid   : {'YES' if rep.audit_chain_valid else 'NO ⚠'}")
    print(f"  Spoliation detected : {'YES ⚠' if any(not r.unchanged for r in rep.integrity) else 'NO'}")
    print(paths_msg)


def cmd_verify_audit(args):
    from glassbox.audit.chain import AuditChain
    path = Path(args.audit_log)
    ok, errors = AuditChain.verify(path)
    if ok:
        print(f"✅ Audit chain VALID: {path}")
    else:
        print(f"❌ Audit chain INVALID: {path}")
        for e in errors:
            print(f"   {e}")
    sys.exit(0 if ok else 1)


def cmd_check_spoliation(args):
    from glassbox.evidence.integrity import write_probe
    from glassbox.evidence.vault import EvidenceVault
    vault = EvidenceVault(args.evidence)
    result = write_probe(vault)
    _print_json(result)
    if result["spoliation_possible"]:
        print("\n⚠  SPOLIATION POSSIBLE — some evidence files could be opened for write.")
        sys.exit(1)
    else:
        print(f"\n✅  All {result['files_tested']} write attempts blocked — evidence integrity holds.")


def cmd_benchmark(args):
    from glassbox.benchmark import run_benchmark
    result = run_benchmark(
        ground_truth_dir=args.gt_dir,
        predictions_dir=args.pred_dir,
        report_path=args.report,
    )
    _print_json(result)


def cmd_mcp_serve(args):
    import os
    if args.case:
        os.environ["GLASSBOX_CASE"] = args.case
    if args.evidence:
        os.environ["GLASSBOX_EVIDENCE"] = args.evidence
    from glassbox.mcp_server.server import main as mcp_main
    mcp_main()


def cmd_demo(args):
    """Fully offline demo — uses replay fixtures, no SIFT required."""
    from pathlib import Path
    demo_root = Path(__file__).parent.parent.parent / "demo_case"
    if not demo_root.exists():
        # Try relative to cwd
        demo_root = Path("demo_case")
    if not demo_root.exists():
        print("ERROR: demo_case/ directory not found. Run from the repo root.")
        sys.exit(1)

    print("[GLASSBOX DEMO] Running offline demo case (replay fixtures) ...")
    print(f"  Case dir : {demo_root}")
    import tempfile, shutil
    with tempfile.TemporaryDirectory(prefix="glassbox_demo_") as tmp:
        case_dir  = Path(tmp) / "demo-cridex-evtx"
        shutil.copytree(demo_root, case_dir)
        ctx = _build_ctx(
            str(case_dir),
            evidence_dir=str(case_dir / "evidence"),
            replay=True,
            max_iter=args.max_iter or 3,
            replay_dir=str(case_dir / "fixtures"),
        )
        from glassbox.orchestrator import run_triage
        rep = run_triage(ctx, demo_overclaim=True, write=True)

        print(f"\n[GLASSBOX DEMO] Complete — {rep.iterations_used} iteration(s)")
        print(f"  Confirmed findings  : {len(rep.confirmed())}")
        print(f"  Inferred findings   : {len(rep.inferred())}")
        print(f"  Quarantined (hallu) : {len(rep.quarantined)}")
        print(f"  Discrepancies       : {len(rep.discrepancies)}")
        print(f"  Audit chain valid   : {'YES' if rep.audit_chain_valid else 'NO ⚠'}")
        if rep.quarantined:
            print(f"\n  [SELF-CORRECTION SEQUENCE]")
            print(f"  The following claim was quarantined as unsupported:")
            for f in rep.quarantined:
                print(f"    QUARANTINED: {f.title}")
                print(f"    Reason     : {f.verifier_note[:120]}")

        # copy reports to cwd for the judge
        out_dir = Path(args.output) if args.output else Path("demo_output")
        out_dir.mkdir(exist_ok=True)
        import shutil as _sh
        for p in (case_dir / "reports").glob("*"):
            _sh.copy(p, out_dir / p.name)
        print(f"\n  Reports written to: {out_dir.resolve()}")


# ------------------------------------------------------------------ main --
def main():
    parser = argparse.ArgumentParser(
        prog="glassbox",
        description="GLASSBOX — read-only, self-correcting autonomous DFIR triage for SANS SIFT.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # triage
    p_triage = sub.add_parser("triage", help="Run full autonomous triage on a case directory.")
    p_triage.add_argument("case", help="Path to the case directory.")
    p_triage.add_argument("--evidence", help="Evidence directory (default: <case>/evidence/).")
    p_triage.add_argument("--max-iter", type=int, default=3, help="Max self-correction iterations.")
    p_triage.add_argument("--demo-overclaim", action="store_true",
                          help="Inject one over-eager claim to demo the hallucination gate.")
    p_triage.set_defaults(func=cmd_triage)

    # verify-audit
    p_va = sub.add_parser("verify-audit", help="Verify the hash-chained audit log.")
    p_va.add_argument("audit_log", help="Path to *.audit.jsonl file.")
    p_va.set_defaults(func=cmd_verify_audit)

    # check-spoliation
    p_cs = sub.add_parser("check-spoliation", help="Confirm evidence files resist writes.")
    p_cs.add_argument("evidence", help="Evidence directory to probe.")
    p_cs.set_defaults(func=cmd_check_spoliation)

    # benchmark
    p_bm = sub.add_parser("benchmark", help="Score against ground-truth dataset.")
    p_bm.add_argument("gt_dir",   help="Ground-truth directory (EVTX-ATTACK-SAMPLES etc.).")
    p_bm.add_argument("pred_dir", help="Predictions directory (agent output).")
    p_bm.add_argument("--report", default="benchmark_report.json", help="Output report path.")
    p_bm.set_defaults(func=cmd_benchmark)

    # mcp-serve
    p_mcp = sub.add_parser("mcp-serve", help="Launch the read-only MCP server over stdio.")
    p_mcp.add_argument("--case", help="Case directory (sets GLASSBOX_CASE).")
    p_mcp.add_argument("--evidence", help="Evidence directory override.")
    p_mcp.set_defaults(func=cmd_mcp_serve)

    # demo
    p_demo = sub.add_parser("demo", help="Run the offline demo (no SIFT required).")
    p_demo.add_argument("--max-iter", type=int, default=3)
    p_demo.add_argument("--output", help="Directory for report files (default: demo_output/).")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
