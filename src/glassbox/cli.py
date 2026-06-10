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
    print(f"\n[GLASSBOX] Triage complete - {rep.iterations_used} iteration(s)")
    print(f"  Reportable findings : {len(rep.findings)}")
    print(f"  Confirmed           : {len(rep.confirmed())}")
    print(f"  Inferred            : {len(rep.inferred())}")
    print(f"  Quarantined (hallu) : {len(rep.quarantined)}")
    print(f"  Discrepancies       : {len(rep.discrepancies)}")
    print(f"  IOCs                : {len(rep.iocs)}")
    print(f"  ATT&CK techniques   : {len(rep.attack_coverage)}")
    print(f"  Timeline events     : {len(rep.timeline)}")
    print(f"  Audit chain valid   : {'YES' if rep.audit_chain_valid else 'NO [!!]'}")
    print(f"  Spoliation detected : {'YES [!!]' if any(not r.unchanged for r in rep.integrity) else 'NO'}")
    print(paths_msg)


def cmd_verify_audit(args):
    from glassbox.audit.chain import AuditChain
    path = Path(args.audit_log)
    ok, errors = AuditChain.verify(path)
    if ok:
        print(f"[OK] Audit chain VALID: {path}")
    else:
        print(f"[!!] Audit chain INVALID: {path}")
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
        print("\n[!!] SPOLIATION POSSIBLE - some evidence files could be opened for write.")
        sys.exit(1)
    else:
        print(f"\n[OK] All {result['files_tested']} write attempts blocked - evidence integrity holds.")


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


def cmd_replay_verify(args):
    """Deterministic replay: prove findings re-derive from audit log + raw store."""
    from glassbox.forensic import replay_verify
    result = replay_verify(args.audit_log, args.raw_dir, args.report_json)
    _print_json(result.summary())
    if result.reproducible:
        print(f"\n[OK] REPRODUCIBLE: audit chain intact; "
              f"{result.findings_reproduced}/{result.findings_checked} findings re-derived "
              f"from {result.tool_executions_in_log} logged tool executions.")
    else:
        print(f"\n[WARN] Not fully reproducible: {result.note}")
        sys.exit(1)


def cmd_bundle(args):
    """Build a court-admissible forensic bundle."""
    from glassbox.forensic.bundle import build_bundle
    from pathlib import Path
    rd = Path(args.reports_dir)
    case_files = list(rd.glob("*.report.json"))
    if not case_files:
        print(f"ERROR: no *.report.json in {rd}")
        sys.exit(1)
    case_id = case_files[0].name.replace(".report.json", "")
    bundle = build_bundle(
        case_id,
        report_md=rd / f"{case_id}.report.md",
        report_json=rd / f"{case_id}.report.json",
        audit_log=Path(args.audit_log),
        execution_log=rd / f"{case_id}.execution_log.jsonl",
        out_dir=args.output,
    )
    _print_json(bundle.model_dump())
    print(f"\n[OK] Court-admissible bundle written to {args.output}")
    print(f"     Bundle hash: {bundle.bundle_hash}")
    print(f"     Sealed (HMAC): {bundle.sealed}")


def cmd_export_navigator(args):
    """Export findings as a MITRE ATT&CK Navigator layer + Diamond Model."""
    import json as _json
    from pathlib import Path
    from glassbox.attack.navigator import to_navigator_layer, to_diamond_model
    report = _json.loads(Path(args.report_json).read_text(encoding="utf-8"))
    layer = to_navigator_layer(report)
    diamond = to_diamond_model(report)
    out = Path(args.output) if args.output else Path("navigator_layer.json")
    out.write_text(_json.dumps(layer, indent=2), encoding="utf-8")
    diamond_out = out.with_name(out.stem + "_diamond.json")
    diamond_out.write_text(_json.dumps(diamond, indent=2), encoding="utf-8")
    print(f"[OK] ATT&CK Navigator layer ({len(layer['techniques'])} techniques) -> {out}")
    print(f"     Load at https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer)")
    print(f"[OK] Diamond Model -> {diamond_out}")


def cmd_dashboard(args):
    """Run triage with a live node-by-node terminal dashboard (great for demos)."""
    import tempfile, shutil
    from pathlib import Path
    demo_root = Path(__file__).parent.parent.parent / "demo_case"
    if not demo_root.exists():
        demo_root = Path("demo_case")
    if args.case:
        ctx = _build_ctx(args.case, args.evidence, max_iter=args.max_iter)
        from glassbox.dashboard import run_dashboard
        run_dashboard(ctx, demo_overclaim=args.demo_overclaim, max_iterations=args.max_iter)
        return
    with tempfile.TemporaryDirectory(prefix="glassbox_dash_") as tmp:
        case_dir = Path(tmp) / "demo-cridex-evtx"
        shutil.copytree(demo_root, case_dir)
        ctx = _build_ctx(str(case_dir), evidence_dir=str(case_dir / "evidence"),
                         replay=True, max_iter=args.max_iter or 3,
                         replay_dir=str(case_dir / "fixtures"))
        from glassbox.dashboard import run_dashboard
        run_dashboard(ctx, demo_overclaim=True, max_iterations=args.max_iter or 3)


def cmd_serve(args):
    """Launch the GLASSBOX web dashboard (zero-dependency stdlib server)."""
    from glassbox.web import serve
    serve(host=args.host, port=args.port,
          case_dir=args.case, evidence_dir=args.evidence,
          demo=(args.case is None), max_iterations=args.max_iter,
          open_browser=not args.no_browser, auto_run=args.auto_run)


def cmd_guardrail_selftest(args):
    """Actively test every architectural guardrail boundary."""
    from glassbox.guardrail import run_guardrail_selftest
    rep = run_guardrail_selftest()
    print("[GLASSBOX] Architectural Guardrail Self-Test\n")
    for c in rep.checks:
        mark = "[PASS]" if c.passed else "[FAIL]"
        print(f"  {mark} {c.name:18s} {c.detail}")
    summ = rep.summary()
    print(f"\n  {summ['passed']}/{summ['total']} guardrail checks passed.")
    if not rep.all_passed:
        sys.exit(1)
    print("  All architectural guardrails hold. Spoliation/hallucination/tamper are "
          "structurally prevented, not prompt-requested.")


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

        rtv = len(rep.red_team_verified())
        print(f"\n[GLASSBOX DEMO] Complete - {rep.iterations_used} iteration(s) in {rep.duration_ms} ms")
        print(f"  Confirmed findings    : {len(rep.confirmed())}")
        print(f"  Inferred findings     : {len(rep.inferred())}")
        print(f"  RED-TEAM VERIFIED     : {rtv}   (survived adversarial panel)")
        print(f"  Refuted -> context    : {len(rep.refuted)}   (false positives caught by red-team)")
        print(f"  Quarantined (hallu)   : {len(rep.quarantined)}")
        print(f"  Discrepancies         : {len(rep.discrepancies)}")
        print(f"  IOCs extracted        : {len(rep.iocs)}")
        print(f"  ATT&CK techniques     : {len(rep.attack_coverage)}")
        print(f"  Timeline events       : {len(rep.timeline)}")
        print(f"  Evidence types        : {', '.join(e.value for e in rep.evidence_types)}")
        print(f"  Audit chain valid     : {'YES' if rep.audit_chain_valid else 'NO [!!]'}")
        print(f"  Spoliation detected   : {'YES [!!]' if any(not r.unchanged for r in rep.integrity) else 'NO'}")
        if rep.quarantined:
            print(f"\n  [SELF-CORRECTION SEQUENCE]")
            print(f"  The following claim was quarantined as unsupported:")
            for f in rep.quarantined:
                print(f"    QUARANTINED: {f.title}")
                print(f"    Reason     : {f.verifier_note[:120]}")
        if rep.refuted:
            print(f"\n  [ADVERSARIAL RED-TEAM caught these false positives]")
            for f in rep.refuted[:4]:
                print(f"    REFUTED: {f.title[:60]}")

        # Export a complete, self-contained forensic case for the judge:
        # reports + audit log + raw store (so replay-verify and bundle work).
        out_dir = Path(args.output) if args.output else Path("demo_output")
        out_dir.mkdir(exist_ok=True)
        import shutil as _sh
        for p in (case_dir / "reports").glob("*"):
            _sh.copy(p, out_dir / p.name)
        if (case_dir / "case.audit.jsonl").exists():
            _sh.copy(case_dir / "case.audit.jsonl", out_dir / "case.audit.jsonl")
        if (case_dir / "raw").exists():
            _sh.copytree(case_dir / "raw", out_dir / "raw", dirs_exist_ok=True)
        print(f"\n  Forensic case exported to: {out_dir.resolve()}")
        print(f"  (reports + case.audit.jsonl + raw/  — try: glassbox replay-verify)")


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

    # replay-verify (deterministic reproducibility)
    p_rv = sub.add_parser("replay-verify",
                          help="Prove findings re-derive from the audit log + raw store.")
    p_rv.add_argument("audit_log", help="Path to *.audit.jsonl")
    p_rv.add_argument("raw_dir", help="Path to the case raw/ directory")
    p_rv.add_argument("report_json", help="Path to *.report.json")
    p_rv.set_defaults(func=cmd_replay_verify)

    # bundle (court-admissible package)
    p_bn = sub.add_parser("bundle", help="Build a court-admissible forensic bundle.")
    p_bn.add_argument("reports_dir", help="Directory with *.report.{md,json}")
    p_bn.add_argument("audit_log", help="Path to *.audit.jsonl")
    p_bn.add_argument("--output", default="forensic_bundle", help="Bundle output directory")
    p_bn.set_defaults(func=cmd_bundle)

    # export-navigator (ATT&CK Navigator layer + Diamond Model)
    p_nav = sub.add_parser("export-navigator",
                           help="Export an ATT&CK Navigator layer + Diamond Model from a report.")
    p_nav.add_argument("report_json", help="Path to *.report.json")
    p_nav.add_argument("--output", help="Output layer path (default: navigator_layer.json)")
    p_nav.set_defaults(func=cmd_export_navigator)

    # guardrail-selftest (architectural boundary verification)
    p_gs = sub.add_parser("guardrail-selftest",
                          help="Actively test every architectural guardrail (criterion #4).")
    p_gs.set_defaults(func=cmd_guardrail_selftest)

    # serve (web dashboard)
    p_sv = sub.add_parser("serve", help="Launch the GLASSBOX web dashboard (browser UI).")
    p_sv.add_argument("--host", default="127.0.0.1")
    p_sv.add_argument("--port", type=int, default=8787)
    p_sv.add_argument("--case", help="Case directory (default: bundled demo case in replay mode).")
    p_sv.add_argument("--evidence", help="Evidence directory override.")
    p_sv.add_argument("--max-iter", type=int, default=3)
    p_sv.add_argument("--no-browser", action="store_true", help="Do not auto-open a browser.")
    p_sv.add_argument("--auto-run", action="store_true", help="Run one triage at startup.")
    p_sv.set_defaults(func=cmd_serve)

    # dashboard (live execution trace — for the demo video)
    p_db = sub.add_parser("dashboard", help="Run triage with a live node-by-node dashboard.")
    p_db.add_argument("--case", help="Case directory (default: bundled demo case).")
    p_db.add_argument("--evidence", help="Evidence directory override.")
    p_db.add_argument("--demo-overclaim", action="store_true")
    p_db.add_argument("--max-iter", type=int, default=3)
    p_db.set_defaults(func=cmd_dashboard)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
