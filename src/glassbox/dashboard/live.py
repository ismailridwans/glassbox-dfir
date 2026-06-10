"""Live terminal dashboard for GLASSBOX triage.

Streams the LangGraph state machine node-by-node and renders the agent's
reasoning in real time — the planner sequencing tools, specialists reporting
findings, the correlation engine catching discrepancies, the hallucination gate
quarantining over-claims, the red-team panel upholding/refuting, and the
self-correction loop deciding to iterate. Dependency-free ANSI output, ideal
for the 5-minute demo screencast.
"""

from __future__ import annotations

import itertools
import time

from glassbox.context import CaseContext
from glassbox.orchestrator.graph import build_graph
from glassbox.orchestrator.llm import get_llm

# ANSI
_R = "\033[0m"; _B = "\033[1m"; _DIM = "\033[2m"
_CY = "\033[36m"; _GR = "\033[32m"; _YE = "\033[33m"; _RE = "\033[31m"; _MA = "\033[35m"; _BL = "\033[34m"

_NODE_ICON = {
    "intake": ("[*]", _CY, "INTAKE"),
    "plan": ("[>]", _BL, "PLAN"),
    "collect": ("[#]", _CY, "COLLECT"),
    "correlate": ("[~]", _MA, "CORRELATE"),
    "map_attack": ("[+]", _YE, "ATT&CK MAP"),
    "verify": ("[v]", _GR, "VERIFY (hallucination gate)"),
    "adversarial_verify": ("[X]", _RE, "RED-TEAM PANEL"),
    "critique": ("[?]", _YE, "SELF-CRITIQUE"),
    "report": ("[=]", _GR, "REPORT"),
}


def _supports_ansi() -> bool:
    import sys
    # ANSI colour only when attached to a TTY *and* the stream can encode it.
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return tty and ("utf" in enc)


def run_dashboard(ctx: CaseContext, *, demo_overclaim: bool = False, max_iterations: int = 3,
                  use_color: bool | None = None) -> "object":
    """Run triage with a live node-by-node dashboard. Returns the TriageReport."""
    color = _supports_ansi() if use_color is None else use_color

    def c(code: str, s: str) -> str:
        return f"{code}{s}{_R}" if color else s

    llm = get_llm(ctx.config.llm_backend, ctx.config.llm_model)
    seq = itertools.count().__next__
    graph = build_graph(ctx, llm, seq)
    init = {"case_id": ctx.config.case_id, "max_iterations": max_iterations,
            "demo_overclaim": demo_overclaim}
    config = {"configurable": {"thread_id": ctx.config.case_id},
              "recursion_limit": ctx.config.recursion_limit}

    bar = "=" * 68
    print(c(_B, f"\n  {bar}"))
    print(c(_B, "   GLASSBOX - Autonomous DFIR Triage  (live execution trace)"))
    print(c(_B, f"  {bar}"))
    print(f"  case: {c(_CY, ctx.config.case_id)}   evidence: {ctx.config.evidence_dir}")
    print(f"  {c(_DIM, 'every finding traces to a tool call | evidence is read-only | loop is bounded')}\n")

    t0 = time.perf_counter()
    iteration = 0
    rep = None
    # Capture the report from the stream itself (avoids checkpoint deserialization).
    for step in graph.stream(init, config, stream_mode="updates"):
        for node, delta in step.items():
            icon, col, label = _NODE_ICON.get(node, ("*", _R, node.upper()))
            elapsed = f"{(time.perf_counter()-t0):6.2f}s"
            line = f"  {c(_DIM, elapsed)}  {icon} {c(col + _B, label):<40}"
            detail = _node_detail(node, delta, c)
            print(line + detail)
            if node == "plan":
                iteration = delta.get("iteration", iteration)
            if node == "report" and isinstance(delta, dict) and delta.get("report") is not None:
                rep = delta["report"]

    if rep is None:
        from glassbox.orchestrator import run_triage
        return run_triage(ctx, demo_overclaim=demo_overclaim, max_iterations=max_iterations)
    rep.duration_ms = int((time.perf_counter() - t0) * 1000)

    total = time.perf_counter() - t0
    print()
    _render_summary(rep, total, c)
    return rep


def _node_detail(node: str, delta: dict, c) -> str:
    if node == "intake":
        ev = delta.get("evidence", [])
        return c(_DIM, f"{len(ev)} evidence item(s) hashed; integrity baseline set")
    if node == "plan":
        plan = delta.get("plan", [])
        it = delta.get("iteration", "?")
        tools = ", ".join(s["tool"] for s in plan[:4]) + ("..." if len(plan) > 4 else "")
        tag = c(_YE, f"[iter {it}]")
        return f"{tag} {c(_DIM, f'{len(plan)} step(s): {tools}')}"
    if node == "collect":
        n = len(delta.get("findings", []))
        return c(_DIM, f"specialists ran; {n} cumulative finding(s)")
    if node == "correlate":
        d = len(delta.get("discrepancies", []))
        return c(_MA, f"{d} cross-source discrepancy(ies)")
    if node == "map_attack":
        a = len(delta.get("attack", []))
        return c(_YE, f"{a} ATT&CK technique(s) mapped")
    if node == "verify":
        v = delta.get("verification", {})
        q = v.get("hallucinated", 0)
        s = f"{v.get('confirmed',0)} confirmed, {v.get('inferred',0)} inferred"
        if q:
            s += c(_RE, f", {q} HALLUCINATED->quarantined")
        return c(_GR, s)
    if node == "adversarial_verify":
        a = delta.get("adversarial", {})
        s = f"{a.get('upheld',0)} UPHELD"
        if a.get("demoted"):
            s += f", {a['demoted']} demoted"
        if a.get("refuted"):
            s += c(_RE, f", {a['refuted']} REFUTED (false positives)")
        return c(_RE, "red-team: ") + c(_DIM, s)
    if node == "critique":
        gaps = delta.get("gaps", [])
        done = delta.get("done")
        if gaps and not done:
            return c(_YE, f"gap found -> SELF-CORRECTING ({', '.join(g['tool'] for g in gaps[:3])})")
        return c(_GR, "no actionable gaps -> concluding")
    if node == "report":
        return c(_GR + _B, "triage complete")
    return ""


def _render_summary(rep, total_s: float, c) -> None:
    rtv = len(rep.red_team_verified())
    bar = "-" * 68
    print(c(_B, f"  +{bar}+"))
    print(f"  | Reportable findings : {c(_B, str(len(rep.findings))):<28}"
          f" iterations: {rep.iterations_used}/{rep.max_iterations}")
    print(f"  | {c(_RE,'RED-TEAM VERIFIED')}    : {rtv:<6} {c(_DIM,'(survived adversarial panel)')}")
    print(f"  | Refuted -> context   : {len(rep.refuted):<6} {c(_DIM,'(false positives caught)')}")
    print(f"  | Quarantined (hallu)  : {len(rep.quarantined):<6} {c(_DIM,'(unsupported claims)')}")
    print(f"  | Discrepancies        : {len(rep.discrepancies)}   IOCs: {len(rep.iocs)}   "
          f"ATT&CK: {len(rep.attack_coverage)}")
    chain = c(_GR, "VALID") if rep.audit_chain_valid else c(_RE, "BROKEN")
    spol = c(_RE, "YES") if any(not r.unchanged for r in rep.integrity) else c(_GR, "NO")
    print(f"  | Audit chain: {chain}   Spoliation: {spol}   "
          f"{c(_B, f'{total_s:.2f}s')} {c(_DIM,'(adversary breakout: 7 min)')}")
    print(c(_B, f"  +{bar}+"))
