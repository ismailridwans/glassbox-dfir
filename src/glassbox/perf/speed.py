"""Machine-speed reporting.

The hackathon's framing: *"An AI-powered adversary can go from initial access to
full domain control in under 8 minutes."* GLASSBOX's answer is to triage at
machine speed. This module turns the recorded tool-execution timings + total
wall-clock into a speed report that quantifies that velocity and contrasts it
with the adversary breakout benchmarks cited by the hackathon.
"""

from __future__ import annotations

from typing import Iterable

# Adversary speed benchmarks cited on the hackathon page (for contrast).
BREAKOUT_BENCHMARKS = {
    "CrowdStrike fastest observed breakout": 7 * 60 * 1000,   # 7 min in ms
    "Horizon3 autonomous priv-esc": 60 * 1000,                # 60 s in ms
}


def speed_report(tool_executions: Iterable, total_duration_ms: int,
                 iterations: int = 1) -> dict:
    """Build a speed report from ToolExecution records + total wall-clock."""
    execs = list(tool_executions)
    per_tool: dict[str, dict] = {}
    total_tool_ms = 0
    for te in execs:
        ms = getattr(te, "duration_ms", 0) or 0
        total_tool_ms += ms
        slot = per_tool.setdefault(te.tool, {"count": 0, "total_ms": 0})
        slot["count"] += 1
        slot["total_ms"] += ms

    slowest = sorted(per_tool.items(), key=lambda kv: -kv[1]["total_ms"])[:5]

    contrast = {}
    for label, bench_ms in BREAKOUT_BENCHMARKS.items():
        if total_duration_ms > 0:
            contrast[label] = {
                "adversary_ms": bench_ms,
                "glassbox_ms": total_duration_ms,
                "glassbox_faster_x": round(bench_ms / max(total_duration_ms, 1), 1),
            }

    return {
        "total_wall_clock_ms": total_duration_ms,
        "total_wall_clock_s": round(total_duration_ms / 1000, 2),
        "self_correction_iterations": iterations,
        "tool_executions": len(execs),
        "total_tool_time_ms": total_tool_ms,
        "avg_tool_ms": round(total_tool_ms / max(len(execs), 1), 1),
        "slowest_tools": [{"tool": t, **v} for t, v in slowest],
        "vs_adversary_breakout": contrast,
        "headline": (f"Full autonomous triage in {round(total_duration_ms/1000, 2)}s "
                     f"across {len(execs)} tool executions and {iterations} self-correction "
                     f"iteration(s) — the adversary's fastest observed breakout is 7 minutes."),
    }
