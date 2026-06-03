"""Assemble the triage StateGraph and run it.

    START → intake → plan → collect → correlate → map_attack → verify → critique
                       ▲                                                    │
                       └──────────────── (gaps & iter<max) ────────────────┘
                                                                            │ else
                                                                            ▼
                                                                          report → END

Two independent loop guards:
  * the in-state ``max_iterations`` counter checked in ``route_after_critique`` —
    the *intended* control;
  * LangGraph's ``recursion_limit`` — a hard global safety net that raises
    ``GraphRecursionError``; we catch it and still emit a report from the last
    checkpoint (graceful degradation, never a crash or a runaway).
"""

from __future__ import annotations

import itertools
from functools import partial
from typing import Optional

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, START, StateGraph

from glassbox.context import CaseContext
from glassbox.models import TriageReport
from glassbox.orchestrator import nodes
from glassbox.orchestrator.llm import BaseLLM, get_llm
from glassbox.orchestrator.state import GraphState


def build_graph(ctx: CaseContext, llm: BaseLLM, seq):
    g = StateGraph(GraphState)
    g.add_node("intake", partial(nodes.intake, ctx=ctx, seq=seq))
    g.add_node("plan", partial(nodes.plan, ctx=ctx, llm=llm, seq=seq))
    g.add_node("collect", partial(nodes.collect, ctx=ctx, llm=llm, seq=seq))
    g.add_node("correlate", partial(nodes.correlate, ctx=ctx, seq=seq))
    g.add_node("map_attack", partial(nodes.map_attack, ctx=ctx))
    g.add_node("verify", partial(nodes.verify, ctx=ctx, seq=seq))
    g.add_node("critique", partial(nodes.critique, ctx=ctx, llm=llm, seq=seq))
    g.add_node("report", partial(nodes.report, ctx=ctx, seq=seq))

    g.add_edge(START, "intake")
    g.add_edge("intake", "plan")
    g.add_edge("plan", "collect")
    g.add_edge("collect", "correlate")
    g.add_edge("correlate", "map_attack")
    g.add_edge("map_attack", "verify")
    g.add_edge("verify", "critique")
    g.add_conditional_edges("critique", nodes.route_after_critique,
                            {"plan": "plan", "report": "report"})
    g.add_edge("report", END)
    return g.compile(checkpointer=InMemorySaver())


def run_triage(
    ctx: CaseContext,
    *,
    demo_overclaim: bool = False,
    max_iterations: Optional[int] = None,
    write: bool = True,
) -> TriageReport:
    """Run the full triage graph for a case and return the TriageReport."""
    llm = get_llm(ctx.config.llm_backend, ctx.config.llm_model)
    seq = itertools.count().__next__
    graph = build_graph(ctx, llm, seq)

    init: GraphState = {
        "case_id": ctx.config.case_id,
        "max_iterations": max_iterations or ctx.config.max_iterations,
        "demo_overclaim": demo_overclaim,
    }
    config = {"configurable": {"thread_id": ctx.config.case_id},
              "recursion_limit": ctx.config.recursion_limit}

    ctx.audit.append("graph_start", llm_backend=llm.name, max_iterations=init["max_iterations"],
                     recursion_limit=ctx.config.recursion_limit)
    try:
        final = graph.invoke(init, config)
    except GraphRecursionError:
        # Safety net tripped: emit a report from the last checkpoint instead of crashing.
        ctx.audit.append("graph_recursion_limit", note="recursion_limit hit; emitting partial report")
        snapshot = graph.get_state(config).values
        final = nodes.report(snapshot, ctx=ctx, seq=seq)
        final = {**snapshot, **final}

    rep: TriageReport = final.get("report")
    if rep is None:  # extreme fallback
        rep = nodes.report(final, ctx=ctx, seq=seq)["report"]
    ctx.audit.append("graph_end", iterations=rep.iterations_used,
                     reportable_findings=len(rep.findings),
                     quarantined=len(rep.quarantined))

    if write:
        from glassbox.report.render import write_report  # lazy to avoid cycles
        write_report(rep, ctx.config.reports_dir, a2a=final.get("a2a", []))
    return rep
