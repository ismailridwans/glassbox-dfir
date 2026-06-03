"""Typed LangGraph state for the triage graph.

Append-only fields (``a2a``, ``executed``, ``degraded``) use ``operator.add``
reducers so every node contributes to a cumulative log without clobbering. The
analytical collections (``findings`` etc.) are merged explicitly inside nodes so
iterations can *refine* rather than only append.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any

from typing_extensions import TypedDict


class GraphState(TypedDict, total=False):
    case_id: str
    evidence: list[dict[str, Any]]          # [{path,label,type,sha256}]
    plan: list[dict[str, Any]]              # [{tool,evidence,agent,reason}]
    iteration: int
    max_iterations: int

    findings: list[Any]                     # list[Finding]
    discrepancies: list[Any]                # list[Discrepancy]
    iocs: Annotated[list[Any], operator.add]  # list[IOC] — accumulates across specialists + iterations
    attack: list[Any]                       # list[AttackMapping]
    quarantined: Annotated[list[Any], operator.add]  # list[Finding] (HALLUCINATED) — accumulates across iters

    mem_view: dict[str, Any]
    disk_view: dict[str, Any]

    gaps: list[str]
    verification: dict[str, Any]
    done: bool
    demo_overclaim: bool                    # demo: emit one over-claim to exercise the gate

    # append-only logs
    a2a: Annotated[list[Any], operator.add]         # list[A2AMessage]
    executed: Annotated[list[str], operator.add]    # tool_exec_ids
    degraded: Annotated[list[str], operator.add]    # tool names that degraded
