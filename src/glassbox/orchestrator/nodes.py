"""Graph nodes. Each node is deterministic code; the LLM (if any) only narrates.

The control flow — and especially the decision to loop — lives in
:func:`route_after_critique`, not in any model output. The max-iterations cap is
enforced there in code. That is what makes the self-correction loop an
*architectural* guardrail rather than a prompted suggestion.
"""

from __future__ import annotations

from typing import Callable

from pathlib import Path

from glassbox.attack import coverage_by_tactic, dedupe_mappings, for_artifact
from glassbox.context import CaseContext
from glassbox.correlate import DiskView, MemoryView, correlate_disk_memory
from glassbox.models import (
    A2AMessage,
    Confidence,
    Discrepancy,
    EvidenceType,
    Finding,
    Severity,
    TokenUsage,
    TriageReport,
    utcnow_iso,
)
from glassbox.orchestrator.llm import BaseLLM
from glassbox.orchestrator.specialists import SPECIALISTS, run_memory
from glassbox.verify import verify_discrepancies, verify_findings

# evidence type -> (specialist agent, base tools for iteration 1)
def _dedup_iocs(iocs) -> list:
    """Deduplicate IOCs by (type, value) preserving first occurrence."""
    seen: set = set()
    out = []
    for ioc in iocs:
        k = (ioc.type if hasattr(ioc, "type") else ioc.get("type", ""),
             str(ioc.value if hasattr(ioc, "value") else ioc.get("value", "")).lower())
        if k not in seen:
            seen.add(k)
            out.append(ioc)
    return out


EVIDENCE_PLAN = {
    EvidenceType.MEMORY: ("memory_analyst", ["mem_pslist", "mem_netscan", "mem_cmdline"]),
    EvidenceType.EVTX:   ("evtx_analyst",   ["evtx_hunt", "evtx_to_json"]),
    EvidenceType.DISK:   ("disk_analyst",   ["disk_partition_table", "disk_list_files", "disk_mft_timeline"]),
    EvidenceType.PCAP:   ("network_analyst", ["pcap_conn_summary", "pcap_dns", "pcap_http"]),
}
# discrepancy kind -> artifact key for ATT&CK enrichment
_DISC_ARTIFACT = {
    "hidden_process": "process_injection",
    "duplicate_singleton_process": "process_hollowing",
    "unexpected_parent_process": "process_injection",
    "orphan_connection": "http_c2",
    "memory_only_executable": "process_injection",
}


def _merge_findings(existing: list[Finding], new: list[Finding]) -> list[Finding]:
    by_id = {f.finding_id: f for f in existing}
    for f in new:
        by_id[f.finding_id] = f
    return list(by_id.values())


# --------------------------------------------------------------------------- #
def intake(state, *, ctx: CaseContext, seq: Callable[[], int]) -> dict:
    man = ctx.toolkit.evidence_manifest()
    evidence = [
        {"path": e["path"], "label": e["path"], "type": e["type"], "sha256": e["sha256"]}
        for e in man["evidence"]
    ]
    ctx.integrity.snapshot()
    msg = A2AMessage(seq=seq(), from_agent="orchestrator", to_agent="case",
                     role="status",
                     summary=f"Case intake: {len(evidence)} evidence item(s); integrity baseline hashed.",
                     refs=[e["label"] for e in evidence])
    return {"evidence": evidence, "iteration": 0, "findings": [], "discrepancies": [],
            "iocs": [], "attack": [], "quarantined": [], "mem_view": {}, "disk_view": {},
            "gaps": [], "done": False, "a2a": [msg]}


def plan(state, *, ctx: CaseContext, llm: BaseLLM, seq: Callable[[], int]) -> dict:
    iteration = int(state.get("iteration", 0)) + 1
    evidence = state.get("evidence", [])
    gaps = state.get("gaps", [])
    ran_pairs = {(te.tool, te.evidence_path) for te in ctx.toolkit.executions}
    steps: list[dict] = []

    if iteration == 1:
        for ev in evidence:
            etype = EvidenceType(ev["type"]) if ev["type"] in EvidenceType._value2member_map_ else EvidenceType.UNKNOWN
            spec = EVIDENCE_PLAN.get(etype)
            if not spec:
                continue
            agent, tools = spec
            for t in tools:
                if (t, ev["label"]) not in ran_pairs:
                    steps.append({"tool": t, "evidence": ev["label"], "agent": agent,
                                  "reason": "baseline triage"})
    else:
        # self-correction: run exactly what the critique asked for
        for g in gaps:
            if (g["tool"], g["evidence"]) in ran_pairs:
                continue
            steps.append({"tool": g["tool"], "evidence": g["evidence"],
                          "agent": g["agent"], "reason": g.get("reason", "gap remediation")})

    # architectural guardrail: drop any step whose tool isn't a real read-only tool
    valid = set(ctx.toolkit.list_tools())
    dropped = [s for s in steps if s["tool"] not in valid]
    steps = [s for s in steps if s["tool"] in valid]
    for d in dropped:
        ctx.audit.append("planner_step_rejected", tool=d["tool"], reason="not a registered read-only tool")

    step_labels = ", ".join(
        f"{s['tool']}({Path(s['evidence']).name})" for s in steps
    )
    rationale, usage = llm.narrate(
        "You are a senior DFIR triage planner. Sequence read-only tools like an analyst.",
        f"Iteration {iteration}. Planning {len(steps)} step(s): {step_labels}",
    )
    ctx.audit.append("plan", iteration=iteration, steps=steps, rationale=rationale,
                     tokens=usage.total)
    msg = A2AMessage(seq=seq(), from_agent="orchestrator", to_agent="specialists",
                     role="plan", summary=f"Iteration {iteration} plan ({len(steps)} step(s)): {rationale}",
                     refs=[s["tool"] for s in steps], token_usage=usage)
    return {"plan": steps, "iteration": iteration, "a2a": [msg]}


def collect(state, *, ctx: CaseContext, llm: BaseLLM, seq: Callable[[], int]) -> dict:
    plan_steps = state.get("plan", [])
    # group tools by (agent, evidence)
    groups: dict[tuple[str, str], list[str]] = {}
    for s in plan_steps:
        groups.setdefault((s["agent"], s["evidence"]), []).append(s["tool"])

    findings = list(state.get("findings", []))
    specialist_iocs: list = []
    mem_view = dict(state.get("mem_view", {}))
    disk_view = dict(state.get("disk_view", {}))
    executed: list[str] = []
    degraded: list[str] = []
    msgs: list[A2AMessage] = []

    for (agent, evidence), tools in groups.items():
        ev_label = Path(evidence).name if evidence else evidence  # basename only — no path leakage
        req = A2AMessage(seq=seq(), from_agent="orchestrator", to_agent=agent, role="request",
                         summary=f"Analyze {ev_label} with {tools}", refs=tools)
        msgs.append(req)
        if agent == "memory_analyst":
            out = run_memory(ctx.toolkit, evidence, tools, demo_overclaim=bool(state.get("demo_overclaim")))
        else:
            out = SPECIALISTS[agent](ctx.toolkit, evidence, tools)
        findings = _merge_findings(findings, out["findings"])
        specialist_iocs.extend(out.get("iocs", []))
        if agent in ("memory_analyst",):
            mem_view.update(out["view"])
        if agent in ("disk_analyst",):
            disk_view.update(out["view"])
        executed += out["executed"]
        degraded += out["degraded"]
        _, usage = llm.narrate("You are a DFIR specialist; explain findings briefly.", out["rationale"])
        res = A2AMessage(seq=seq(), from_agent=agent, to_agent="orchestrator", role="result",
                         summary=f"{len(out['findings'])} finding(s). {out['rationale']}",
                         refs=out["executed"], token_usage=usage)
        msgs.append(res)
        ctx.audit.append("specialist_result", agent=agent, evidence=evidence, tools=tools,
                         n_findings=len(out["findings"]), executed=out["executed"],
                         degraded=out["degraded"], rationale=out["rationale"])

    return {"findings": findings, "iocs": specialist_iocs, "mem_view": mem_view,
            "disk_view": disk_view, "executed": executed, "degraded": degraded, "a2a": msgs}


def correlate(state, *, ctx: CaseContext, seq: Callable[[], int]) -> dict:
    mv = state.get("mem_view", {})
    dv = state.get("disk_view", {})
    mem = MemoryView(
        pslist=mv.get("pslist", []), psscan=mv.get("psscan", []), netscan=mv.get("netscan", []),
        pslist_exec_id=mv.get("pslist_exec_id"), psscan_exec_id=mv.get("psscan_exec_id"),
        netscan_exec_id=mv.get("netscan_exec_id"),
    )
    disk = DiskView(image_names=dv.get("image_names", []), listing_exec_id=dv.get("listing_exec_id")) if dv else None
    discrepancies = correlate_disk_memory(mem, disk)

    # mirror each discrepancy into a verifiable INFERRED finding so it gets
    # ATT&CK enrichment and flows through the same gate.
    mirrors: list[Finding] = []
    for d in discrepancies:
        artifact = _DISC_ARTIFACT.get(d.kind)
        # Build a clean title from kind + first affected identifier in provenance
        locator = d.provenance[0].raw_locator if d.provenance else ""
        kind_label = d.kind.replace("_", " ").title()
        title = f"[{kind_label}] {locator}" if locator else kind_label
        mirrors.append(Finding(
            finding_id=f"F-{d.discrepancy_id}",
            title=title,
            description=d.description,
            evidence_type=EvidenceType.MEMORY,
            severity=d.severity,
            confidence=Confidence.INFERRED,
            attack=for_artifact(artifact) if artifact else [],
            cited_values=[p.raw_locator for p in d.provenance],
            provenance=list(d.provenance),
            source_agent="correlation_engine",
        ))
    findings = _merge_findings(list(state.get("findings", [])), mirrors)
    ctx.audit.append("correlation", n_discrepancies=len(discrepancies),
                     kinds=[d.kind for d in discrepancies])
    msg = A2AMessage(seq=seq(), from_agent="correlation_engine", to_agent="orchestrator",
                     role="result",
                     summary=f"{len(discrepancies)} cross-source discrepancy(ies): "
                             + ", ".join(d.kind for d in discrepancies),
                     refs=[d.discrepancy_id for d in discrepancies])
    return {"discrepancies": discrepancies, "findings": findings, "a2a": [msg]}


def map_attack(state, *, ctx: CaseContext) -> dict:
    findings = state.get("findings", [])
    mappings = []
    finding_iocs = []
    for f in findings:
        mappings += f.attack
        finding_iocs += f.iocs
    mappings = dedupe_mappings(mappings)
    # finding_iocs are added to the accumulator (state["iocs"] already has specialist iocs)
    ctx.audit.append("attack_mapping", techniques=[m.technique_id for m in mappings],
                     finding_ioc_count=len(finding_iocs))
    return {"attack": mappings, "iocs": finding_iocs}  # accumulator adds to existing specialist iocs


def verify(state, *, ctx: CaseContext, seq: Callable[[], int]) -> dict:
    known = ctx.known_exec_ids()
    result = verify_findings(state.get("findings", []), ctx.rawstore, known, audit=ctx.audit)
    reportable_ids = [f.finding_id for f in result.verified]
    kept_disc, dropped_disc = verify_discrepancies(
        state.get("discrepancies", []), reportable_ids, ctx.rawstore, known, audit=ctx.audit
    )
    summary = result.summary()
    summary["discrepancies_kept"] = len(kept_disc)
    summary["discrepancies_dropped"] = len(dropped_disc)
    msg = A2AMessage(seq=seq(), from_agent="verifier", to_agent="orchestrator", role="result",
                     summary=(f"Verified: {summary['confirmed']} confirmed, {summary['inferred']} inferred, "
                              f"{summary['hallucinated']} HALLUCINATED (quarantined)."),
                     refs=[o.finding_id for o in result.outcomes if o.verdict == Confidence.HALLUCINATED])
    return {"findings": result.verified, "quarantined": result.quarantined,
            "discrepancies": kept_disc, "verification": summary, "a2a": [msg]}


def critique(state, *, ctx: CaseContext, llm: BaseLLM, seq: Callable[[], int]) -> dict:
    """Self-critique: find concrete gaps and decide whether to loop. The loop
    decision is bounded by max_iterations in route_after_critique."""
    iteration = int(state.get("iteration", 0))
    findings = state.get("findings", [])
    verification = state.get("verification", {})
    ran = {te.tool for te in ctx.toolkit.executions}
    ran_pairs = {(te.tool, te.evidence_path) for te in ctx.toolkit.executions}
    evidence = state.get("evidence", [])
    mem_labels = [e["label"] for e in evidence if e["type"] == "memory"]

    gaps: list[dict] = []
    notes: list[str] = []

    # Indicators that justify deeper memory analysis
    ext_or_inj = any(
        ("External network connection" in f.title) or ("Injected" in f.title)
        or ("malfind" in f.description.lower())
        for f in findings
    )
    for mem in mem_labels:
        if ext_or_inj and ("mem_psscan", mem) not in ran_pairs:
            gaps.append({"tool": "mem_psscan", "evidence": mem, "agent": "memory_analyst",
                         "reason": "external/injection indicators warrant a hidden-process pool scan"})
        if ext_or_inj and ("mem_malfind", mem) not in ran_pairs:
            gaps.append({"tool": "mem_malfind", "evidence": mem, "agent": "memory_analyst",
                         "reason": "check for injected/RWX code behind the suspicious activity"})
        # service-related EVTX detection -> corroborate with svcscan
        if any("service" in f.title.lower() or "7045" in (f.observed_at or "") for f in findings) \
                and ("mem_svcscan", mem) not in ran_pairs:
            gaps.append({"tool": "mem_svcscan", "evidence": mem, "agent": "memory_analyst",
                         "reason": "corroborate service-install events against in-memory services"})

    # Graceful degradation -> try a pure-Python fallback for EVTX
    if "evtx_to_json" in {d for d in state.get("degraded", [])}:
        for ev in evidence:
            if ev["type"] == "evtx" and ("evtx_dump_xml", ev["label"]) not in ran_pairs:
                gaps.append({"tool": "evtx_dump_xml", "evidence": ev["label"], "agent": "evtx_analyst",
                             "reason": "EvtxECmd unavailable; fall back to python-evtx"})

    if verification.get("hallucinated"):
        notes.append(f"{verification['hallucinated']} unsupported claim(s) quarantined by the verifier")

    # de-dupe gaps
    uniq = []
    seen = set()
    for g in gaps:
        k = (g["tool"], g["evidence"])
        if k not in seen:
            seen.add(k)
            uniq.append(g)
    gaps = uniq

    done = (not gaps) or (iteration >= int(state.get("max_iterations", 3)))
    rationale, usage = llm.narrate(
        "You are a senior DFIR reviewer checking whether the triage is complete.",
        (f"Iteration {iteration}/{state.get('max_iterations')}: "
         f"{len(findings)} findings, {verification.get('hallucinated', 0)} quarantined. "
         f"Gaps: {[g['tool'] for g in gaps] or 'none'}. "
         f"{'Looping to remediate.' if (gaps and not done) else 'Concluding.'} "
         + (" ".join(notes))),
    )
    ctx.audit.append("critique", iteration=iteration, gaps=[g["tool"] for g in gaps],
                     done=done, notes=notes, rationale=rationale, tokens=usage.total)
    msg = A2AMessage(seq=seq(), from_agent="orchestrator", to_agent="self", role="critique",
                     summary=rationale, refs=[g["tool"] for g in gaps], token_usage=usage)
    return {"gaps": gaps, "done": done, "a2a": [msg]}


def route_after_critique(state) -> str:
    """Code-enforced loop bound. Returns 'plan' (self-correct) or 'report'."""
    if state.get("done"):
        return "report"
    if int(state.get("iteration", 0)) >= int(state.get("max_iterations", 3)):
        return "report"
    if not state.get("gaps"):
        return "report"
    return "plan"


def report(state, *, ctx: CaseContext, seq: Callable[[], int]) -> dict:
    from glassbox.timeline import build_timeline, narrative_summary  # lazy — avoids import cycle
    integrity = ctx.integrity.verify()
    chain_valid, chain_errs = ctx.audit.verify_self()
    findings = state.get("findings", [])
    discrepancies = state.get("discrepancies", [])
    attack = state.get("attack", [])
    a2a = state.get("a2a", [])
    total = TokenUsage()
    timeline = build_timeline(findings, discrepancies)
    narrative = narrative_summary(timeline, case_id=state.get("case_id", ctx.config.case_id))
    for m in a2a:
        total = total + (m.token_usage if isinstance(m.token_usage, TokenUsage) else TokenUsage(**m.token_usage))

    rep = TriageReport(
        case_id=state.get("case_id", ctx.config.case_id),
        summary=(f"{len(findings)} reportable finding(s) across "
                 f"{len({f.evidence_type for f in findings})} evidence type(s); "
                 f"{len(state.get('discrepancies', []))} cross-source discrepancy(ies); "
                 f"{len(state.get('quarantined', []))} claim(s) quarantined as unsupported."),
        evidence_types=sorted({EvidenceType(e["type"]) for e in state.get("evidence", [])
                               if e["type"] in EvidenceType._value2member_map_}, key=lambda x: x.value),
        findings=findings,
        discrepancies=discrepancies,
        iocs=_dedup_iocs(state.get("iocs", [])),
        attack_coverage=attack,
        quarantined=state.get("quarantined", []),
        integrity=integrity,
        iterations_used=int(state.get("iteration", 0)),
        max_iterations=int(state.get("max_iterations", 3)),
        degraded_tools=sorted(set(state.get("degraded", []))),
        total_tokens=total,
        audit_log_ref=ctx.config.audit_path.name,
        audit_chain_valid=chain_valid,
        timeline=[e.as_dict() for e in timeline],
        narrative=narrative,
    )
    ctx.audit.append("report", n_findings=len(findings),
                     n_quarantined=len(state.get("quarantined", [])),
                     spoliation_detected=ctx.integrity.spoliation_detected(),
                     audit_chain_valid=chain_valid, chain_errors=chain_errs[:3])
    msg = A2AMessage(seq=seq(), from_agent="orchestrator", to_agent="analyst", role="status",
                     summary=f"Triage complete in {rep.iterations_used} iteration(s). {rep.summary}")
    return {"report": rep, "done": True, "a2a": [msg]}
