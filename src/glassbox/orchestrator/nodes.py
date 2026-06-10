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
    EvidenceType.MEMORY:   ("memory_analyst",   ["mem_pslist", "mem_netscan", "mem_cmdline", "yara_scan"]),
    EvidenceType.EVTX:     ("evtx_analyst",     ["evtx_hunt", "evtx_to_json"]),
    EvidenceType.DISK:     ("disk_analyst",     ["disk_partition_table", "disk_list_files", "disk_mft_timeline"]),
    EvidenceType.PCAP:     ("network_analyst",  ["pcap_conn_summary", "pcap_dns", "pcap_http"]),
    EvidenceType.REGISTRY: ("registry_analyst", ["registry_analyze"]),
}
# discrepancy kind -> artifact key for ATT&CK enrichment
_DISC_ARTIFACT = {
    "hidden_process": "process_injection",
    "duplicate_singleton_process": "process_hollowing",
    "unexpected_parent_process": "process_injection",
    "orphan_connection": "http_c2",
    "memory_only_executable": "process_injection",
    "temporal_process_network_correlation": "http_c2",
}


def _merge_findings(existing: list[Finding], new: list[Finding],
                    iteration: int = 0) -> list[Finding]:
    by_id = {f.finding_id: f for f in existing}
    for f in new:
        if f.finding_id not in by_id:
            if iteration > 0:
                f.iteration_found = iteration
            by_id[f.finding_id] = f
        else:
            by_id[f.finding_id] = f  # update with refined version
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
    evtx_view = dict(state.get("evtx_view", {}))
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
        iteration = int(state.get("iteration", 1))
        findings = _merge_findings(findings, out["findings"], iteration=iteration)
        specialist_iocs.extend(out.get("iocs", []))
        if agent == "memory_analyst":
            mem_view.update(out["view"])
        elif agent == "disk_analyst":
            disk_view.update(out["view"])
        elif agent == "evtx_analyst":
            evtx_view.update(out["view"])
        # registry_analyst findings flow into findings list only (no separate view needed)
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
            "disk_view": disk_view, "evtx_view": evtx_view,
            "executed": executed, "degraded": degraded, "a2a": msgs}


def correlate(state, *, ctx: CaseContext, seq: Callable[[], int]) -> dict:
    # Merge all specialist views so credential/lateral detectors can see evtx_events from EVTX analyst
    mv = dict(state.get("mem_view", {}))
    ev = state.get("evtx_view", {})  # populated by evtx specialists
    mv.update({k: v for k, v in ev.items() if k not in mv})
    dv = state.get("disk_view", {})
    mem = MemoryView(
        pslist=mv.get("pslist", []), psscan=mv.get("psscan", []), netscan=mv.get("netscan", []),
        pslist_exec_id=mv.get("pslist_exec_id"), psscan_exec_id=mv.get("psscan_exec_id"),
        netscan_exec_id=mv.get("netscan_exec_id"),
    )
    disk = DiskView(image_names=dv.get("image_names", []), listing_exec_id=dv.get("listing_exec_id")) if dv else None
    discrepancies = correlate_disk_memory(mem, disk)

    # Temporal correlation: process create-time vs. network connection
    if mv.get("pslist") and mv.get("netscan") and mv.get("pslist_exec_id") and mv.get("netscan_exec_id"):
        from glassbox.correlate.temporal import temporal_process_network_correlation
        temporal_disc = temporal_process_network_correlation(
            mv["pslist"], mv["netscan"],
            mv["pslist_exec_id"], mv["netscan_exec_id"],
        )
        discrepancies = list(discrepancies) + temporal_disc

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

    # Credential access + lateral movement detection (cross-specialist)
    evtx_events = mv.get("evtx_events", [])
    cmdlines = mv.get("cmdlines", [])
    evtx_exec_id = mv.get("evtx_to_json_exec_id", "")
    cmdline_exec_id = mv.get("cmdline_exec_id", "")
    if evtx_events or cmdlines:
        from glassbox.detect import detect_credential_access, detect_lateral_movement
        cred_findings = detect_credential_access(
            evtx_events, cmdlines, evtx_exec_id or "unknown", cmdline_exec_id or "unknown"
        )
        lateral_findings = detect_lateral_movement(
            evtx_events, cmdlines, evtx_exec_id or "unknown", cmdline_exec_id or "unknown"
        )
        findings = _merge_findings(findings, cred_findings + lateral_findings)
        ctx.audit.append("detection_modules",
                         credential=len(cred_findings), lateral=len(lateral_findings))

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
    findings_to_verify = list(state.get("findings", []))
    # Apply persistent lessons log: pre-downgrade known-bad patterns
    suppressed = ctx.lessons.apply_to_findings(findings_to_verify)
    if suppressed > 0:
        ctx.audit.append("lessons_applied", suppressed_count=suppressed,
                         lessons_total=ctx.lessons.summary()["total_lessons"])
    result = verify_findings(findings_to_verify, ctx.rawstore, known, audit=ctx.audit)
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


def adversarial_verify(state, *, ctx: CaseContext, seq: Callable[[], int]) -> dict:
    """Adversarial Verification Panel — red-team every grounded finding.

    A grounded finding can still be a false positive. The panel of skeptic
    perspectives challenges each one; findings are UPHELD (red-team verified),
    DEMOTED (kept, severity lowered), or REFUTED (moved to a context bucket).
    Runs every iteration so corroboration discovered in a later loop can
    *upgrade* a previously-uncertain finding."""
    from glassbox.adversarial import AdversarialPanel
    findings = list(state.get("findings", []))
    panel = AdversarialPanel()
    result = panel.review(findings, rawstore=ctx.rawstore,
                          known_exec_ids=ctx.known_exec_ids(), audit=ctx.audit)
    summ = result.summary()
    # Keep ALL reviewed findings in state (verdicts applied in place) so re-review
    # across self-correction iterations is consistent. The active-vs-refuted split
    # is computed once, at report time, from each finding's adversarial_verdict.
    msg = A2AMessage(
        seq=seq(), from_agent="red_team", to_agent="orchestrator", role="result",
        summary=(f"Adversarial panel ({len(panel.skeptics)} skeptics): "
                 f"{summ['upheld']} UPHELD (red-team verified), {summ['demoted']} demoted, "
                 f"{summ['refuted']} refuted to context."),
        refs=[v.finding_id for v in result.verdicts if v.verdict == "REFUTED"],
    )
    return {"findings": findings, "adversarial": summ, "a2a": [msg]}


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
        or ("malfind" in f.description.lower()) or ("YARA match" in f.title)
        for f in findings
    )
    has_hidden_proc = any("hidden" in f.title.lower() or "psxview" in f.title.lower() for f in findings)
    has_kerberoasting = any("kerberoasting" in f.title.lower() for f in findings)
    has_wmi = any("wmi" in f.title.lower() for f in findings)
    has_cmd_evidence = any("command line" in f.title.lower() or "cmdscan" in f.title.lower() for f in findings)

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
        # injection/malfind found -> DLL list for each suspicious process
        if ext_or_inj and ("mem_dlllist", mem) not in ran_pairs:
            gaps.append({"tool": "mem_dlllist", "evidence": mem, "agent": "memory_analyst",
                         "reason": "enumerate loaded DLLs to identify injection vehicles"})
        # pstree not yet run
        if ext_or_inj and ("mem_pstree", mem) not in ran_pairs:
            gaps.append({"tool": "mem_pstree", "evidence": mem, "agent": "memory_analyst",
                         "reason": "build process tree to surface suspicious parent-child chains"})
        # Advanced: psxview for hidden process cross-view (if psscan found hidden procs)
        if has_hidden_proc and ("mem_psxview", mem) not in ran_pairs:
            gaps.append({"tool": "mem_psxview", "evidence": mem, "agent": "memory_analyst",
                         "reason": "hidden process detected — 6-source cross-view to confirm DKOM hiding"})
        # Advanced: handles for C2 named pipe / cross-process injection evidence
        if ext_or_inj and ("mem_handles", mem) not in ran_pairs:
            gaps.append({"tool": "mem_handles", "evidence": mem, "agent": "memory_analyst",
                         "reason": "injection indicators — enumerate handles for C2 named pipes"})
        # Advanced: cmdscan for attacker command history
        if ("mem_cmdscan", mem) not in ran_pairs:
            gaps.append({"tool": "mem_cmdscan", "evidence": mem, "agent": "memory_analyst",
                         "reason": "recover typed command history from COMMAND_HISTORY structures"})
        # Advanced: mutantscan for malware family fingerprinting
        if ext_or_inj and ("mem_mutantscan", mem) not in ran_pairs:
            gaps.append({"tool": "mem_mutantscan", "evidence": mem, "agent": "memory_analyst",
                         "reason": "malware indicators — fingerprint via named mutex strings"})
        # Advanced: mftscan if disk artifacts show deleted files
        if ("mem_mftscan", mem) not in ran_pairs and has_hidden_proc:
            gaps.append({"tool": "mem_mftscan", "evidence": mem, "agent": "memory_analyst",
                         "reason": "hidden process found — scan memory MFT for deleted malware files"})

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
    from glassbox.timeline import build_timeline, narrative_summary
    from glassbox.approve import ApprovalGate
    integrity = ctx.integrity.verify()
    chain_valid, chain_errs = ctx.audit.verify_self()
    all_reviewed = state.get("findings", [])
    # Split active findings vs. adversarially-refuted (context) at report time.
    findings = [f for f in all_reviewed if f.adversarial_verdict != "REFUTED"]
    refuted = [f for f in all_reviewed if f.adversarial_verdict == "REFUTED"]
    discrepancies = state.get("discrepancies", [])
    # Persistent learning: save lessons from quarantined findings for future runs
    quarantined = state.get("quarantined", [])
    new_lessons = ctx.lessons.append_from_quarantined(
        quarantined, run_id=ctx.config.case_id
    )
    if new_lessons > 0:
        ctx.audit.append("lessons_learned", new_lessons=new_lessons,
                         lessons_summary=ctx.lessons.summary())
    attack = state.get("attack", [])
    a2a = state.get("a2a", [])
    total = TokenUsage()
    timeline = build_timeline(findings, discrepancies)
    narrative = narrative_summary(timeline, case_id=state.get("case_id", ctx.config.case_id))

    # Apply approval gate: classify findings and compute investigation depth
    gate = ApprovalGate(state.get("case_id", ctx.config.case_id), audit=ctx.audit)
    for f in findings:
        gate.classify_finding(f)
    approval_summary = gate.apply_to_report(findings)
    depth = ApprovalGate.investigation_depth(
        findings,
        initial_alert_terms=["malware", "suspicious", "cridex", "alert", "infection"],
    )
    ctx.audit.append("approval_gate", **approval_summary)
    ctx.audit.append("investigation_depth", **depth)
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
        lessons_summary=ctx.lessons.summary(),
        refuted=refuted,
        adversarial=state.get("adversarial", {}),
        investigation_depth=depth,
    )
    ctx.audit.append("report", n_findings=len(findings),
                     n_quarantined=len(state.get("quarantined", [])),
                     n_refuted=len(state.get("refuted", [])),
                     red_team_verified=len(rep.red_team_verified()),
                     spoliation_detected=ctx.integrity.spoliation_detected(),
                     audit_chain_valid=chain_valid, chain_errors=chain_errs[:3])
    msg = A2AMessage(seq=seq(), from_agent="orchestrator", to_agent="analyst", role="status",
                     summary=f"Triage complete in {rep.iterations_used} iteration(s). {rep.summary}")
    return {"report": rep, "done": True, "a2a": [msg]}
