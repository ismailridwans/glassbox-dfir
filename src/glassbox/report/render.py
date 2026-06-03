"""Report renderer — Markdown + JSON artefacts, all citable.

Every finding in the Markdown report carries a ``[TExxxx]`` citation that the
judge can trace to the corresponding ``tool_exec_id`` in the JSONL execution
log.  The quarantine section is always present (even if empty) so the false-
positive / hallucination count is visible, not hidden.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from glassbox.attack import coverage_by_tactic
from glassbox.models import A2AMessage, Confidence, Severity, TriageReport, utcnow_iso

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}
_CONF_LABEL = {
    Confidence.CONFIRMED:    "**CONFIRMED**",
    Confidence.INFERRED:     "*INFERRED*",
    Confidence.UNVERIFIED:   "UNVERIFIED",
    Confidence.HALLUCINATED: "~~HALLUCINATED~~",
}


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").strip()


def _citation(prov) -> str:
    if not prov:
        return ""
    ids = [p.tool_exec_id for p in prov if p.tool_exec_id]
    return " ".join(f"`[{i}]`" for i in sorted(set(ids)))


def render_markdown(rep: TriageReport, a2a: list[Any] | None = None) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# GLASSBOX Triage Report — `{rep.case_id}`")
    a(f"")
    a(f"Generated: {rep.generated_at}  ")
    a(f"GLASSBOX version: {rep.glassbox_version}  ")
    a(f"Evidence types: {', '.join(e.value for e in rep.evidence_types)}  ")
    a(f"Iterations: {rep.iterations_used}/{rep.max_iterations}  ")
    a(f"Audit chain valid: {'✅' if rep.audit_chain_valid else '❌ CHAIN BROKEN'}  ")
    a(f"Spoliation detected: {'❌ YES' if any(not r.unchanged for r in rep.integrity) else '✅ No'}  ")
    a(f"Total tokens: {rep.total_tokens.total}  ")
    a(f"")
    a(f"> **{rep.summary}**")
    a(f"")

    # --- integrity table
    if rep.integrity:
        a("## Evidence Integrity")
        a("")
        a("| File | SHA-256 (before) | SHA-256 (after) | Unchanged |")
        a("|------|-----------------|-----------------|-----------|")
        for r in rep.integrity:
            name = Path(r.path).name
            a(f"| `{name}` | `{r.sha256_before[:16]}…` | "
              f"`{(r.sha256_after or 'N/A')[:16]}…` | {'✅' if r.unchanged else '❌'} |")
        a("")

    # --- incident narrative (timeline-driven)
    if rep.narrative:
        a(rep.narrative)
        a("")

    # --- timeline table
    if rep.timeline:
        a(f"## Unified Incident Timeline ({len(rep.timeline)} events)")
        a("")
        a("| Timestamp | Source | Category | Title | Sev | Conf | Tool Exec |")
        a("|-----------|--------|----------|-------|-----|------|-----------|")
        for ev in rep.timeline[:30]:
            ts = ev.get("ts", "unknown")[:19]
            a(f"| `{ts}` | {ev.get('source','')} | {ev.get('category','')} "
              f"| {_md_escape(ev.get('title','')[:55])} | {ev.get('severity','')} "
              f"| {ev.get('confidence','')[:3]} | `{ev.get('tool_exec_id','')}` |")
        if len(rep.timeline) > 30:
            a(f"\n*({len(rep.timeline) - 30} additional events in JSON report)*")
        a("")

    # --- findings
    confirmed = rep.confirmed()
    inferred  = rep.inferred()
    a(f"## Findings ({len(rep.findings)} reportable)")
    a("")

    for f in sorted(rep.findings, key=lambda x: list(Severity).index(x.severity)):
        icon = _SEV_ICON.get(f.severity, "")
        conf = _CONF_LABEL.get(f.confidence, f.confidence.value)
        cite = _citation(f.provenance)
        a(f"### {icon} {_md_escape(f.title)}")
        a(f"")
        a(f"- **Severity:** {f.severity.value}  **Confidence:** {conf}  {cite}")
        if f.evidence_type:
            a(f"- **Evidence type:** {f.evidence_type.value}")
        if f.observed_at:
            a(f"- **Observed at:** {f.observed_at}")
        if f.description:
            a(f"- {_md_escape(f.description)}")
        if f.attack:
            techs = ", ".join(f"`{m.technique_id}` {m.technique_name}" for m in f.attack)
            a(f"- **ATT&CK:** {techs}")
        if f.iocs:
            ioc_str = ", ".join(f"`{i.defanged or i.value}`" for i in f.iocs[:5])
            a(f"- **IOCs:** {ioc_str}")
        if f.verifier_note:
            a(f"- *Verifier:* {f.verifier_note}")
        a("")

    # --- discrepancies
    if rep.discrepancies:
        a(f"## Cross-Source Discrepancies ({len(rep.discrepancies)})")
        a("")
        for d in rep.discrepancies:
            a(f"### 🔍 [{d.kind}] {_md_escape(d.discrepancy_id)}")
            a(f"")
            a(f"- **Sources:** {', '.join(e.value for e in d.sources)}")
            a(f"- **Severity:** {d.severity.value}  **Confidence:** {d.confidence.value}")
            a(f"- {_md_escape(d.description)}")
            a("")

    # --- ATT&CK coverage
    if rep.attack_coverage:
        a("## MITRE ATT&CK Coverage")
        a("")
        coverage = coverage_by_tactic(rep.attack_coverage)
        for row in coverage:
            techs = ", ".join(f"`{t}`" for t in row["technique_ids"])
            a(f"- **{row['tactic_name']}** (`{row['tactic_id']}`): {techs}")
        a("")

    # --- IOCs
    if rep.iocs:
        a(f"## Extracted IOCs ({len(rep.iocs)})")
        a("")
        a("| Type | Value (defanged) | Context |")
        a("|------|-----------------|---------|")
        for ioc in rep.iocs[:100]:
            a(f"| {ioc.type} | `{_md_escape(ioc.defanged or ioc.value)}` | {_md_escape(ioc.context[:60])} |")
        if len(rep.iocs) > 100:
            a(f"\n*({len(rep.iocs) - 100} additional IOCs in JSON report)*")
        a("")

    # --- quarantine (hallucination transparency)
    a(f"## Quarantined Claims ({len(rep.quarantined)} — HALLUCINATED / unsupported)")
    a("")
    a("> These findings were proposed but **quarantined by the hallucination gate** because")
    a("> the cited value was absent from all captured tool output. They are listed here for")
    a("> transparency (per the accuracy report requirement) and must not be treated as fact.")
    a("")
    if rep.quarantined:
        for f in rep.quarantined:
            a(f"- ~~{_md_escape(f.title)}~~  *(verifier: {f.verifier_note[:120]})*")
    else:
        a("*None — all proposed findings were grounded in tool output.*")
    a("")

    # --- degraded tools
    if rep.degraded_tools:
        a(f"## Degraded / Unavailable Tools")
        a("")
        a("> These tools were unavailable or errored; findings may be incomplete.")
        for t in rep.degraded_tools:
            a(f"- `{t}`")
        a("")

    # --- agent-to-agent log summary (deliverable #8)
    msgs = a2a or []
    if msgs:
        a(f"## Agent Execution Summary ({len(msgs)} messages)")
        a("")
        a("| # | From | To | Role | Summary |")
        a("|---|------|----|------|---------|")
        for m in msgs:
            if isinstance(m, dict):
                m = A2AMessage(**m)
            a(f"| {m.seq} | `{m.from_agent}` | `{m.to_agent}` | {m.role} | "
              f"{_md_escape(str(m.summary)[:80])} |")
        a("")

    a("---")
    a(f"*Report generated by GLASSBOX v{rep.glassbox_version}. "
      f"Audit log: `{rep.audit_log_ref}`. "
      f"Every finding cites a `[TExxxx]` tool execution ID traceable in the JSONL execution log.*")
    return "\n".join(lines)


def write_report(
    rep: TriageReport,
    reports_dir: str | Path,
    *,
    a2a: list[Any] | None = None,
) -> dict[str, Path]:
    out = Path(reports_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {}

    # Markdown
    md = out / f"{rep.case_id}.report.md"
    md.write_text(render_markdown(rep, a2a=a2a), encoding="utf-8")
    paths["markdown"] = md

    # JSON (full, machine-readable)
    jf = out / f"{rep.case_id}.report.json"
    jf.write_text(rep.model_dump_json(indent=2), encoding="utf-8")
    paths["json"] = jf

    # JSONL execution log (deliverable #8 — structured agent execution logs)
    el = out / f"{rep.case_id}.execution_log.jsonl"
    with el.open("w", encoding="utf-8") as fh:
        for m in (a2a or []):
            row = m if isinstance(m, dict) else m.model_dump()
            fh.write(json.dumps(row, default=str) + "\n")
    paths["execution_log"] = el

    return paths
