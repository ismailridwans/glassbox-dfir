# GLASSBOX dashboard — view contract (read before building a view)

Every view is **one self-registering JS file**, vanilla ES (no build step, no
imports, no external libraries). It registers itself on load:

```js
(function () {
  const ICON = "<svg viewBox='0 0 24 24'>…</svg>";   // 24x24, stroke=currentColor
  GLASSBOX.registerView("findings", {
    title: "Findings",
    sub:   "grounded + red-team verified",   // shown under the page title
    order: 30,                               // sidebar position
    icon:  ICON,
    badge: (ctx) => (ctx.report.findings || []).length,   // optional sidebar count
    render(root, ctx) { /* build DOM into root */ },
  });
})();
```

## render(root, ctx)
- `root` — an empty `<div>`; append your DOM to it. May be `async`.
- `ctx.state`  — `/api/state` result `{case_id, version, demo, has_report, running, evidence:[{path,sha256,bytes,type}], tools:[...], max_iterations}`
- `ctx.report` — `/api/report` result (the TriageReport, see shape below). May be `{}` if no run yet — **always guard** with `if (!ctx.report.findings) { root.appendChild(ui.empty("Run triage first")); return; }`
- `ctx.api`    — async client: `state() report() a2a() navigator() diamond() speed() audit() guardrail() replay()`; plus `streamTriage(onEvent,onDone,onError)`
- `ctx.ui`     — helper toolkit (below). **Use these — do not hand-roll HTML strings.**
- `ctx.go(id)` — navigate to another view. `ctx.refresh()` — reload data + re-render.

## ctx.ui helpers
- `el(tag, attrs, children)` — DOM builder. attrs: `{class, text, html, style:{}, onclick, ...}`. children: node | string | array.
- `frag(...nodes)`, `esc(s)`
- `card(title, bodyNode, {sub, action, class, bodyClass})` → `.card`
- `stat(label, value, {tone:'accent'|'good'|'warn'|'bad', foot})` → stat tile
- `badge(text, kind)` kind ∈ `crit high med low info good warn bad ghost mono`
- `sevBadge(severity)` — severity → colored badge. `pill(text)` — mono chip (good for technique IDs).
- `table(columns, rows, rowAttr?)` — columns: `[{label,key,render?(row),mono?,html?}]`; returns `.tbl-wrap`.
- `empty(msg, iconHtml?)` — empty state.
- `donut(segments, {center,round,size,width})`, `legend(segments)`, `bars(items)` — segments/items: `[{label,value,color?}]`. Inline SVG charts.
- `sevKey(s)` → 'crit'|'high'|'med'|'low'|'info'; `sevColor(s)` → hex; `SEV` = severity order array; `fmtNum(n)`.

## CSS classes you can use (see app.css)
`grid cols-2|cols-3|cols-4|cols-auto`, `card card-head card-body`, `badge` (+kinds),
`pill`, `sev-rail crit|high|med|low|info` (severity left border), `tbl`, `toolbar`,
`input`, `btn btn-primary btn-ghost btn-sm`, `muted faint mono row wrap spacer hr`,
`finding f-title f-meta f-desc f-prov`, `trace trace-row`, `attack-grid tactic-col tactic-head tech-cell`,
`chain chain-rec`, `pbar`, `loader`, `empty`, `pill`.

## TriageReport shape (ctx.report)
```
case_id, generated_at, glassbox_version, summary, duration_ms,
evidence_types: ["disk","evtx","memory","pcap","registry"],
iterations_used, max_iterations, audit_chain_valid (bool), audit_log_ref,
findings: [ Finding ],            // active findings (UPHELD + DEMOTED)
refuted:  [ Finding ],            // adversarially REFUTED (false positives → context)
quarantined: [ Finding ],         // hallucinated/unsupported
discrepancies: [ {discrepancy_id, kind, description, severity, confidence, sources:[], provenance:[]} ],
iocs: [ {type, value, defanged, context, provenance:[]} ],
attack_coverage: [ {technique_id, technique_name, tactic_ids:[], tactic_names:[], confidence} ],
integrity: [ {path, sha256_before, sha256_after, unchanged(bool), bytes} ],
degraded_tools: [str], total_tokens:{input_tokens,output_tokens},
timeline: [ {ts, source, category, title, severity, confidence, tool_exec_id, technique_ids:[], detail} ],
narrative: "markdown-ish string",
adversarial: {total, upheld, demoted, refuted},
investigation_depth: {total, novel, parroted, investigation_depth_score},
lessons_summary: {...}
```
### Finding shape
```
finding_id, title, description, evidence_type, host, observed_at,
severity ("CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"),
confidence ("CONFIRMED"|"INFERRED"|"HALLUCINATED"),
epistemic_type ("PRATYAKSA"|"ANUMANA"|...|null),
confidence_score (0..1), adversarial_verdict ("UPHELD"|"DEMOTED"|"REFUTED"|null),
requires_human_review (bool), approval_status,
attack: [ {technique_id, technique_name, tactic_names:[]} ],
iocs: [ IOC ], cited_values:[str], verifier_note,
provenance: [ {tool_exec_id, tool, raw_locator, note} ],
skeptic_votes: [ {perspective, vote, reason} ],
source_agent
```

## Endpoint-specific shapes
- `api.navigator()` → MITRE Navigator layer `{name, domain, techniques:[{techniqueID, score, color, comment, metadata}], ...}`
- `api.diamond()`   → `{adversary, capability:{attack_techniques:[],malware_artifacts:[]}, infrastructure:{c2_and_network_iocs:[]}, victim:{hosts:[]}}`
- `api.audit()`     → `{valid(bool), errors:[], count, records:[{seq, ts, event:{type, ...}, prev_hash, record_hash}]}`
- `api.speed()`     → `{total_wall_clock_s, tool_executions, self_correction_iterations, slowest_tools:[{tool,count,total_ms}], vs_adversary_breakout:{<label>:{adversary_ms,glassbox_ms,glassbox_faster_x}}, headline}`
- `api.guardrail()` → `{all_passed(bool), passed, total, checks:[{name, passed, detail}]}`
- `api.replay()`    → `{reproducible(bool), audit_chain_valid, findings_checked, findings_reproduced, failed}`
- `api.a2a()`       → `{messages:[{seq, ts, from_agent, to_agent, role, summary, refs:[], token_usage}]}`

## Live triage (triage.js only)
`triage.js` must expose a global `GLASSBOX.startTriage()` that opens
`ctx.api.streamTriage(onEvent, onDone, onError)` and renders the live node trace
into its view. Events: `{type:'start', case_id, evidence, tools}`,
`{type:'node', node, label, detail, data, elapsed_ms}`,
`{type:'done', duration_ms, report}`, `{type:'error', error}`.
Also call `GLASSBOX.setStatus('running'|'done'|'error', text)` to update the topbar chip.
After `done`, call `ctx.refresh()` so other views pick up the new report.

## Rules
- Vanilla JS only. No fetch of external CDNs. No frameworks.
- Always guard empty/missing data. Never throw.
- Match the dark theme; reuse ui helpers and CSS classes. Keep it elegant and dense but readable.
- The exemplar is `views/dashboard.js` — match its structure and quality.
