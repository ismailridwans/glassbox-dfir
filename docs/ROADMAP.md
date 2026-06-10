# GLASSBOX — Improvement Roadmap

This document turns GLASSBOX's current weaknesses into a prioritized, measurable
engineering plan across four pillars: **UI/UX**, **backend performance &
scalability**, **security hardening**, and **DFIR coverage**.

Every item distinguishes what is **ALREADY IMPLEMENTED** (grounded in named
modules/functions) from what is **RECOMMENDED**. Each recommendation carries a
problem statement, a proposed solution, a technical-feasibility note, an effort
estimate (S ≤ 1 day, M ≈ 2–4 days, L ≈ 1–2 weeks), and a measurable benefit/KPI.

> Scope honesty: this roadmap is written against the code as it exists in
> `src/glassbox`. Where the prompt's framing implies a capability that is not yet
> built (e.g. a light theme), it is called out explicitly as RECOMMENDED, not
> claimed as done.

---

## 0. Current State — what is already built (baseline)

These are real, verifiable capabilities the roadmap builds on. They are NOT
proposals.

| Capability | Where it lives | What it does |
|---|---|---|
| Deterministic LangGraph pipeline | `orchestrator/graph.py` `build_graph()` | `intake → plan → collect → correlate → map_attack → verify → adversarial_verify → critique → (loop\|report)`; in-state `max_iterations` + LangGraph `recursion_limit` dual loop guards; `GraphRecursionError` caught → partial report |
| Five specialist analysts | `orchestrator/specialists.py` `SPECIALISTS` | `run_memory`, `run_evtx`, `run_disk`, `run_network`, `run_registry` — each emits structured `Finding`s with `Provenance.raw_locator` |
| Hallucination gate | `verify/hallucination.py` `verify_findings()` / `_check_finding()` | Re-reads `RawStore` and confirms every `raw_locator` + `cited_values` string is physically present; can only downgrade to `HALLUCINATED`; NABAOS epistemic typing (`PRATYAKSA`/`ANUMANA`/`UNGROUNDED`) |
| Adversarial verification panel | `adversarial/panel.py` `AdversarialPanel.review()` + `adversarial/skeptic.py` | 4 deterministic skeptics (`BenignExplanation`, `FalsePositivePattern`, `Corroboration`, `Attribution`) vote `UPHOLD/REFUTE/UNCERTAIN`; weighted tally → `UPHELD/DEMOTED/REFUTED`; idempotent via `base_severity` restore |
| Court-admissible bundle | `forensic/bundle.py` `build_bundle()` / `verify_bundle()` | Packages report + audit + methodology; per-component SHA-256 + binding `bundle_hash`; optional HMAC seal via `GLASSBOX_APPROVAL_KEY` |
| Deterministic replay | `forensic/replay.py` `replay_verify()` | Re-walks the hash chain and re-derives every finding from `RawStore` alone — no SIFT re-run needed |
| Architectural guardrail self-test | `guardrail/selftest.py` `run_guardrail_selftest()` | Actively exercises 6 boundaries: `NO_WRITE_TOOL`, `PATH_TRAVERSAL`, `EVIDENCE_RO`, `AUDIT_TAMPER`, `HALLUCINATION`, `HMAC_APPROVAL` |
| Web console (SPA + SSE) | `web/server.py` `serve()`, `web/session.py` `TriageSession`, `web/static/js/app.js` | Zero-dependency `ThreadingHTTPServer`; SSE live trace; 10 self-registering views; REST endpoints for report/navigator/diamond/speed/audit/guardrail/replay |
| ATT&CK Navigator + Diamond export | `attack/navigator.py` `to_navigator_layer()` / `to_diamond_model()` | Navigator v4.5 layer scored by max severity; Diamond Model reconstruction |
| Speed report | `perf/speed.py` `speed_report()` | Per-tool timings + wall-clock contrasted against cited adversary breakout benchmarks |
| Offline-first LLM | `orchestrator/llm.py` `HeuristicLLM` (default), `AnthropicLLM` | Safety-critical logic is deterministic code; LLM only narrates; Anthropic backend uses prompt caching |
| Read-only SIEM clients | `siem/client.py` | Env-var creds, read-only `query()`, graceful `UNAVAILABLE` |

---

## Phase: NOW (highest leverage, low-to-medium risk)

### N1 — Cache verification verdicts across self-correction iterations
**Pillar:** backend performance
**Status:** RECOMMENDED (current behavior is re-verify-everything)

- **Problem.** `verify_findings()` (`verify/hallucination.py`) re-runs the full
  string-presence gate over *every* finding on *every* iteration, and
  `AdversarialPanel.review()` (`adversarial/panel.py`) resets each finding to
  `base_severity` and re-challenges all four skeptics on every iteration. A
  finding discovered in iteration 1 is re-checked unchanged in iterations 2 and
  3. With `max_iterations=3` (default in `EVIDENCE_PLAN` runs), the gate and panel
  do ~3× the necessary work on stable findings. `_check_finding()` also calls
  `rawstore.contains()` once per locator *and* once per `cited_value` — repeated
  substring scans of captured output.
- **Proposed solution.** Key each verdict by `finding_id` plus a hash of
  `(provenance, cited_values)`. On re-entry, skip re-verification when the key is
  unchanged (findings are content-addressed via `stable_id`, so an unchanged
  finding has an unchanged id). Only newly merged findings from `_merge_findings()`
  (which already stamps `iteration_found`) need a fresh pass.
- **Feasibility.** High. The merge layer already tracks new vs. existing
  findings; pass that delta into `verify_findings`/`review` instead of the full
  set. Verdicts are deterministic, so caching is safe.
- **Effort.** M.
- **KPI.** Cut re-verification CPU ~2–3× on multi-iteration cases (proportional to
  `iterations_used`); verification wall-time on the demo case drops from ~O(N×iters)
  to ~O(N). Track via `perf/speed.py` `slowest_tools` + a new `verify_ms` field.

### N2 — Index captured output instead of linear substring scans
**Pillar:** backend performance
**Status:** RECOMMENDED

- **Problem.** Grounding is built on `RawStore.contains(exec_id, locator)`, a
  substring search over the captured tool output. The corroboration skeptic
  (`AdversarialContext.entity_index`) and `finding_entities()` already build an
  entity index for findings, but the raw-output side is scanned linearly each
  call. On large EVTX/JSON captures this is the dominant verification cost.
- **Proposed solution.** Build a per-`exec_id` token/line index (or a simple
  `set` of normalized lines) once when output is stored, and answer
  `contains()` against it. Locators are short strings (IPs, PIDs, filenames,
  rule names), so a hashed-substring or suffix-trimmed line index suffices.
- **Feasibility.** High. `RawStore` is the single chokepoint; the change is
  internal and does not alter the security guarantee (still string-presence).
- **Effort.** M.
- **KPI.** Reduce `contains()` from O(len(output)) to ~O(1) amortized; target a
  measurable drop in `avg_tool_ms`-adjacent verification time on captures > 1 MB.

### N3 — Make the web console handle concurrent cases (lift the single global session)
**Pillar:** backend scalability
**Status:** RECOMMENDED (today it is strictly single-case)

- **Problem.** `web/server.py` holds one module-global `_SESSION` and a single
  `_RUN_LOCK`; `do_POST("/api/triage")` returns `409 already running` when busy,
  and every REST endpoint reads the one `_SESSION`. The console can analyze
  exactly **one** case at a time. There is no notion of K simultaneous
  investigations.
- **Proposed solution.** Replace the global with a `dict[case_id, TriageSession]`
  registry keyed by case id, a per-session lock, and route REST/SSE by a
  `case_id` path/query param. `TriageSession` is already self-contained (owns its
  own `CaseContext`, temp dir, report cache), so it is close to multi-instance
  ready.
- **Feasibility.** Medium. The session object is already encapsulated; the work
  is in routing and lifecycle (eviction, `cleanup()` on idle).
- **Effort.** M.
- **KPI.** Support **K ≥ 8 concurrent cases** on one workstation (bounded by a
  configurable worker pool), measured by K parallel `/api/triage/stream` runs
  completing without 409s.

### N4 — Bind the web console to loopback + token, and document the trust boundary
**Pillar:** security hardening
**Status:** PARTIAL (loopback default exists; no auth)

- **Problem.** `serve()` defaults to `host="127.0.0.1"` (good), but the handler
  has **no authentication** and runs plain HTTP. If an operator passes a routable
  `--host` (the CLI exposes `serve`), the dashboard — which can trigger triage
  and read audit records/reports — is exposed unauthenticated on the network. The
  SSE `_RUN_LOCK` is the only access control, and it is a concurrency lock, not a
  security control.
- **Proposed solution.** (a) Require a one-time bearer token (printed at startup,
  like Jupyter) checked in `Handler` before any `/api/*` route; (b) refuse to bind
  a non-loopback host unless `--host` is paired with `--token` and TLS; (c) add a
  `Strict-Transport-Security`-equivalent warning and a startup banner stating the
  trust boundary.
- **Feasibility.** High. Single check at the top of `do_GET`/`do_POST`; the
  static file handler already blocks path traversal via `target.relative_to(_STATIC)`.
- **Effort.** S.
- **KPI.** Eliminate the unauthenticated-network-exposure class entirely
  (0 routes reachable without a token); verified by an added guardrail check
  `WEB_AUTH` in `guardrail/selftest.py`.

### N5 — Surface the hallucination/red-team distinction more prominently in the report header
**Pillar:** UI/UX
**Status:** PARTIAL (data exists; terminal dashboard shows it; web summary should lead with it)

- **Problem.** The terminal dashboard (`dashboard/live.py` `_render_summary`)
  already prints `RED-TEAM VERIFIED`, `Refuted → context`, and
  `Quarantined (hallu)`. The web SPA exposes the same data via `/api/report` and
  the forensic/guardrail views, but the *dashboard* view does not lead with the
  trust-tier breakdown that is GLASSBOX's headline differentiator.
- **Proposed solution.** Add a top-of-dashboard "trust ladder" stat row
  (`ui.stat` in `app.js`) reading `red_team_verified()` / `refuted` /
  `quarantined` counts straight from the report dict — the same numbers the
  terminal already renders.
- **Feasibility.** High. The data and `ui.stat`/`ui.donut` helpers already exist
  in `app.js`; this is a view-layer change in `views/dashboard.js`.
- **Effort.** S.
- **KPI.** Trust-tier breakdown visible above the fold in ≤ 1 screen, 0 extra
  clicks (today it requires navigating to the forensic/findings views).

---

## Phase: NEXT (meaningful capability, moderate effort)

### X1 — Parallelize independent specialists in `collect`
**Pillar:** backend performance
**Status:** RECOMMENDED (today specialists run sequentially)

- **Problem.** `nodes.collect()` iterates `groups.items()` in a plain `for` loop,
  running each specialist (`run_memory`, `run_disk`, `run_evtx`, …) one after
  another. Memory, disk, EVTX, and network analysis are independent — they read
  different evidence and share no state until `correlate`. Total `collect` time is
  the *sum* of per-specialist time, not the max.
- **Proposed solution.** Run specialists in a `ThreadPoolExecutor` (tools are
  largely I/O- and subprocess-bound, so the GIL is not the bottleneck), then merge
  results deterministically via the existing `_merge_findings()` (id-keyed, so
  order-independent). Keep the audit `append` calls thread-safe (the hash chain is
  append-only and must be serialized — guard with a lock or collect-then-append).
- **Feasibility.** Medium. Merge is already order-independent; the one
  serialization point is the audit chain.
- **Effort.** M.
- **KPI.** Cut `collect` wall-clock toward `max(specialist_time)` instead of
  `sum(...)` — on a 4-evidence-type case, target ~2–3× faster collection;
  measured by `speed_report` total wall-clock before/after.

### X2 — Persist sessions and reports to a case store (durability + reload)
**Pillar:** backend scalability
**Status:** RECOMMENDED (today reports live in-memory + on disk per run)

- **Problem.** `TriageSession` caches `self.report` in process memory and writes
  artifacts to `reports_dir`; the web `_SESSION` is lost on restart. There is no
  index of historical cases to reopen in the console — `replay_verify()` can
  re-derive a case, but the UI has no case picker.
- **Proposed solution.** Add a lightweight case index (SQLite or a manifest
  JSONL) recording `case_id`, paths to `report.json`/`audit.jsonl`/`raw`, and the
  `bundle_hash`. Add a `/api/cases` endpoint and a console case-picker view that
  loads a prior report and offers one-click `replay_verify`.
- **Feasibility.** Medium. All artifacts already exist on disk with stable names
  (`*.report.json`, `*.audit.jsonl`); this is an index + a view.
- **Effort.** M.
- **KPI.** Reopen any historical case in < 2 s without re-running tools; support
  an unbounded case archive browsable from the console.

### X3 — Streaming / chunked analysis for large memory & disk images
**Pillar:** backend performance + DFIR coverage
**Status:** RECOMMENDED

- **Problem.** Specialists consume whole-tool-output summaries; very large images
  (multi-GB memory dumps, full disk images) can produce large captured outputs
  that the `RawStore` holds and the gate scans. There is no chunking or
  size-based budgeting.
- **Proposed solution.** Add output-size budgeting in `mcp_server/runner.py`:
  cap captured output with a documented truncation marker, and store an index
  (ties into N2). For disk, prefer targeted `disk_list_files`/timeline windows
  over full enumeration when an offset is known (the disk analyst already sorts
  `disk_partition_table` first to obtain the NTFS offset).
- **Feasibility.** Medium. Truncation must be recorded in provenance so the gate
  never flags a value that was truncated away (failure-mode honesty).
- **Effort.** L.
- **KPI.** Bound peak RawStore memory per case to a configurable ceiling (e.g.
  256 MB) regardless of image size; no `MemoryError` on multi-GB inputs.

### X4 — Expand the skeptic panel with corroboration-from-raw and timeline skeptics
**Pillar:** DFIR coverage + IR accuracy
**Status:** RECOMMENDED (extends an implemented design)

- **Problem.** `DEFAULT_SKEPTICS` is four perspectives. The `CorroborationSkeptic`
  reasons over the cross-finding `entity_index` but does **not** consult the
  `RawStore` directly (the `AdversarialContext` accepts `rawstore`/`known_exec_ids`
  but the default skeptics do not use them). There is no temporal-consistency
  skeptic, even though `correlate/temporal.py` produces temporal discrepancies.
- **Proposed solution.** Add (a) a `RawCorroborationSkeptic` that upgrades
  confidence when the same entity appears in *independent* captured outputs (using
  the passed `rawstore`), and (b) a `TemporalConsistencySkeptic` that refutes
  findings whose claimed sequence contradicts `observed_at` ordering.
- **Feasibility.** High. The plumbing (`rawstore`, `known_exec_ids`) is already
  passed into `AdversarialPanel.review()`; only new `Skeptic` subclasses are
  needed.
- **Effort.** M.
- **KPI.** Increase red-team precision: target a measurable reduction in `DEMOTED`
  findings that a human would have upheld (track against the benchmark in
  `ACCURACY_REPORT.md`, current FP rate 0.143).

### X5 — Wire SIEM enrichment into specialists with explicit provenance
**Pillar:** DFIR coverage
**Status:** PARTIAL (read-only clients exist; not consumed by specialists)

- **Problem.** `siem/client.py` provides read-only `query()` clients with
  graceful `UNAVAILABLE` degradation, but no specialist consumes them. Live
  SIEM corroboration (e.g. confirming a netscan C2 IP against Wazuh/Splunk alerts)
  is not yet part of the finding pipeline.
- **Proposed solution.** Add an optional enrichment pass in `run_network`/
  `run_memory` that calls the SIEM client for each external IOC and attaches a
  `Provenance` whose `raw_locator` is the SIEM hit id. Crucially, route SIEM
  output through the *same* `RawStore` + gate so SIEM-sourced claims are grounded,
  not trusted blindly.
- **Feasibility.** Medium. The `LiveQueryResult.to_tool_result_summary()` shape
  already mirrors a tool result; the gate is content-agnostic.
- **Effort.** M.
- **KPI.** Add a measurable corroboration tier (`N` IOCs SIEM-confirmed) to the
  report; raise multi-source corroboration coverage on live cases.

---

## Phase: LATER (strategic, higher effort / external dependencies)

### L1 — Dual-theme analyst console (light + dark)
**Pillar:** UI/UX
**Status:** RECOMMENDED — **NOT IMPLEMENTED TODAY**

- **Problem.** The console is **dark-theme only**. `web/static/css/app.css`
  defines a single `:root` palette (`--bg: #0a0e16`, etc.) and the view
  `CONTRACT.md` instructs contributors to "Match the dark theme." There is no
  `data-theme` switch, no `prefers-color-scheme` handling, and no persisted theme
  preference. Daytime SOC analysts and printed/exported reports benefit from a
  light theme; courtroom/exhibit screenshots often require high-contrast light.
- **Proposed solution.** Promote the palette to `[data-theme="dark"]` /
  `[data-theme="light"]` variable sets, add a topbar toggle in `app.js` that sets
  `document.documentElement.dataset.theme` and persists to `localStorage`, and
  default from `prefers-color-scheme`. All views already read colors via CSS
  variables (`ui.sevColor` reads `--crit/--high/...`), so they inherit the theme
  for free.
- **Feasibility.** High. The CSS-variable architecture is already in place; this
  is a palette duplication + a 10-line toggle. The honest gap is that *today the
  feature does not exist at all*.
- **Effort.** M.
- **KPI.** Two fully styled themes with persisted preference; 0 hard-coded colors
  remaining in views (audited by grepping `#` hex literals out of `views/*.js`).
  This becomes a genuine competitive differentiator only once shipped.

### L2 — Multi-user / RBAC and signed audit export
**Pillar:** security hardening
**Status:** RECOMMENDED

- **Problem.** There is no user model. The HMAC approval gate
  (`forensic/bundle.py` `_hmac_key()` from `GLASSBOX_APPROVAL_KEY`,
  `approve/` `ApprovalGate`) seals a bundle and validates tokens, but there is no
  notion of *who* approved a finding — only that *someone with the key* did.
- **Proposed solution.** Add per-examiner identities and roles (analyst vs.
  approver), record the approver identity in the `requires_human_review` /
  `approval_status` workflow already present in `verify_findings`, and sign audit
  exports per-examiner. Keep all evidence access read-only.
- **Feasibility.** Medium–High; depends on N4 (auth) landing first.
- **Effort.** L.
- **KPI.** Every CRITICAL/`PENDING_REVIEW` finding carries an attributable
  approver identity; tamper of the approver field is caught by the existing
  `AUDIT_TAMPER` chain check.

### L3 — Pluggable detection content (Sigma/YARA hot-reload + rule versioning)
**Pillar:** DFIR coverage
**Status:** PARTIAL (YARA + Sigma/Hayabusa consumed; rules are not externally managed)

- **Problem.** Detection logic is partly code-embedded: `run_evtx` recognizes
  specific event ids (4769 Kerberoasting, 5861/5859/5857 WMI, 4624 LogonType=9)
  and `run_memory`'s `yara_scan` maps rule names to artifacts via a hard-coded
  `_TECH_MAP`. Adding coverage means editing `specialists.py`.
- **Proposed solution.** Externalize the event-id→technique and YARA-rule→artifact
  maps into versioned content files, with a content hash recorded in the audit log
  so a report states exactly which detection content version produced it
  (reproducibility + Daubert "known error rate" alignment per
  `forensic/bundle.py` methodology).
- **Feasibility.** Medium. The maps are small dicts today; the work is the
  loader + content-version provenance.
- **Effort.** L.
- **KPI.** Add detections without code changes; every report cites a detection
  content version hash (100% of runs).

### L4 — Distributed / queued triage for fleet-scale intake
**Pillar:** backend scalability
**Status:** RECOMMENDED

- **Problem.** Even with N3 (concurrent sessions) and X1 (parallel specialists),
  a single workstation is the unit of scale. Incident response at fleet scale
  needs many cases queued and dispatched to workers.
- **Proposed solution.** Introduce a work queue (case in → worker runs
  `run_triage` → artifacts + bundle out) with the case store from X2 as the
  system of record. The graph is already a pure function of `(CaseContext, llm)`,
  so a worker is just `build_graph(...).invoke(...)`.
- **Feasibility.** Medium, contingent on X2.
- **Effort.** L.
- **KPI.** Sustained throughput of **C cases/hour** across W workers with linear
  scaling up to the I/O ceiling; queue depth and per-case latency observable.

---

## Competitive Edge — pain points GLASSBOX can own

These contrast GLASSBOX against the **Protocol SIFT baseline** and typical
LLM-DFIR assistants. The first two are **already implemented**; the third is
**RECOMMENDED** and is included honestly as a gap to close, not a current claim.

| Differentiator | Status | Why competitors / SIFT haven't solved it | GLASSBOX mechanism | Measurable edge |
|---|---|---|---|---|
| **Adversarially-verified findings** | IMPLEMENTED | Protocol SIFT (per its own README/Substack) warns the model "may overstate confidence… human verification of raw tool output is required" and ships **no hallucination gate** — any stated finding becomes a finding. | Two independent layers: deterministic string-presence gate (`verify/hallucination.py`) + a 4-skeptic red-team panel (`adversarial/panel.py`) that emits `UPHELD/DEMOTED/REFUTED`. Both are code, not prompts; the verifier can only downgrade. | Eliminates the "overstated/fabricated" failure class (GTG-1002). On the demo benchmark: hallucination rate 0.083 with the fabricated "2.3 GB exfil" claim quarantined (`ACCURACY_REPORT.md`). Findings carry a trust tier no SIFT output has. |
| **Court-admissible deterministic replay** | IMPLEMENTED | LLM assistants produce prose; they cannot prove a third party re-derives identical conclusions from the artifacts alone. | `forensic/replay.py` `replay_verify()` re-walks the hash chain and re-grounds every finding from `RawStore` **without re-running any SIFT tool**; `forensic/bundle.py` seals a bundle with per-component SHA-256 + binding hash + optional HMAC, plus an FRE 901 / Daubert methodology statement. | Reproducibility is binary and provable: `reproducible=true` iff chain intact and every locator re-found. Tamper of any component is detected by `verify_bundle()`; tamper of the log is caught by the `AUDIT_TAMPER` guardrail check. |
| **Dual-theme analyst console** | RECOMMENDED (not built) | Most CLI-first DFIR agents have no GUI at all; the few with dashboards are single-theme. | Proposed L1: promote the existing CSS-variable palette to `data-theme` light/dark with persisted preference. The architecture (variables + `ui.sevColor`) already supports it. | Once shipped: two themes, persisted, with court-/print-friendly light mode. **Today this is dark-only — it is a roadmap item, not a current capability.** |

**Additional edges already in the code that are worth marketing honestly:**

- **Architectural (not prompt) guardrails, self-tested.** `guardrail/selftest.py`
  actively *exercises* `NO_WRITE_TOOL`, `PATH_TRAVERSAL`, `EVIDENCE_RO`,
  `AUDIT_TAMPER`, `HALLUCINATION`, and `HMAC_APPROVAL` rather than asserting them
  in docs. Directly answers the hackathon's criterion #4 ("architectural or
  prompt-based? … tested for bypass").
- **Runs fully offline, deterministically.** `orchestrator/llm.py` `HeuristicLLM`
  is the default; all planning/verification/looping is code. Reproducible, 0
  tokens, no network — judges (and courts) get the same result every run.
- **Machine-speed framing.** `perf/speed.py` quantifies wall-clock against cited
  adversary breakout benchmarks (7-minute fastest observed breakout) — a concrete,
  defensible "triage at machine speed" claim.

---

## Prioritized backlog (at a glance)

| ID | Item | Pillar | Phase | Effort | Headline KPI |
|----|------|--------|-------|--------|--------------|
| N1 | Cache verification verdicts | Perf | Now | M | ~2–3× less re-verify CPU |
| N2 | Index captured output | Perf | Now | M | `contains()` O(len) → ~O(1) |
| N3 | Concurrent cases in console | Scale | Now | M | K ≥ 8 concurrent cases |
| N4 | Web auth + loopback hardening | Security | Now | S | 0 unauthenticated routes |
| N5 | Trust-ladder in dashboard header | UI/UX | Now | S | Trust tiers above the fold |
| X1 | Parallelize specialists | Perf | Next | M | `collect` sum → max time |
| X2 | Persistent case store + picker | Scale | Next | M | Reopen any case < 2 s |
| X3 | Chunked large-image analysis | Perf/DFIR | Next | L | Bounded RawStore memory |
| X4 | More skeptics (raw + temporal) | DFIR/Acc | Next | M | Lower wrong-DEMOTE rate |
| X5 | SIEM enrichment into pipeline | DFIR | Next | M | +N IOCs SIEM-confirmed |
| L1 | Dual-theme console | UI/UX | Later | M | 2 themes, persisted |
| L2 | RBAC + signed audit export | Security | Later | L | Attributable approvals |
| L3 | Pluggable detection content | DFIR | Later | L | No-code detection adds |
| L4 | Distributed/queued triage | Scale | Later | L | C cases/hr across W workers |
