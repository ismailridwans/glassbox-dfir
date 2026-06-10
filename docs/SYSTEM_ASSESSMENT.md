# GLASSBOX — Current System Assessment

*Status: candid current-state assessment, grounded in the source tree as of this commit. Every capability claim below is traced to a concrete module or function. Recommendations are explicitly separated from implemented behavior.*

---

## 1. What GLASSBOX Is

GLASSBOX is an autonomous, self-correcting incident-response triage agent for the SANS SIFT Workstation. Its defining design decision is to make the dangerous capabilities (writing, shelling out, deleting, mounting) *structurally unavailable* rather than prompt-discouraged, and to make every reported finding mechanically traceable to the raw tool output that produced it.

The system runs in two modes from one codebase:

- **MCP server** over stdio for Claude Code / Claude Desktop (`glassbox mcp-serve` → `glassbox.mcp_server.server:main`).
- **Self-driving LangGraph orchestrator** that calls the same tool surface in-process (`glassbox triage` / `demo` / `serve` / `dashboard`).

Both transports share `CaseContext` (`src/glassbox/context.py`), which wires together the vault, audit chain, raw store, tool runner, toolkit, integrity guard, and lessons log. This is deliberate: the design comment states behavior "never diverges between transports."

### Chosen architecture

**Custom read-only MCP Server + LangGraph `StateGraph` orchestrator.**

The rationale (per `docs/ARCHITECTURE.md`) is that the MCP server provides the primary architectural trust boundary — the model cannot invoke a destructive capability that is not registered — while LangGraph provides bounded, logged, autonomous execution. The orchestration graph is assembled in `src/glassbox/orchestrator/graph.py:build_graph`:

```
START → intake → plan → collect → correlate → map_attack
      → verify → adversarial_verify → critique → {plan | report} → END
```

Note: the README and ARCHITECTURE diagrams show the loop as `... → verify → critique → report`. The **actual** graph (`graph.py`) inserts an `adversarial_verify` node between `verify` and `critique`. The docs are slightly stale here; the code is authoritative.

---

## 2. Module Inventory and Responsibilities

| Module | Responsibility | Key symbols |
|--------|----------------|-------------|
| `models.py` | Pydantic data contracts; the `Finding`→`Provenance`→`ToolExecution` invariant | `Finding`, `Provenance`, `ToolExecution`, `Confidence`, `EpistemicType`, `TriageReport`, `A2AMessage`, `Discrepancy` |
| `config.py` | Case layout + YAML/env config resolution | `GlassboxConfig.for_case`, `_apply_env` |
| `context.py` | Single wiring point for all per-case services | `CaseContext` |
| `mcp_server/toolkit.py` | The entire read-only tool surface | `ReadOnlyToolKit`, `list_tools()` |
| `mcp_server/server.py` | MCP `@mcp.tool()` wrappers over the toolkit | `main` |
| `mcp_server/runner.py` | Subprocess execution + RawStore capture + replay | `ToolRunner`, `ToolPaths` |
| `mcp_server/parsers.py`, `parsers_extra.py` | Server-side normalization of tool stdout to compact summaries | `normalize_*`, `parse_*` |
| `audit/chain.py` | Hash-chained, append-only JSONL audit log | `AuditChain.append`, `AuditChain.verify` |
| `audit/rawstore.py` | Content-addressed verbatim tool output | `RawStore.contains`, `get_raw` |
| `evidence/vault.py` | Path-traversal-safe evidence resolution + manifest + harden | `EvidenceVault.resolve`, `manifest`, `harden`, `classify` |
| `evidence/integrity.py` | Before/after SHA-256 + active write probe | `IntegrityGuard`, `write_probe` |
| `verify/hallucination.py` | The deterministic hallucination gate + NABAOS tagging | `verify_findings`, `verify_discrepancies` |
| `adversarial/panel.py`, `skeptic.py` | Red-team verification panel | `AdversarialPanel.review`, `DEFAULT_SKEPTICS` |
| `correlate/cross_source.py`, `temporal.py` | Disk-vs-memory + temporal discrepancy detection | `correlate_disk_memory`, `temporal_process_network_correlation` |
| `detect/` | LOLBAS, credential-access, lateral-movement heuristics | `detect_credential_access`, `detect_lateral_movement` |
| `attack/` | MITRE ATT&CK mapping + Navigator/Diamond export | `for_artifact`, `for_event_id`, `to_navigator_layer`, `to_diamond_model` |
| `orchestrator/graph.py`, `nodes.py`, `specialists.py`, `state.py`, `llm.py` | LangGraph build + node logic + specialist agents + LLM abstraction | `run_triage`, `route_after_critique`, `SPECIALISTS`, `get_llm` |
| `timeline/engine.py` | Cross-source event timeline + narrative | `build_timeline`, `narrative_summary` |
| `ioc/extract.py` | Grounded IOC extraction + defanging | `extract_iocs` |
| `approve/gate.py` | HMAC-sealed approval tokens + investigation-depth metric | `ApprovalGate`, `investigation_depth` |
| `learning/lessons.py` | Persistent learning loop from quarantined findings | `LessonsLog.apply_to_findings`, `append_from_quarantined` |
| `forensic/replay.py`, `bundle.py` | Deterministic replay + court-admissible bundle | `replay_verify`, `build_bundle` |
| `guardrail/selftest.py` | Active boundary-exercising self-test | `run_guardrail_selftest` |
| `perf/speed.py` | Machine-speed report vs. adversary breakout benchmarks | `speed_report` |
| `siem/client.py` | Optional live SIEM/EDR query with graceful offline degradation | `build_client` |
| `web/server.py`, `session.py` | Zero-dependency stdlib dashboard (HTTP + SSE) | `serve`, `TriageSession` |
| `dashboard/live.py` | Terminal node-by-node live trace | `run_dashboard` |
| `report/render.py` | Markdown + JSON report rendering | `write_report` |
| `benchmark/score.py` | Accuracy scoring vs. ground truth | `run_benchmark` |
| `cli.py` | Argparse entrypoint for all 12 subcommands | `main` |

---

## 3. Verified Capabilities

These are confirmed by reading the implementing code, not by documentation alone.

### 3.1 Read-only tool surface — 30 tools (not the "20" implied by the ARCHITECTURE diagram)

`ReadOnlyToolKit.list_tools()` (`toolkit.py:447`) returns exactly **30** tool names. The ARCHITECTURE.md diagram lists an older 20-tool surface; the toolkit has since grown (advanced Volatility plugins + SIEM + YARA + RegRipper). The current set:

| Category | Tools |
|----------|-------|
| Memory — standard (Volatility 3) | `mem_pslist`, `mem_pstree`, `mem_psscan`, `mem_netscan`, `mem_malfind`, `mem_cmdline`, `mem_svcscan`, `mem_dlllist` (8) |
| Memory — advanced malware | `mem_psxview`, `mem_handles`, `mem_cmdscan`, `mem_consoles`, `mem_mutantscan`, `mem_mftscan` (6) |
| Live SIEM/EDR | `live_endpoint_query` (1) |
| YARA | `yara_scan` (1) |
| Disk (Sleuth Kit) | `disk_partition_table`, `disk_list_files`, `disk_mft_timeline` (3) |
| Registry (RegRipper) | `registry_analyze` (1) |
| EVTX | `evtx_hunt`, `evtx_to_json`, `evtx_dump_xml` (3) |
| Network (tshark) | `pcap_conn_summary`, `pcap_dns`, `pcap_http` (3) |
| Meta | `evidence_manifest`, `hash_verify`, `ioc_extract`, `attack_map` (4) |

The critical property is *absence*: there is no `execute_shell`, `write_file`, `delete`, `Bash`, `mount`, or `dd` method on the class. `run_guardrail_selftest` check `NO_WRITE_TOOL` (`selftest.py:53`) actively asserts the intersection of the registered set with a forbidden set is empty.

### 3.2 Five evidence types

`EvidenceType` enum (`models.py:84`) defines `DISK`, `MEMORY`, `EVTX`, `PCAP`, `REGISTRY` (plus `UNKNOWN`). The orchestrator's `EVIDENCE_PLAN` (`nodes.py:47`) maps each of the five to a specialist agent and a baseline tool sequence, so all five are wired end-to-end, not merely declared.

### 3.3 Hash-chained audit (tamper-evident chain of custody)

`AuditChain` (`audit/chain.py`) computes `record_hash = SHA-256(prev_hash || canonical_json({seq, ts, event}))` per record, starting from a 64-zero genesis. `AuditChain.verify` re-walks the file and flags seq gaps, `prev_hash` breaks, and recomputed-hash mismatches. The architectural point: **the model has no tool that writes to this log** — only the trusted runner/orchestrator appends. Self-test `AUDIT_TAMPER` mutates a record and confirms detection.

### 3.4 Hallucination gate

`verify_findings` (`verify/hallucination.py`) is deterministic code, not a prompt. For each finding it (1) rejects findings with no provenance, (2) rejects unknown `tool_exec_id`s, (3) requires every `raw_locator` to be physically present in the captured output via `RawStore.contains`, and (4) requires every extra `cited_values` entry to be grounded in some cited output. The verifier **can only downgrade**: the comment states "The model cannot talk its way to CONFIRMED." Findings failing any check become `HALLUCINATED` and are quarantined into `TriageReport.quarantined` — kept for transparency, never reported as fact (`is_reportable()` only admits `CONFIRMED`/`INFERRED`).

### 3.5 Adversarial verification panel

`AdversarialPanel.review` (`adversarial/panel.py`) runs each grounded finding past a skeptic panel (`DEFAULT_SKEPTICS`), tallies weighted UPHOLD/REFUTE votes, honors a `veto` for authoritative refutations, and assigns `UPHELD` / `DEMOTED` / `REFUTED`. UPHELD findings are tagged "RED-TEAM VERIFIED" and get a confidence bump; REFUTED findings are split out at report time into `TriageReport.refuted` (context, not active). Idempotency across self-correction iterations is handled via `base_severity` so demotions never compound — a real subtlety the code addresses explicitly (`panel.py:74`, `_apply`).

### 3.6 NABAOS epistemic tagging

`verify_findings` assigns `Finding.epistemic_type` (`EpistemicType` enum, `models.py:56`) from the verdict: `PRATYAKSA` (direct observation, CONFIRMED), `ANUMANA` (inference, INFERRED), `UNGROUNDED` (HALLUCINATED). It also sets a numeric `confidence_score` (e.g. CONFIRMED scales `0.75 + 0.083·min(locators,3)`; INFERRED fixed `0.65`). Note: the enum also defines `ABHAVA` (absence-as-evidence) and `SABDA` (external authority), but `verify_findings` currently only ever assigns `PRATYAKSA` / `ANUMANA` / `UNGROUNDED` — `ABHAVA` and `SABDA` are **declared but not yet assigned anywhere** in the verification path.

### 3.7 Forensic replay (reproducibility)

`replay_verify` (`forensic/replay.py`) re-derives findings from the audit log + RawStore + report JSON *without re-running any SIFT tool*: it re-walks the hash chain, collects logged `tool_execution` ids, and confirms each finding's locator still appears in stored output. `reproducible` requires chain validity AND zero failed findings AND a non-empty finding set. Exposed via `glassbox replay-verify`.

### 3.8 Court-admissible bundle + approval gate

`build_bundle` (`forensic/bundle.py`) packages report + audit + manifest + a methodology statement (mapped to FRE 901 / Daubert), records a binding manifest hash, and optionally HMAC-seals. `ApprovalGate` (`approve/gate.py`) issues HMAC-signed approval tokens; self-test `HMAC_APPROVAL` confirms a tampered token is rejected.

### 3.9 Web dashboard

`web/server.py` is a `ThreadingHTTPServer` serving a static SPA + REST + Server-Sent-Events live stream, built on the Python standard library only (no Node, no build step). It has its own path-traversal guard on static file serving (`_file`, `server.py:54`).

### 3.10 Other implemented capabilities worth noting

- **Bounded self-correction** with two independent guards: in-state `iteration >= max_iterations` in `route_after_critique` (`nodes.py:434`) and LangGraph `recursion_limit=50` caught as `GraphRecursionError` → graceful partial report (`graph.py:96`).
- **Cross-source + temporal correlation** producing `Discrepancy` records that are mirrored into INFERRED findings and pushed through the same gate (`nodes.py:correlate`).
- **Graceful degradation**: `evtx_dump_xml` fallback when `evtx_to_json` is `DEGRADED`; `live_endpoint_query` returns `UNAVAILABLE` offline; no crash path from a missing binary.
- **Persistent learning loop** (`learning/lessons.py`): quarantined findings become lessons that pre-downgrade matching patterns on future runs.

### 3.11 Test coverage — 135 tests

Counting `def test_` across `tests/` yields **135** test functions in 15 files. Heaviest coverage: `test_sprint5.py` (22), `test_web.py` (14), `test_adversarial.py` (11), `test_detection.py` (11), `test_ioc.py` (9). Core safety modules have dedicated suites: `test_audit_chain.py` (5), `test_hallucination.py` (6), `test_vault.py` (8), `test_forensic.py` (8), `test_end_to_end.py` (8). All tests are designed to run offline (README: "no SIFT binaries required").

---

## 4. Honest Strengths / Weaknesses / Risks

| Dimension | Assessment | Evidence |
|-----------|------------|----------|
| **Strength** — capability containment | The "no write tool exists" design is genuinely architectural, not aspirational; it's enforced by class shape and asserted by an active self-test. | `toolkit.py` (no write methods), `selftest.py:NO_WRITE_TOOL` |
| **Strength** — anti-hallucination | The gate is deterministic, downgrade-only, and runs server-side against verbatim captured output. This directly answers the GTG-1002 "overstated/fabricated" finding cited in the module docstring. | `verify/hallucination.py` |
| **Strength** — auditability | Hash-chained log + content-addressed raw store + deterministic replay form a coherent chain-of-custody story that survives independent re-verification. | `chain.py`, `rawstore.py`, `replay.py` |
| **Strength** — offline determinism | Replay fixtures + heuristic LLM backend make the whole pipeline reproducible in CI with no binaries; this is why 135 tests can run offline. | `config.py` (`llm_backend="heuristic"`), `runner.py` replay |
| **Weakness** — detection is heuristic/keyword-driven | The critique node's gap-finding keys on substrings in finding titles ("External network connection", "Injected", "kerberoasting", "wmi") in `nodes.py:critique`. This is brittle to title-wording changes and to evidence the heuristics don't anticipate. | `nodes.py:347-396` |
| **Weakness** — partial NABAOS implementation | `ABHAVA` and `SABDA` epistemic types are defined but never assigned. Absence-as-evidence (a tool running and returning zero rows) is not currently captured as a first-class epistemic state. | `models.py:69`, `hallucination.py:155-168` |
| **Weakness** — doc/code drift | ARCHITECTURE.md lists 20 tools and omits the `adversarial_verify` node; README example output predates current counts. A reader trusting the docs over the code will be wrong on tool count and graph shape. | `ARCHITECTURE.md` vs `toolkit.py`/`graph.py` |
| **Weakness** — locator matching is substring containment | The gate's grounding test is `RawStore.contains(exec_id, locator)` — plain substring presence. A locator that is a common short token (e.g. a single digit or a frequent word) could pass spuriously. Strength of grounding depends on locator *specificity*, which is producer-chosen. | `hallucination.py:92` |
| **Risk** — evidence read-only relies partly on OS layer | Vault `harden()` strips write bits and `write_probe` actively tests, but true write-blocking on a live case still depends on OS mount flags / hardware blockers (ARCHITECTURE Boundary 2, Layer 1). The architectural guarantee covers the *agent's* inability to write; it does not by itself prevent an out-of-band process from touching evidence. | `evidence/vault.py:harden`, `integrity.py:write_probe` |
| **Risk** — real-binary path largely unexercised in tests | Tests run in replay/heuristic mode. Parser robustness against real Volatility/Hayabusa/tshark output variations across versions is not covered by the offline suite; field/format drift in those tools is an untested failure surface. | `runner.py` replay; absence of live-binary fixtures |
| **Risk** — `live_endpoint_query` widens posture | The SIEM/EDR client introduces an outbound network dependency. It degrades gracefully when offline, but on a live case it is the one tool reaching beyond local evidence; its read-only-ness depends on the backend client implementations in `siem/client.py`, not on the MCP surface. | `toolkit.py:422`, `siem/client.py` |

---

## 5. Top User Pain Points It Solves

| Pain point (from hackathon framing) | How GLASSBOX addresses it | Implemented? |
|-------------------------------------|---------------------------|--------------|
| **Hallucination** ("Protocol SIFT works. It also hallucinates more than we'd like."; GTG-1002 fabrication) | Deterministic, downgrade-only gate re-checks every cited value against verbatim captured output; ungrounded claims quarantined. Adversarial panel additionally refutes grounded-but-wrong findings (e.g. benign public DNS). | Yes (`verify/hallucination.py`, `adversarial/panel.py`) |
| **Spoliation** (evidence modification) | No write/shell/delete tool exists in the surface; before/after SHA-256 via `IntegrityGuard`; active `write_probe` and `harden()`. | Yes (`toolkit.py`, `evidence/integrity.py`) |
| **Traceability / admissibility** | Every finding carries `Provenance` → `ToolExecution` → verbatim RawStore span; hash-chained audit; deterministic replay; FRE-901/Daubert methodology bundle. | Yes (`models.py`, `chain.py`, `replay.py`, `bundle.py`) |
| **Machine speed** (8-minute adversary breakout) | Full autonomous triage with bounded self-correction; `speed_report` quantifies wall-clock vs. adversary breakout benchmarks; `TriageReport.duration_ms` recorded. | Yes (`perf/speed.py`, `graph.py` timing) |

---

## 6. Gaps Still Open

These are honest gaps in the *current* implementation (distinct from the recommendations in §7):

1. **`ABHAVA` / `SABDA` epistemic states are unused.** Absence-as-evidence and external-authority provenance are modeled but never produced.
2. **Critique heuristics are title-substring-based** and therefore coupled to specialist wording rather than structured signals.
3. **No grounding-specificity guard.** The gate accepts any substring match regardless of how discriminating the locator is.
4. **Live-tool/parser robustness is untested** against real binary output across tool versions.
5. **Documentation lags code** (tool count, graph topology, sample output).

---

## 7. Recommendations

Each recommendation states the reasoning and a measurable benefit. These are *not yet implemented*.

### R1 — Add a locator-specificity check to the hallucination gate
**Reasoning:** `RawStore.contains` accepts any substring (`hallucination.py:92`); a short or common locator can match spuriously, undermining the "grounded" guarantee that the whole architecture leans on.
**Proposal:** Reject (or downgrade to a new `WEAK` epistemic state) locators below a minimum length / above a maximum corpus frequency, measured against the cited output.
**Measurable benefit:** Track "spurious-match rate" on a fixture set of deliberately weak locators; target reducing false-CONFIRMED on that set to 0 while leaving the legitimate confirmed count in `test_hallucination.py` unchanged.

### R2 — Implement `ABHAVA` (absence) tagging
**Reasoning:** A tool that runs and returns zero rows is real evidence (e.g. "no persistence services found"), but the verifier cannot currently classify it; such conclusions either get no epistemic tag or are forced into the wrong one.
**Proposal:** When a finding cites a `ToolExecution` whose `parsed_summary["count"] == 0` and asserts absence, assign `EpistemicType.ABHAVA` in `verify_findings`.
**Measurable benefit:** Count of absence-based findings correctly tagged (currently 0); plus a dedicated test in `test_hallucination.py` raising suite coverage of the `EpistemicType` enum from 3/5 to 4/5 values exercised.

### R3 — Replace title-substring critique heuristics with structured signals
**Reasoning:** Gap detection in `nodes.py:critique` matches strings like `"kerberoasting"`/`"wmi"` in finding titles; renaming a finding silently disables follow-up tool selection — a maintenance hazard with no compile-time or test-time signal.
**Proposal:** Have specialists emit structured tags (e.g. `finding.attack` technique ids or an explicit `signals: set[str]`) and key critique on those instead of `title`/`description` text.
**Measurable benefit:** Mutation test — rename every finding title in a fixture run and assert the same gap set is produced; today that test would fail, after the change it should pass.

### R4 — Add a live-output parser regression corpus
**Reasoning:** The 135-test suite runs entirely in replay/heuristic mode; real Volatility 3 / Hayabusa / tshark output format drift is an untested failure surface that would surface only on a live SIFT case.
**Proposal:** Capture sanitized real-binary outputs (across at least two tool versions) into `tests/fixtures/` and add parser-only regression tests for `mcp_server/parsers.py` / `parsers_extra.py`.
**Measurable benefit:** Parser test count and number of distinct tool-version outputs covered (currently effectively 0 real-binary samples); target ≥1 sample per parser.

### R5 — Reconcile ARCHITECTURE.md and README with the code
**Reasoning:** Docs state 20 tools and a `verify → critique` graph; the code has 30 tools and a `verify → adversarial_verify → critique` graph. Reviewers (and judges) reading the docs will mis-state the system.
**Proposal:** Regenerate the tool list in ARCHITECTURE.md from `ReadOnlyToolKit.list_tools()` and add the `adversarial_verify` node to the diagram; optionally add a CI check that diffs the documented tool list against `list_tools()`.
**Measurable benefit:** Zero discrepancies between `list_tools()` and the documented surface, enforceable as a passing CI assertion.
