# GLASSBOX — Backend Architecture, Performance & Scalability

> Scope: backend control plane (orchestration, tool execution, verification, audit, web transport). Grounded in the code as it exists today. Sections clearly distinguish **Implemented** behavior from **Recommended** changes. Every recommendation carries reasoning and a measurable benefit.

---

## 1. Architecture overview

GLASSBOX is a single-process, read-only DFIR triage agent. The control flow is a LangGraph `StateGraph` of deterministic Python nodes; the LLM only narrates (see the module docstring in `orchestrator/nodes.py`). Evidence is touched exclusively through a typed read-only tool surface, every tool execution is content-addressed and hash-chained, and findings pass a mechanical hallucination gate before they can be reported.

### 1.1 Component map

| Layer | Module / file | Responsibility |
|---|---|---|
| Orchestration | `orchestrator/graph.py` (`build_graph`, `run_triage`) | Assembles the `StateGraph`, compiles with `InMemorySaver()`, invokes/streams it, handles `GraphRecursionError` |
| Graph nodes | `orchestrator/nodes.py` (`intake`, `plan`, `collect`, `correlate`, `map_attack`, `verify`, `adversarial_verify`, `critique`, `route_after_critique`, `report`) | Deterministic step logic; loop bound enforced in `route_after_critique` |
| Tool surface | `mcp_server/toolkit.py` (`ReadOnlyToolKit`) | Typed read-only methods (`mem_pslist`, `disk_list_files`, `pcap_http`, …); 30 tools enumerated in `list_tools()` |
| Tool runner | `mcp_server/runner.py` (`ToolRunner.run`, `ToolPaths`) | The *only* place `subprocess.run(..., shell=False)` is called; capture, status, provenance, audit |
| Raw capture | `audit/rawstore.py` (`RawStore`) | On-disk + in-memory store of verbatim tool stdout, keyed by `tool_exec_id` |
| Audit | `audit/chain.py` (`AuditChain`) | Append-only, SHA-256 hash-chained JSONL log; `verify()` re-walks it |
| Verification | `verify/hallucination.py` (`verify_findings`, `verify_discrepancies`, `_check_finding`) | Re-opens raw output, confirms cited locators physically present; can only downgrade |
| Integrity | `evidence/integrity.py` (`IntegrityGuard`), `evidence/vault.py` (`EvidenceVault`) | Before/after SHA-256 custody; path-traversal-safe vault |
| Web transport | `web/server.py` (`Handler`, `serve`), `web/session.py` (`TriageSession`) | `ThreadingHTTPServer`, REST + SSE, drives one triage session |
| Context wiring | `context.py` (`CaseContext`) | Wires vault, audit, rawstore, runner, toolkit, integrity, lessons for one case |

### 1.2 Graph topology (from `build_graph`)

```
START → intake → plan → collect → correlate → map_attack → verify
        → adversarial_verify → critique
                                  │
        ┌────── route_after_critique ──────┐
        │ (gaps & iteration < max)         │ else
        ▼                                   ▼
       plan  (self-correction loop)        report → END
```

Two independent loop guards exist, both visible in code:
- The in-state `max_iterations` counter checked in `route_after_critique` (the intended control).
- LangGraph's `recursion_limit` (a hard safety net). `run_triage` catches `GraphRecursionError` and still emits a report from the last checkpoint via `graph.get_state(config).values` + `nodes.report(...)` — graceful degradation, never a crash.

---

## 2. Performance bottlenecks

Each subsection states what the code does today, the impact, a concrete remediation, and the measurable benefit. The bottlenecks compound because the self-correction loop re-executes several of them per iteration.

### 2.1 LangGraph `InMemorySaver` msgpack round-trip per super-step

**Implemented.** `build_graph` compiles with `g.compile(checkpointer=InMemorySaver())`. The graph state (`GraphState`) carries Pydantic models — `Finding`, `Discrepancy`, `A2AMessage`, `IOC`, ATT&CK mappings — accumulated across nodes. LangGraph's `InMemorySaver` serializes the full channel state through msgpack at every super-step. The team has already acknowledged the symptom: `graph.py` lines 25-31 raise the log level of `langgraph`, `langgraph.checkpoint`, `langgraph.checkpoint.serde`, and `ormsgpack` to `ERROR` specifically to silence the *"Deserializing unregistered type"* warning emitted for the un-registered Pydantic types "on every super-step."

**Impact.** The warning is suppressed but the underlying work is not: every super-step (there are ~9 nodes × N iterations) does a serialize/deserialize round-trip of the entire accumulated state, including the growing `findings` list and the entire `a2a` message log (which only ever grows — see `report` summing `m.token_usage` over all of `state["a2a"]`). For a single short run this is negligible; cost is **O(super-steps × |state|)** and the `|state|` term grows with iterations because findings and A2A messages accumulate. The fact that warnings had to be suppressed rather than fixed is a code smell: the checkpointer is doing serialization work that this single-process, in-memory deployment never consumes (state is read back from the same `graph.invoke`/`graph.stream` return value, not from a restored checkpoint — except the one `get_state` call in the recursion-limit fallback).

**Remediation.** Two options, ranked:
1. For the dominant single-run path, the checkpointer provides no value: nothing resumes from a checkpoint except the `GraphRecursionError` fallback. Replace the fallback's reliance on `get_state` with the last `delta` already observed in the stream loop, and **drop the checkpointer** (`g.compile()` with no checkpointer) for one-shot CLI/`run_triage` runs. This removes the per-super-step serde entirely.
2. If checkpointing must stay (e.g. for the web stream and future resume), register serializers so the round-trip is cheap and warning-free — pass an explicit serde to `InMemorySaver(serde=...)` that knows how to (de)serialize the Pydantic models via `model_dump()`/`model_validate()`, instead of falling back to the generic msgpack path that warns on every unregistered type.

**Measurable benefit.** Eliminates one full serialize + deserialize of the accumulated state per super-step. With ~9 nodes/iteration and up to `max_iterations` (default 3) iterations, that is ~27 round-trips of a monotonically growing object graph removed (option 1) or made cheap and warning-free (option 2). Measure with `time.perf_counter()` deltas already captured in `run_triage` (`duration_ms`) before/after; expect the largest relative win on cases with many findings, where serde cost scales with `|state|`.

### 2.2 Verifier re-verifies ALL accumulated findings every iteration

**Implemented.** `nodes.verify` calls `verify_findings(list(state["findings"]), ctx.rawstore, known, audit=ctx.audit)` over **all** accumulated findings — not just the ones produced in the current iteration. `_merge_findings` only ever grows the set (keyed by `finding_id`), so iteration *k* re-verifies everything from iterations 1..*k*. Inside `verify_findings` → `_check_finding`, each finding's provenance and `cited_values` are checked with `rawstore.contains(tool_exec_id, locator)`, which calls `RawStore.get_raw` and does a substring scan of the raw output. Worse, `adversarial_verify` runs the `AdversarialPanel` over **all** findings every iteration too (its docstring explicitly says it "Runs every iteration so corroboration discovered in a later loop can *upgrade* a previously-uncertain finding"), and that panel also takes `rawstore=ctx.rawstore`.

**Impact.** Cost is **O(iterations × findings × locators)** of `RawStore.contains` calls, each a full-text `in` scan of the cited raw blob. `RawStore.get_raw` caches the blob in `_raw_cache` after the first read, so the *disk* read is amortized — but the substring scan, the audit append per finding (`verify_findings` appends a `verification` event for every finding every time), and the adversarial re-review are not amortized. The audit chain in particular re-logs every finding's verdict on every iteration, inflating the WORM log and adding a `threading.Lock` + file append + SHA-256 per finding per iteration (`AuditChain.append`). For a case that accumulates F findings over I iterations, the audit log grows by ~F+F+...= O(F×I) `verification` records even though most findings did not change.

**Remediation.** Incremental verification of only-new findings:
- Track verification verdicts on the `Finding` (the fields already exist: `confidence`, `verifier_note`, `epistemic_type`, `confidence_score`, `approval_status`). In `verify`, partition `state["findings"]` into already-verified vs new (e.g. by a `verified_at_iteration` marker set when first verified, analogous to the existing `iteration_found` set in `_merge_findings`). Run `verify_findings` only over the new/changed subset; carry prior verdicts forward.
- Keep the *adversarial* panel's intentional re-review semantics (a later iteration can upgrade an earlier finding), but scope its re-scan to findings whose backing evidence set changed this iteration, not the whole list. The corroboration signal comes from *new* executions, so only findings touching the new `tool_exec_id`s need re-review.
- Emit a single batched audit record per iteration (counts + the deltas) instead of one record per finding per iteration.

**Measurable benefit.** Turns the per-iteration verifier cost from O(all findings) into O(new findings), making total work over the loop O(F) instead of O(F×I). On the default 3-iteration loop this is roughly a 3× reduction in `rawstore.contains` scans, audit appends, and adversarial reviews for findings discovered in iteration 1. Directly observable as fewer `verification` records in the audit log (`AuditChain.count()`) and lower `verify`/`adversarial_verify` node time in the SSE `elapsed_ms` stream emitted by `web/session.py`.

### 2.3 Web server: synchronous triage under a single global lock, no backpressure

**Implemented.** `web/server.py` uses one module-global `_RUN_LOCK = threading.Lock()` and one module-global `_SESSION`. Both `POST /api/triage` (`_run_locked`) and `GET /api/triage/stream` (`_triage_stream`) take that lock; a second concurrent attempt gets HTTP 409 `"already running"` / an SSE `"triage already running"` error. The run itself is blocking: `_run_locked` calls `_SESSION.run_blocking()`, and `TriageSession.stream_run` drives `graph.stream(...)` to completion synchronously on the request/worker thread. The server is `ThreadingHTTPServer`, which spawns a thread per connection but has **no bounded queue and no backpressure** — connections are accepted and threaded without limit.

**Impact.** The backend is effectively single-tenant: exactly one triage at a time, system-wide, because of the global lock and the single global `_SESSION`. There is no run-ID model — `/api/report`, `/api/a2a`, `/api/navigator`, etc. all read the one `_SESSION`'s cached state, so a second user (or a second case) cannot run or even be tracked. Under load `ThreadingHTTPServer` keeps accepting connections and spawning threads with no admission control; the only protection is the 409. A long-running live case (the runner default `timeout` per tool is 600s) blocks the single slot for minutes. The web layer cannot scale past one concurrent run regardless of host capacity.

**Remediation.** A job queue + async triage with run IDs:
- Replace the single global `_SESSION`/`_RUN_LOCK` with a `Runs` registry keyed by a generated `run_id`. `POST /api/triage` enqueues a job and returns `{run_id, 202}` immediately; `GET /api/triage/{run_id}/stream` attaches to that run's event stream; `GET /api/report?run_id=...` reads that run's result. This removes the system-wide single-run constraint and makes results addressable.
- Put a bounded worker pool (`concurrent.futures.ThreadPoolExecutor(max_workers=N)`) behind the queue so admission is explicit and backpressure is a 429/queue-depth signal rather than unbounded thread spawning. Cap `ThreadingHTTPServer` (or move to a small ASGI/WSGI server) so connection acceptance is bounded.
- Per-run isolation already half-exists: `TriageSession` builds a fresh `CaseContext` per run via `_reset_context`; lift that into per-`run_id` sessions.

**Measurable benefit.** Concurrency rises from a hard cap of **1** to **N** (the worker-pool size) simultaneous triages, bounded by host CPU/IO rather than a global lock. Request latency for status endpoints stops being coupled to whether a run is in progress. Queue depth and worker saturation become measurable signals for capacity planning; today the only signal is a binary 409.

### 2.4 Subprocess fan-out is sequential per specialist

**Implemented.** `nodes.collect` groups the plan steps into `groups[(agent, evidence)]` and then iterates `for (agent, evidence), tools in groups.items():` strictly sequentially, calling `run_memory(...)` or `SPECIALISTS[agent](...)`. Each specialist ultimately calls `ToolRunner.run`, which executes a blocking `subprocess.run(list(...), capture_output=True, timeout=self.timeout, shell=False)` (runner.py). So all tool executions in an iteration run one after another on a single thread. There is no parallelism across independent specialists (memory vs disk vs network vs evtx vs registry) even though they target *different evidence files and different binaries* and share no mutable state except append-only sinks.

**Impact.** Wall-clock for an iteration is the **sum** of every tool's runtime, not the max. With a per-tool `timeout` default of 600s and real DFIR tools (Volatility `windows.netscan`, `tshark` over a large PCAP, `fls -r` over a multi-GB image) each taking tens of seconds to minutes, sequential execution is the dominant cost of a live (non-replay) run. The five specialist domains are embarrassingly parallel: they read disjoint evidence and write to independent in-memory views (`mem_view`, `disk_view`, `evtx_view`) merged afterward.

**Remediation.** Parallel subprocess fan-out via `concurrent.futures`:
- Submit each `(agent, evidence)` group to a `ThreadPoolExecutor` (threads are sufficient because the work is in `subprocess.run`, which releases the GIL while the child runs). Collect futures, then merge results deterministically in a fixed order so `_merge_findings` and the view-merge stay reproducible.
- The shared sinks need attention: `ToolRunner._next_id` increments `self._counter` (not thread-safe), `RawStore.put` writes per-key files (safe across distinct keys, but the in-memory caches mutate), and `AuditChain.append` is already guarded by `self._lock`. Make `_next_id` atomic (lock or `itertools.count`) and append executions to `ReadOnlyToolKit.executions` under a lock; raw files are content-addressed by distinct `tool_exec_id` so there is no path collision.
- Bound the pool (e.g. number of evidence items, or a small fixed N) to avoid oversubscribing CPU/disk on the SIFT workstation.

**Measurable benefit.** Iteration wall-clock drops from **Σ(tool times)** toward **max(tool times)** across the parallel groups. For a typical 4–5-source case where each domain takes comparable time, that is up to a ~4–5× reduction in collection time per iteration. Measurable directly: `ToolExecution.duration_ms` is recorded per tool (runner.py), and `web/session.py` already feeds these to `glassbox.perf.speed_report` — compare summed vs. observed wall-clock before/after.

### 2.5 Full-file SHA-256 hashing of evidence at intake — and it happens twice

**Implemented.** At intake, `nodes.intake` does two things that each hash every evidence file in full:
1. `ctx.toolkit.evidence_manifest()` → `EvidenceVault.manifest()` → `sha256_file(p)` for every file.
2. `ctx.integrity.snapshot()` → `IntegrityGuard.snapshot()` → `self.vault.manifest()` **again** → another full `sha256_file(p)` pass over the same files.

`sha256_file` (util.py) is chunked (1 MiB blocks) so it does not blow RAM, but it still reads **every byte** of every evidence file — twice — before any analysis starts. Later, `IntegrityGuard.verify()` (called in `nodes.report`) hashes every file a **third** time for the after-snapshot. There is partial memoization in the toolkit (`ReadOnlyToolKit._sha` caches into `self._hashes`, and `evidence_manifest` pre-populates `_hashes`), but `EvidenceVault.manifest()` itself does not consult that cache — it re-hashes unconditionally — so the two intake passes are genuinely redundant reads.

**Impact.** For multi-GB disk/memory images, intake is I/O-bound on reading the entire corpus twice before the first tool runs, and a third full pass at report time. On a 20 GB disk image that is ~40 GB of reads at intake alone. This is pure latency the analyst waits through before any finding appears. The redundancy (two intake passes) is wasted work with no added integrity value — the manifest hash and the baseline hash are computed from the same bytes at the same instant.

**Remediation.**
- **Hash once, share the baseline.** Compute the SHA-256 baseline a single time and have intake reuse it. Concretely: have `IntegrityGuard.snapshot()` accept (or read) the manifest the toolkit already produced, or have `EvidenceVault.manifest()` consult/populate a single authoritative hash cache (the toolkit's `_hashes` is already that cache — wire `manifest()` to it). The after-verification pass is the only one that legitimately needs a fresh recompute (to prove unchanged); the two *before* passes should collapse to one.
- **Stream/sample for very large images where appropriate.** Where a full cryptographic hash of the *entire* image is not the integrity contract (e.g. when the evidence is mounted read-only / behind a hardware write blocker per `evidence/vault.py` layer 1), a sampled or rolling hash plus the OS read-only guarantee can stand in for the before-snapshot, reserving full SHA-256 for the after-check only. (This is a policy choice; keep full hashing where chain-of-custody requires it.)

**Measurable benefit.** Eliminates one of two full reads of the evidence corpus at intake — a 2× reduction in intake hashing I/O (e.g. ~20 GB instead of ~40 GB read on a 20 GB image), shrinking time-to-first-finding by the duration of one full-corpus read. The `integrity_baseline` audit event timing and the gap between `case_open` and the first `tool_execution` record give a direct before/after measurement.

### 2.6 Raw tool output stored on disk per execution (no content dedupe)

**Implemented.** `ToolRunner.run` always calls `self.rawstore.put(exec_id, raw, parsed)`, and `RawStore.put` writes `{key}.raw.txt` and `{key}.parsed.json` to disk **and** caches both in memory, keyed by `tool_exec_id`. The key is the execution ID (`TE0001-mem_pslist`, …), **not** a content hash — so two executions that emit byte-identical output (e.g. the same plugin re-run across iterations, or replay fixtures) are stored as two separate files. The docstring calls this "content-addressed," but the addressing is by `tool_exec_id`, not by content.

**Impact.** Disk grows linearly with executions, with no deduplication of identical output. In the self-correction loop, re-running a tool against the same evidence (guarded against in `plan`/`critique` via `ran_pairs`, but not impossible across distinct logical tools that wrap the same plugin output) writes redundant blobs. For large outputs (a 40 MB `fls` dump, full `netscan` JSON) this is real disk pressure, and every blob is also held in `_raw_cache` in memory for the process lifetime, so memory grows with total raw output across the whole run — the cache is never evicted.

**Remediation.** Content-addressed dedupe + bounded cache:
- Address raw blobs by `sha256(raw)` and keep a thin `tool_exec_id → content_hash` index. Identical outputs then share one on-disk blob (and one cache entry). `ToolExecution.stdout_sha256` is already computed in `runner.py` (`sha256_bytes(raw...)`) — reuse it as the storage key instead of recomputing addressing by `exec_id`.
- Bound `_raw_cache` (LRU with a byte budget) so peak memory is capped rather than O(total raw output); `get_raw` already falls back to disk, so eviction is safe and the verifier still works.
- Optionally back the store with an object store (see §5) so it is not tied to local disk.

**Measurable benefit.** De-duplicates identical raw blobs to a single copy on disk and in cache; in replay/demo mode where fixtures repeat, and in loops that re-touch the same output, this directly cuts both disk footprint and resident memory. Caps process memory growth from "all raw output ever produced" to a fixed budget — important on a workstation where a single case can emit hundreds of MB of tool output.

---

## 3. Bottleneck summary

| # | Bottleneck (Implemented) | Complexity today | Remediation (Recommended) | Measurable benefit |
|---|---|---|---|---|
| 2.1 | `InMemorySaver` msgpack serde per super-step | O(super-steps × \|state\|) | Drop checkpointer for single run, or `InMemorySaver(serde=…)` with registered Pydantic serializers | ~27 serde round-trips of growing state removed/cheapened per run |
| 2.2 | Verifier + adversarial panel re-scan ALL findings each iteration | O(iterations × findings × locators) + O(F×I) audit records | Verify only new/changed findings; batch audit per iteration | ~3× fewer scans/appends on default 3-iter loop (O(F) not O(F×I)) |
| 2.3 | Web triage synchronous under one global lock, no backpressure | 1 concurrent run, unbounded threads | Job queue + run IDs + bounded `ThreadPoolExecutor` | Concurrency 1 → N; status latency decoupled from runs |
| 2.4 | Subprocess fan-out sequential across specialists | Σ(tool times) per iteration | Parallel via `concurrent.futures`, thread-safe sinks | Σ → max ≈ up to 4–5× faster collection |
| 2.5 | Full SHA-256 of evidence twice at intake (+once at report) | 2× full-corpus read before first finding | Hash once, share baseline; sample where mount is RO | 2× less intake hashing I/O; faster time-to-first-finding |
| 2.6 | Raw output stored per `tool_exec_id`, unbounded cache | O(total executions / total raw bytes) | Content-address by `sha256(raw)`, LRU-bound `_raw_cache` | Dedupe identical blobs; cap peak memory |

---

## 4. Maintainability

What is already strong, and where the seams are.

**Typing & contracts (strong).** The tool surface is fully typed: `ReadOnlyToolKit` methods return a Pydantic `ToolResult` envelope, and `ToolRunner.run` returns a `ToolExecution`. The verifier returns `VerificationResult`/`VerificationOutcome` Pydantic models. `from __future__ import annotations` is used consistently. This makes the data contracts between nodes inspectable and serializable (the `report` dict the web layer caches comes straight from `model_dump_json()`).

**Module boundaries (mostly clean, one weak spot).**
- The transport-independence claim holds: `CaseContext` wires one stack used identically by CLI, MCP server, and orchestrator (`context.py` docstring; `toolkit.py` notes both `server.py` and the orchestrator call the same class). This is a genuine strength — behavior cannot diverge between transports.
- The read-only guarantee is structural, not prompted: there is literally no write/exec method in `ReadOnlyToolKit.list_tools()`, and `subprocess.run` is confined to the single `ToolRunner.run` call site with `shell=False`. This is the right kind of boundary (capability-based).
- **Weak spot:** `web/server.py` leans on module-global mutable state (`_SESSION`, `_RUN_LOCK`). This couples the HTTP layer to a single run and makes it the least testable and least scalable module (see §2.3). Recommend encapsulating run state in an injected registry object rather than module globals.

**Lazy imports.** Several nodes and the web layer use function-local imports (`from glassbox.report.render import write_report`, `from glassbox.adversarial import AdversarialPanel`, etc.) to avoid import cycles. This works but signals latent cycle pressure between `orchestrator`, `report`, `adversarial`, and `attack`. Recommend mapping the cycle and extracting shared types into a leaf module so imports can move to module top-level (cheaper, and clearer dependency graph).

**Test seams (good, with a gap).**
- **Replay mode** is an excellent seam: `ToolRunner._replay` serves canned output through the *identical* parse/store/audit path (runner.py docstring), so offline tests exercise real code without SIFT installed. `TriageSession` uses it for the demo case.
- The audit chain is independently verifiable (`AuditChain.verify` is a classmethod that re-walks any file), and the hallucination gate is pure given a `RawStore` + known IDs — both are unit-testable in isolation.
- **Gap:** `nodes.collect`'s sequential fan-out and the web layer's global lock are not seam-friendly for concurrency testing. Introducing the worker pool (§2.3/§2.4) behind an interface would also make these paths injectable/mockable.

**Reproducibility hooks already present.** `stable_id` (util.py) yields deterministic IDs; `forensic.replay_verify` (referenced from `session.py`) re-derives a report from the audit log + raw store. Preserve these when introducing parallelism — fixed merge order in `collect` is required to keep `_merge_findings` output deterministic.

---

## 5. Proposed target architecture for scale

The current design is correct and auditable for a single case on a single workstation. To scale to many concurrent cases and large evidence without losing the integrity guarantees, evolve along three axes while keeping `CaseContext` as the per-case unit of isolation.

```
                         ┌──────────────────────────────────────────────┐
   HTTP / SSE  ─────────▶│  API layer (run-ID addressable; bounded conns) │
                         └───────────────┬──────────────────────────────┘
                                         │ enqueue {run_id, case}
                                         ▼
                         ┌──────────────────────────────────────────────┐
                         │  Job queue + Worker pool (ThreadPool/Process)  │  ← admission control / backpressure
                         └───────────────┬──────────────────────────────┘
                                         │ one CaseContext per run_id
              ┌──────────────────────────┼───────────────────────────────┐
              ▼                          ▼                                 ▼
   LangGraph + SqliteSaver     Parallel specialist fan-out        Object-store RawStore
   (persistent checkpoint,     (concurrent.futures, thread-safe   (content-addressed by
    resume, registered serde)   sinks, deterministic merge)        sha256(raw), LRU cache)
                                         │
                                         ▼
                          Hash-chained AuditChain (unchanged contract)
```

**1. Worker pool + run-ID API (addresses §2.3, §2.4).** A bounded `ThreadPoolExecutor` (or process pool for CPU-heavy parsing) behind a job queue gives explicit concurrency and backpressure. Each job owns one `CaseContext` (already the isolation boundary in `context.py`). The API becomes run-ID addressable so multiple cases/users coexist. Specialist fan-out within a run uses a second, smaller pool (§2.4) with deterministic result merging.

**2. Persistent checkpointer, e.g. `SqliteSaver` (addresses §2.1 for the resumable case).** If durable resume is wanted (long live cases, crash recovery), swap `InMemorySaver` for LangGraph's `SqliteSaver` with a registered serde for the Pydantic state types — this fixes both the warning spam and the lost-on-crash state, and makes the existing `get_state` fallback meaningful across process restarts. For pure one-shot runs, keep the *no-checkpointer* fast path.

**3. Object-store `RawStore` (addresses §2.6).** Keep the `RawStore.contains` / `get_raw` interface (the verifier depends only on it) but back it with content-addressed object storage keyed by `sha256(raw)` — local for the workstation, S3/MinIO for a shared deployment. Identical blobs dedupe; the in-memory `_raw_cache` becomes an LRU front. The hallucination gate is unchanged because it only ever calls `contains`/`get_raw`.

**Invariants to preserve through all of this.** The integrity properties are non-negotiable and must survive the refactor: (a) the hash-chained `AuditChain` contract (`prev_hash`/`record_hash`, verifiable by `AuditChain.verify`); (b) the capability boundary — no write/exec tool, `subprocess.run` only in `ToolRunner.run` with `shell=False`; (c) before/after SHA-256 custody via `IntegrityGuard`; (d) deterministic IDs and replay-verifiability. Parallelism and persistence change *how fast* and *how many*, never *what is provable*.

---

*All "Implemented" statements above are grounded in the named functions/files in `src/glassbox`. "Recommended" items are proposals with stated reasoning and a measurable check; none are implemented yet.*
