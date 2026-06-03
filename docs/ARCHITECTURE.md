# GLASSBOX Architecture

## Architectural Pattern

**Primary pattern: Custom Read-Only MCP Server + LangGraph StateGraph Orchestrator**

This combination was selected because the hackathon explicitly calls the Custom MCP Server "the most sound architecture in the evaluation" and LangGraph satisfies the tiebreaker criterion (autonomous execution quality) and audit trail requirement (logged agent-to-agent messages with timestamps and token usage).

---

## System Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ANALYST WORKSTATION (SANS SIFT — Ubuntu 20/22.04 LTS)                   │
│                                                                          │
│  ┌─────────────────────────────────┐                                     │
│  │  Claude Code / Claude Desktop   │  ← human-readable narration only    │
│  │  (MCP client, stdio transport)  │                                     │
│  └───────────────┬─────────────────┘                                     │
│                  │ stdio MCP (JSON-RPC)                                   │
│  ════════════════╪════════════════════════════════════════════════════   │
│   TRUST BOUNDARY │   (prompt-based guardrails stop here ↑)               │
│  ════════════════╪════════════════════════════════════════════════════   │
│                  ▼                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  GLASSBOX Read-Only MCP Server  (glassbox.mcp_server.server)     │    │
│  │                                                                  │    │
│  │  Registered tools (ALL read-only):                               │    │
│  │    mem_pslist  mem_psscan  mem_netscan  mem_malfind  mem_cmdline │    │
│  │    mem_svcscan  mem_pstree                                       │    │
│  │    disk_partition_table  disk_list_files  disk_mft_timeline      │    │
│  │    evtx_hunt  evtx_to_json  evtx_dump_xml                       │    │
│  │    pcap_conn_summary  pcap_dns  pcap_http                       │    │
│  │    evidence_manifest  hash_verify  ioc_extract  attack_map      │    │
│  │                                                                  │    │
│  │  NOT registered: execute_shell / write_file / delete / Bash     │    │
│  │  ← The absence is the architectural guardrail                    │    │
│  └─────────────────────────┬────────────────────────────────────────┘    │
│                            │ in-process                                   │
│  ════════════════════════ ORCHESTRATION LAYER ═══════════════════════    │
│                            ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  LangGraph StateGraph  (langgraph==1.2.4, InMemorySaver)         │    │
│  │                                                                  │    │
│  │  START → intake → plan → collect → correlate → map_attack        │    │
│  │            ▲        └── specialists ──┘                          │    │
│  │            │                                                     │    │
│  │          plan ←── critique (bounded loop, max_iterations cap)   │    │
│  │            │                                                     │    │
│  │          report → END                                            │    │
│  │                                                                  │    │
│  │  Loop guards:                                                    │    │
│  │    1. in-state iteration counter (architectural, in code)        │    │
│  │    2. LangGraph recursion_limit=50 → GraphRecursionError caught  │    │
│  │    Both route to report (graceful degradation, never a crash)    │    │
│  └─────────────────────────┬────────────────────────────────────────┘    │
│                            │                                              │
│  ════════════════════════ DATA LAYER ════════════════════════════════    │
│                            ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  RawStore (content-addressed verbatim tool output)               │    │
│  │  AuditChain (hash-chained JSONL — every event linked)            │    │
│  │  IntegrityGuard (before/after SHA-256 per evidence file)         │    │
│  └─────────────────────────┬────────────────────────────────────────┘    │
│                            │ read-only (vault.resolve rejects traversal) │
│  ════════════════════════ EVIDENCE VAULT ════════════════════════════    │
│                            ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Evidence (filesystem — ideally mounted -o ro / write-blocked)   │    │
│  │    *.vmem  *.E01  *.img  *.evtx  *.pcap                         │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Trust Boundaries

### Boundary 1: MCP Server Surface (Primary architectural guardrail)

**What crosses the boundary:** Typed structured results (pydantic `ToolResult` objects). Never raw multi-MB dumps; those go to RawStore only.

**What is deliberately absent:** `execute_shell`, `write_file`, `Bash`, `delete`, `mount`, `dd`. The model cannot request a capability that doesn't exist. This is what the hackathon spec calls "the agent physically cannot run destructive commands because the server doesn't have those tools."

**Contrast with Protocol SIFT baseline:** Protocol SIFT exposes a `Bash` tool with an allow-list. The allow-list is enforced by Claude Code's permission system (a prompt-adjacent control). GLASSBOX has no `Bash` tool — a fundamentally different attack surface.

### Boundary 2: Evidence Vault (Defense in depth)

**Layer 1 (recommended for live cases):** OS-level read-only mount: `ewfmount`, `-o ro`, or hardware write blocker. GLASSBOX never relies on this alone but documents it.

**Layer 2 (always on):** `EvidenceVault.resolve()` rejects any path that doesn't resolve inside the vault root (path traversal blocked). Every tool call goes through `vault.resolve()` before touching the filesystem.

**Layer 3 (on-demand):** `vault.harden()` strips write bits (POSIX `0o444`/`0o555`; Windows read-only attribute). Called by `IntegrityGuard`.

**Testing:** `glassbox check-spoliation <evidence_dir>` actively attempts a zero-byte write to every evidence file and reports whether the OS blocked it.

### Boundary 3: Hallucination Gate (Verification layer)

Every finding proposed by a specialist node carries `Provenance.raw_locator` — a substring the verifier re-finds in the captured output for `tool_exec_id`. This gate is the *only* path to CONFIRMED status. The model cannot self-promote.

---

## Prompt-Based vs. Architectural Guardrails (Required by Hackathon)

| Guardrail | Type | Mechanism |
|-----------|------|-----------|
| No destructive tool calls | **Architectural** | No `Bash`/`write`/`delete` tool registered in MCP server |
| No path traversal | **Architectural** | `vault.resolve()` in Python — called before every tool touches the FS |
| No context window overload | **Architectural** | Parsers run server-side; LLM receives only structured summaries |
| Loop termination | **Architectural** | `iteration >= max_iterations` check in `route_after_critique` (Python code) + LangGraph `recursion_limit` |
| Hallucination prevention | **Architectural** | Verifier re-checks raw output; HALLUCINATED findings never appear in report as fact |
| Evidence integrity | **Architectural** | Before/after SHA-256 via `IntegrityGuard`; no write capability in tool surface |
| Audit trail | **Architectural** | Hash-chained JSONL; model has no tool to write to it |
| "Read-only evidence" narration | **Prompt** | LLM system prompt reinforces the posture; *not depended on for safety* |
| Grounding confidence | **Prompt** | Specialists asked to cite locators; *the gate, not the prompt, is the enforcement* |

The bottom two rows are present but explicitly non-load-bearing. The top seven are the real controls.

---

## Agent-to-Agent Communication (Deliverable #8)

Every `A2AMessage` carries: `seq`, `ts` (UTC ISO-8601), `from_agent`, `to_agent`, `role`, `summary`, `refs` (tool_exec_ids / finding_ids), `token_usage`. The JSONL execution log (`*.execution_log.jsonl`) is the structured trace required by deliverable #8.

Agents: `orchestrator`, `memory_analyst`, `disk_analyst`, `evtx_analyst`, `network_analyst`, `correlation_engine`, `verifier`.

---

## Graceful Degradation

When a tool is `UNAVAILABLE` (binary not found) or returns `ERROR`:
1. The `ToolExecution` records the status and `stderr_excerpt`.
2. The `degraded` list in state is updated.
3. The `critique` node checks for EVTX fallback (`evtx_dump_xml` when `evtx_to_json` fails) and logs the substitution.
4. The final report lists `degraded_tools` so the analyst knows what was missed.
5. The hallucination gate never flags a finding as CONFIRMED if it depends on a degraded tool's output — it won't find the locator there.

No crash path exists from a missing binary.
