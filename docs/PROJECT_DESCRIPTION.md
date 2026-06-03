# GLASSBOX — Project Description (Devpost Format)

## What it does

GLASSBOX is a fully autonomous, self-correcting DFIR triage agent for the SANS SIFT Workstation. Given a set of evidence — disk images, memory captures, Windows event logs, or PCAP captures — it orchestrates the full IR analysis at machine speed and delivers a structured report where **every finding cites the tool execution that produced it**.

It solves the three specific failure modes of the existing Protocol SIFT baseline:

1. **Hallucination** — Protocol SIFT (and the Anthropic GTG-1002 report) document that autonomous agents "frequently overstate findings and occasionally fabricate data." GLASSBOX adds a mechanical verification gate: every finding's cited value is re-found in the captured raw output of the cited tool execution. If it isn't there, the finding is quarantined — not silently dropped, but logged in the accuracy report so the false-positive count is visible to the judge.

2. **Evidence spoliation** — Protocol SIFT's guardrail is a prompt: "NEVER modify evidence." GLASSBOX's guardrail is architectural: there is no `execute_shell`, `write_file`, or `delete` tool in the MCP server's surface. The model cannot modify evidence because the capability does not exist — not because it was asked not to.

3. **Runaway execution** — The hackathon explicitly warns about "agent loops stuck in infinite conversational spirals." GLASSBOX implements a LangGraph state machine with a bounded self-correction loop: an in-state `max_iterations` counter enforced in deterministic routing code, backed by LangGraph's `recursion_limit` safety net. Both are architectural, not prompt-based.

### The full feature set

- **20 read-only tool functions** across memory (Volatility 3), disk (Sleuth Kit), event logs (Hayabusa/EvtxECmd/python-evtx fallback), and network (tshark) — every one typed, parsed server-side, and never exposing raw multi-MB dumps to the model.
- **Hash-chained JSONL audit trail** — every tool execution, agent-to-agent message, self-correction decision, and integrity check is hash-linked; any insertion, deletion, or alteration breaks the chain (detected by `glassbox verify-audit`).
- **Cross-source correlation** — compares disk listing vs. memory process list; flags hidden processes (psscan-vs-pslist), duplicate singletons (Stuxnet 3×lsass pattern), unexpected parents (lsass parented by services.exe), and orphan network connections.
- **MITRE ATT&CK full kill-chain mapping** — 17 verified artifact→technique mappings + Sigma tag parsing; coverage rollup by tactic in canonical recon→impact order.
- **IOC extraction with defanging** — IPv4, domain, URL, SHA-256, MD5, registry path; every IOC grounded to the tool execution it was extracted from.
- **Evidence integrity proof** — before/after SHA-256 for every evidence file; `glassbox check-spoliation` actively probes for write access.
- **Offline demo** — the full pipeline runs on any machine without SIFT installed via replay fixtures based on the cridex.vmem Volatility labs ground truth.

---

## How we built it

**Architecture pattern:** Custom read-only MCP Server (the hackathon's "most sound architecture") + LangGraph StateGraph orchestrator.

The two-layer design was chosen because it satisfies *two separate* judging criteria simultaneously:
- The Custom MCP Server wins **Constraint Implementation** (criterion #4): guardrails are architectural, not prompt-based.
- LangGraph wins **Autonomous Execution Quality** (criterion #1, the tiebreaker) and **Audit Trail Quality** (criterion #5): the state machine is the source of truth for execution order, self-correction decisions, and token accounting.

**Key design decisions:**

1. *The model never sees raw tool output.* Every SIFT tool is wrapped with a parser that extracts a compact structured summary. The model reasons over structured findings; the raw bytes go to the RawStore for the verifier. This is the hackathon spec's exact prescription: "The MCP server handles raw tool output natively… preventing context window overload."

2. *The hallucination verifier is the sole authority on confidence.* The model proposes findings (UNVERIFIED); the verifier assigns CONFIRMED, INFERRED, or HALLUCINATED. The model cannot self-promote a claim to CONFIRMED.

3. *The self-correction loop is deterministic.* The `critique` node identifies specific analytical gaps (e.g., "external connection found but psscan not yet run"). The `route_after_critique` function decides whether to loop — in code, not via a model output. The model only narrates.

4. *Every claim is content-addressed.* Tool output is stored under `tool_exec_id` keys in the RawStore. A finding's `Provenance.raw_locator` is a substring the verifier re-finds there. This is what makes the audit trail truly traceable rather than just logged.

**Technology stack:**

- `mcp==1.27.2` — official MCP Python SDK (FastMCP), `mcp.run(transport="stdio")`
- `langgraph==1.2.4` — StateGraph with `InMemorySaver` checkpointer
- `pydantic>=2.7` — typed data contracts throughout
- `anthropic>=0.40` (optional) — real LLM reasoning via Claude claude-opus-4-8; system prompt uses `cache_control: ephemeral` for prompt caching
- All SIFT tools invoked via `subprocess.run(..., shell=False)` — no string-interpolation injection possible

---

## Challenges

**Hallucination verification vs. context efficiency.** The verifier needs the raw output; the model needs to not be drowned in it. The solution — RawStore as a side-channel, parsers running server-side — required inverting the usual design (tools return structured data to the model, raw data to the verifier separately).

**Making the self-correction loop self-stopping.** The loop must remediate real gaps (psscan after an injection indicator) without becoming a runaway. The critique node's gap detection is conservative: it only adds steps for tool/evidence pairs not yet executed, and the in-state counter is the hard bound. LangGraph's `recursion_limit` is the backstop.

**Architectural vs. prompt guardrails — the distinction matters.** Protocol SIFT's read-only mode is an `allow`/`deny` list on command names — the model still gets a general Bash tool and could run `fls --help > /evidence/oops`. GLASSBOX's MCP server doesn't expose `Bash` at all. A judge probing bypass will find a different surface.

**Running without SIFT for CI and demo.** The replay system (fixture JSONs matched by tool name) threads through the identical parse/store/audit/verify path, so the CI tests exercise real hallucination detection and real audit-chain integrity, just with canned tool output.

---

## What we learned

- The hardest part of autonomous IR is not writing the agent — it's making the agent's claims *trustworthy*. The hallucination gate and the provenance model are what distinguish a demo from something a practitioner could stand behind.
- LangGraph's typed state is an excellent fit for multi-stage IR: each node updates exactly the fields it owns, the checkpoint is the audit trail, and `stream_mode="updates"` gives per-node execution visibility for free.
- Protocol SIFT's actual implementation (Skills + Bash allowlist) is significantly more vulnerable to accidental evidence modification than its marketing implies. The community needs the architectural upgrade.

---

## What's next

- **Live endpoint triage** via an MCP-connected SIEM/EDR (starter idea #3) — the toolkit's architecture supports it; add a `live_endpoint` tool that pulls from an API instead of a file.
- **Persistent learning loop** (starter idea #7) — currently each run starts fresh; adding cross-run failure memory would let the agent improve on recurring case types.
- **Symbol table management** for Volatility 3 offline cases (PDB download automation or pre-packed symbol archives).
- **Chainsaw integration** alongside Hayabusa for EVTX (Sigma rule diversity, different default rule sets).
- **PDF report via WeasyPrint** (the same path Protocol SIFT's `generate_pdf_report.py` uses, so GLASSBOX is a drop-in enhancement).
