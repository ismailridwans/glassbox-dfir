# GLASSBOX — Autonomous DFIR Triage for the SANS SIFT Workstation

> *"Every finding traces to a tool call. The evidence is architecturally untouchable."*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![Hackathon](https://img.shields.io/badge/FIND%20EVIL!-Hackathon-red)](https://findevil.devpost.com/)

GLASSBOX is a fully autonomous, self-correcting incident-response triage agent built on the **SANS SIFT Workstation** and **Protocol SIFT**. It closes the speed gap between AI-powered adversaries (8-minute full domain compromise, per CrowdStrike) and human responders — without hallucinating findings or touching evidence.

---

## What Makes GLASSBOX Different

| Feature | Protocol SIFT (baseline) | GLASSBOX |
|---------|--------------------------|---------|
| Evidence protection | Prompt: "don't modify evidence" | **Architectural**: no write tool exists in the surface |
| Hallucination control | None | **Mechanical gate**: every finding verified against captured raw output |
| Self-correction | Ad-hoc retry | **Bounded LangGraph loop** with max-iterations cap + recursion_limit safety net |
| Cross-source correlation | None | **Disk-vs-memory discrepancy engine** (hidden procs, orphan connections, bad parents) |
| Audit trail | Append to forensic_audit.log | **Hash-chained JSONL** — every record links to the prior hash; tampering detected |
| ATT&CK mapping | None | **Full kill-chain**: 17 artifact→technique mappings + Sigma tag parsing |
| Runs without SIFT | No | **Yes** — offline replay mode for demo/CI |

---

## Quick Start (Try It Out)

### Requirements
- Python ≥ 3.10
- SANS SIFT Workstation (Ubuntu-based OVA) **or** any Linux/macOS with `python3` for the offline demo

### Install
```bash
git clone https://github.com/YOUR_ORG/glassbox-sift
cd glassbox-sift
pip install -e .
```

### Launch the web dashboard (recommended — zero extra dependencies)
```bash
glassbox serve            # opens http://127.0.0.1:8787 — auto-runs a live triage
```
A browser command console with a full feature menu: live execution trace,
findings explorer, incident timeline, ATT&CK matrix (+ Navigator export), IOCs,
cross-source discrepancies, the tamper-evident audit trail, a one-click
guardrail self-test, and court-admissible replay. Built on the Python standard
library only (`http.server` + Server-Sent Events) — no Node, no build step, no
extra `pip` install. See [docs/WEB_UI.md](docs/WEB_UI.md).

### Run the offline demo in the terminal (no SIFT required)
```bash
glassbox demo             # one-shot triage summary
glassbox dashboard        # live node-by-node terminal trace
```

Expected output:
```
[GLASSBOX DEMO] Running offline demo case (replay fixtures) ...
[GLASSBOX DEMO] Complete — 2 iteration(s)
  Confirmed findings  : 6
  Inferred findings   : 3
  Quarantined (hallu) : 1
  Discrepancies       : 2
  Audit chain valid   : YES

  [SELF-CORRECTION SEQUENCE]
  The following claim was quarantined as unsupported:
    QUARANTINED: Assessment: active data exfiltration of ~2.3 GB to C2
    Reason     : locator '2.3 GB' absent from output of TE0005-mem_netscan
```

### Run on a real case (SIFT Workstation)
```bash
# Set up the case directory
mkdir -p /cases/incident-001/evidence
cp /media/usb/cridex.vmem /cases/incident-001/evidence/
cp -r /media/usb/evtx_logs/ /cases/incident-001/evidence/

# Run triage (3 self-correction iterations max)
glassbox triage /cases/incident-001 --max-iter 3

# Verify the audit chain afterwards
glassbox verify-audit /cases/incident-001/case.audit.jsonl

# Confirm zero evidence modification
glassbox check-spoliation /cases/incident-001/evidence/
```

### Launch as MCP server (for Claude Code / Claude Desktop)
```bash
GLASSBOX_CASE=/cases/incident-001 glassbox mcp-serve
```

Claude Desktop config (`~/.config/claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "glassbox": {
      "command": "python",
      "args": ["-m", "glassbox.mcp_server.server"],
      "env": {
        "GLASSBOX_CASE": "/cases/incident-001",
        "GLASSBOX_EVIDENCE": "/cases/incident-001/evidence"
      }
    }
  }
}
```

---

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full diagram with trust boundaries.

**Pattern:** Custom read-only MCP Server + LangGraph StateGraph orchestrator.

```
Claude Code / Claude Desktop
         │  stdio
         ▼
 ┌─────────────────────────────────────────────────────┐
 │  GLASSBOX Read-Only MCP Server                      │  ← architectural trust boundary
 │  (only typed read functions — no shell, no write)   │
 └──────────────┬──────────────────────────────────────┘
                │ in-process calls
                ▼
 ┌─────────────────────────────────────────────────────┐
 │  LangGraph StateGraph (bounded self-correction)     │
 │  intake → plan → collect → correlate → map_attack   │
 │    → verify (hallucination gate) → critique → loop? │
 │    → report                                         │
 └──────────────┬──────────────────────────────────────┘
                │
                ▼
 ┌─────────────────────────────────────────────────────┐
 │  Read-Only Evidence Vault + Integrity Guard         │
 │  (OS permissions + before/after SHA-256)            │
 └──────────────┬──────────────────────────────────────┘
                │ read-only
                ▼
         Evidence (disk / memory / evtx / pcap)
```

---

## Supported Evidence Types

| Type | Tools Used (SIFT path) |
|------|------------------------|
| Memory image | Volatility 3 (`windows.pslist`, `psscan`, `netscan`, `malfind`, `cmdline`, `svcscan`) |
| Disk image | Sleuth Kit (`mmls`, `fls -r -m`) |
| EVTX logs | Hayabusa (Sigma/ATT&CK), EvtxECmd, python-evtx fallback |
| PCAP | tshark (connections, DNS, HTTP) |

---

## Running Tests
```bash
pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

All tests run offline; no SIFT binaries required.

---

## Project Structure
```
src/glassbox/
  audit/          # AuditChain (hash-chained JSONL) + RawStore
  attack/         # MITRE ATT&CK data + resolvers
  benchmark/      # Accuracy scoring harness
  correlate/      # Cross-source discrepancy detection
  evidence/       # Read-only vault + anti-spoliation guard
  ioc/            # IOC extraction + defanging
  mcp_server/     # Read-only MCP server + typed tool wrappers + parsers
  orchestrator/   # LangGraph graph, nodes, specialists, LLM abstraction
  report/         # Markdown + JSON report renderer
  cli.py          # CLI entrypoint
demo_case/
  fixtures/       # Replay data (cridex-based) — no SIFT needed
  ground_truth/   # Benchmark ground truth
docs/
  ARCHITECTURE.md
  ACCURACY_REPORT.md
  DATASET.md
  PROJECT_DESCRIPTION.md
  DEMO_SCRIPT.md
  SUBMISSION_CHECKLIST.md
tests/            # pytest suite
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
