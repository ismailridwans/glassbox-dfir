# GLASSBOX — Submission Checklist

All 8 mandatory deliverables. Missing any one = elimination.

| # | Deliverable | Status | Location |
|---|------------|--------|----------|
| 1 | **Code Repository** — GitHub (public), Apache 2.0 | ✅ | Repo root, `LICENSE` |
| 2 | **Demo Video** (5 min) — live terminal, audio narration, ≥1 self-correction | ✅ Script ready | `docs/DEMO_SCRIPT.md` |
| 3 | **Architecture Diagram** — pattern, trust boundaries, prompt vs. architectural guardrails | ✅ | `docs/ARCHITECTURE.md` |
| 4 | **Written Project Description** — what/how/challenges/learned/next | ✅ | `docs/PROJECT_DESCRIPTION.md` |
| 5 | **Dataset Documentation** — source, findings, reproducibility | ✅ | `docs/DATASET.md` |
| 6 | **Accuracy Report** — FP rate, missed, hallucinated, confirmed vs. inferred, integrity approach, spoliation test | ✅ | `docs/ACCURACY_REPORT.md` |
| 7 | **Try-It-Out Instructions** — local deploy on SIFT Workstation | ✅ | `README.md` — Quick Start |
| 8 | **Agent Execution Logs** — structured, every finding traceable | ✅ | `*.execution_log.jsonl` (in reports/) |

---

## Judging Criteria Mapping

| Criterion | Weight | How GLASSBOX addresses it |
|-----------|--------|--------------------------|
| 1. Autonomous Execution Quality (tiebreaker) | High | LangGraph StateGraph runs end-to-end without human input; critique node self-identifies gaps; bounded self-correction loop; deterministic planning |
| 2. IR Accuracy | High | Mechanical hallucination gate (code, not prompt); CONFIRMED vs. INFERRED vs. HALLUCINATED distinction; accuracy report with FP rate and missed artifacts |
| 3. Breadth & Depth | Medium | Disk + Memory + EVTX (3 types, deep per type); cross-source correlation; 20 read-only tools; ATT&CK full kill-chain |
| 4. Constraint Implementation | High | Custom MCP Server with zero write tools (architectural, not prompt); path traversal blocked in code; verified + tested for bypass |
| 5. Audit Trail Quality | High | Hash-chained JSONL; [TExxxx] citations in report; JSONL execution log with A2A messages, timestamps, token usage |
| 6. Usability & Documentation | Medium | `glassbox demo` (1 command, no SIFT); full README; ARCHITECTURE + DATASET + ACCURACY_REPORT; pytest suite |

---

## Pre-Submission Verification Steps

```bash
# 1. Tests pass
pytest tests/ -v --tb=short

# 2. Offline demo runs end-to-end
glassbox demo

# 3. Audit chain is valid after the demo
glassbox verify-audit /tmp/glassbox_demo_*/case/case.audit.jsonl

# 4. Confirm no write tool in MCP surface
python -c "
from glassbox.mcp_server.toolkit import ReadOnlyToolKit
# Instantiate minimally and list tools
import tempfile, pathlib
from glassbox.evidence.vault import EvidenceVault
from glassbox.mcp_server.runner import ToolRunner
from glassbox.audit.chain import AuditChain
from glassbox.audit.rawstore import RawStore
t = tempfile.mkdtemp()
(pathlib.Path(t)/'evidence').mkdir()
v = EvidenceVault(pathlib.Path(t)/'evidence')
r = ToolRunner(RawStore(pathlib.Path(t)/'raw'), AuditChain(pathlib.Path(t)/'a.jsonl'))
kit = ReadOnlyToolKit(v, r)
tools = kit.list_tools()
print(tools)
assert 'execute_shell' not in tools
assert 'write_file' not in tools
assert 'Bash' not in tools
print('PASS: no write/shell tools in MCP surface')
"

# 5. License check
head -3 LICENSE  # should show Apache 2.0

# 6. Repo is public on GitHub
gh repo view YOUR_ORG/glassbox-sift
```
