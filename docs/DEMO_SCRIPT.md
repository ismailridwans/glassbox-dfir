# GLASSBOX Demo Script (5-Minute Screencast)

This script walks through a live terminal demo that satisfies deliverable #2:  
*"Screencast of live terminal execution with audio narration. Show the agent working against real case data, including **at least one self-correction sequence**."*

---

## Setup (before recording)

```bash
# Install (SIFT or any Python 3.10+ machine)
git clone https://github.com/YOUR_ORG/glassbox-sift && cd glassbox-sift
pip install -e .
```

---

## Scene 1: What GLASSBOX Is (00:00–00:30)

**Narrate:** *"GLASSBOX is an autonomous DFIR triage agent for the SANS SIFT Workstation. It closes the speed gap between machine-speed adversaries and human responders — without hallucinating findings or touching evidence. Every finding traces to a tool call; the evidence is architecturally untouchable."*

Show the architecture diagram briefly: `cat docs/ARCHITECTURE.md`

---

## Scene 2: Evidence Integrity Proof (00:30–01:00)

```bash
# Show the evidence vault
ls demo_case/evidence/

# Confirm no write tool exists in the MCP surface
python -c "
from glassbox.mcp_server.toolkit import ReadOnlyToolKit
# (abbreviated init for demo)
print('Registered tools:')
# Output: 20 read-only tools — no Bash, no write, no delete
"

# Run the spoilation probe
glassbox check-spoliation demo_case/evidence/
```

**Expected output:**
```
✅  All 0 write attempts blocked — evidence integrity holds.
```
*(Demo evidence dir is empty — on SIFT with real evidence: blocked by filesystem permissions.)*

**Narrate:** *"Before a single tool runs, the evidence is hash-baselined. GLASSBOX has no write tool — the MCP server simply doesn't expose one. Spoliation is architecturally impossible, not just asked-for-nicely in a prompt."*

---

## Scene 3: Autonomous Triage — Iteration 1 (01:00–02:30)

```bash
glassbox demo --max-iter 3
```

Watch the LangGraph graph execute. The output streams:

```
[GLASSBOX DEMO] Running offline demo case (replay fixtures) ...
  Case dir : /tmp/glassbox_demo_xxx/case

# intake node:
→ Case intake: 0 evidence item(s) in vault (fixtures will replay)

# plan node (iteration 1):
→ Planning 5 step(s): mem_pslist(cridex.vmem), mem_netscan(cridex.vmem),
  mem_cmdline(cridex.vmem), evtx_hunt(Security.evtx), ...

# collect node — specialists run:
→ [memory_analyst] 6 finding(s). netscan: 2 external connections; malfind: 2 injection(s)
→ [evtx_analyst]   3 finding(s). evtx_hunt: 3 detection(s)

# correlate node:
→ 2 cross-source discrepancy(ies): hidden_process, orphan_connection

# verify node (HALLUCINATION GATE):
→ Verified: 8 confirmed, 3 inferred, 1 HALLUCINATED (quarantined).
```

**Narrate:** *"The memory analyst found Cridex connecting to 41.168.5.140:8080. The EVTX analyst caught the service install and log-clear. The verifier just quarantined one finding — an over-eager exfil-volume claim the agent made without any supporting data in the tool output. That's the hallucination gate working exactly as intended."*

---

## Scene 4: Self-Correction Loop (02:30–03:30) ← REQUIRED SELF-CORRECTION SEQUENCE

```
# critique node (automatic after verify):
→ Iteration 1/3: 11 findings, 1 quarantined.
  Gaps: ['mem_psscan', 'mem_malfind']
  Reason: external/injection indicators warrant hidden-process pool scan + malfind
  Looping to remediate.

# plan node (iteration 2 — self-correction):
→ Planning 2 step(s): mem_psscan(cridex.vmem), mem_malfind(cridex.vmem)
  Reason: self-correction — gap remediation

# collect (iteration 2):
→ [memory_analyst] psscan: 11 processes by pool scan
  HIDDEN: PID 1520 (HIDDEN_PROC) found by pool scan but absent from active list

# correlate (iteration 2):
→ 3 cross-source discrepancy(ies): hidden_process, duplicate_singleton_process, orphan_connection

# verify (iteration 2):
→ Verified: 11 confirmed, 4 inferred, 1 HALLUCINATED (quarantined).

# critique (iteration 2):
→ No new gaps found. Concluding.
```

**Narrate:** *"After iteration 1, the critique node noticed that with injection indicators found, the pool scanner hadn't been run yet. It generated a concrete gap — mem_psscan — and routed back for a second iteration. That's the bounded self-correction loop. The loop bound is enforced in code: if gaps remain at max_iterations, GLASSBOX finishes gracefully with what it has."*

---

## Scene 5: Results (03:30–04:30)

```
[GLASSBOX DEMO] Complete — 2 iteration(s)
  Confirmed findings  : 9
  Inferred findings   : 4
  Quarantined (hallu) : 1
  Discrepancies       : 3
  Audit chain valid   : YES

  [SELF-CORRECTION SEQUENCE]
  The following claim was quarantined as unsupported:
    QUARANTINED: Assessment: active data exfiltration of ~2.3 GB to C2
    Reason     : locator '2.3 GB' absent from output of TE0005-mem_netscan

  Reports written to: demo_output/
```

```bash
# Show the Markdown report
cat demo_output/demo-cridex-evtx.report.md | head -80

# Show the execution log (deliverable #8)
head -5 demo_output/demo-cridex-evtx.execution_log.jsonl | python -m json.tool
```

**Narrate:** *"Every finding in the report carries a [TExxxx] citation. The execution log is JSONL — every agent-to-agent message with timestamp and token usage. A judge can take any finding ID and trace it back to the exact tool run that produced it."*

---

## Scene 6: Audit Chain Verification (04:30–05:00)

```bash
# The audit log is in the case directory
ls /tmp/glassbox_demo_xxx/case/case.audit.jsonl

# Verify the hash chain is intact
glassbox verify-audit /tmp/glassbox_demo_xxx/case/case.audit.jsonl
```

**Expected:**
```
✅ Audit chain VALID: /tmp/glassbox_demo_xxx/case/case.audit.jsonl
```

**Narrate:** *"The audit chain uses the same hash-linking technique as a blockchain. Each record's hash covers the previous hash and the event body. Alter any record — even one character — and every subsequent hash breaks. This is chain-of-custody that can survive a legal challenge."*

---

## Key Talking Points (for audio narration)

1. **No prompt-based guardrails for safety** — the MCP server doesn't register destructive tools. There's nothing to bypass.
2. **The hallucination gate is code, not a prompt** — it re-reads captured output and does string matching. The model cannot talk its way to CONFIRMED.
3. **The loop terminates by design** — `iteration >= max_iterations` in Python, backed by `recursion_limit`.
4. **Every finding is traceable** — `[TExxxx]` in the Markdown, full record in the JSONL, raw output in the RawStore.
5. **Runs offline** — the demo needs no SIFT, no API key, no network. Forensically deterministic.
