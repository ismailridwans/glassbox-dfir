# GLASSBOX Dataset Documentation

## Test Data Used

### 1. Offline Demo / CI — Synthetic Replay Fixtures

**Source:** Synthetic JSON fixtures in `demo_case/fixtures/`, derived from the documented ground truth of `cridex.vmem` (Volatility Foundation memory samples).

**What the agent finds (reproducible):**

| Finding | Evidence source | Tool | Confidence |
|---------|----------------|------|-----------|
| External TCP connection to `41.168.5.140:8080` (explorer.exe) | Memory | mem_netscan | CONFIRMED |
| External TCP connection to `125.19.103.198:8080` | Memory | mem_netscan | CONFIRMED |
| Injected/RWX code in PID 1484 (explorer.exe) | Memory | mem_malfind | CONFIRMED |
| Injected/RWX code in PID 1640 (reader_sl.exe) | Memory | mem_malfind | CONFIRMED |
| PowerShell encoded command in PID 1640 | Memory | mem_cmdline | CONFIRMED |
| Suspicious service `Cridex` in `C:\Users\Public\` | Memory | mem_svcscan | CONFIRMED |
| New service installed (EventID 7045) → T1543.003 | EVTX | evtx_hunt | CONFIRMED |
| Security log cleared (EventID 1102) → T1070.001 | EVTX | evtx_hunt | CONFIRMED |
| Local account created `backdoor` (EventID 4720) → T1136.001 | EVTX | evtx_hunt | CONFIRMED |
| Hidden process PID 1520 (psscan not in pslist) | Memory correlation | correlate | INFERRED |
| Orphan connection from PID 9999 (not in pslist) | Memory correlation | correlate | INFERRED |
| **QUARANTINED: "2.3 GB exfil" assessment** | Memory | mem_netscan | ~~HALLUCINATED~~ |

**Reproducibility:** `glassbox demo` always produces this exact output (deterministic, no LLM tokens consumed by default).

**Ground truth:** `demo_case/ground_truth/ground_truth.json`

---

### 2. Memory Forensics — cridex.vmem (Volatility Foundation)

**Source:** http://files.sempersecurus.org/dumps/cridex_memdump.zip  
**Image:** Windows XP SP2 x86, Cridex banking trojan  
**Documented ground truth:** http://www.sempersecurus.org/2012/08/cridex-analysis-using-volatility.html  
**Memory Samples wiki:** https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples

**Documented evil (primary source, pre-verified):**
- Process: `reader_sl.exe` (PID 1640), child of `explorer.exe` (PID 1484) — masquerading as Adobe Reader SpeedLauncher
- Network IOC: `41.168.5.140:8080` (Cridex C2), `POST /zb/v_01_a/in/`
- Process injection: malfind flags RWX private memory in explorer.exe (PID 1484) and reader_sl.exe (PID 1640)

**How to use on SIFT:**
```bash
# Place cridex.vmem in your case evidence directory
mkdir -p /cases/cridex/evidence
cp ~/Downloads/cridex.vmem /cases/cridex/evidence/
glassbox triage /cases/cridex --max-iter 3
```

---

### 3. EVTX Attack Samples — sbousseaden/EVTX-ATTACK-SAMPLES

**Source:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  
**Organization:** Top-level directories by ATT&CK tactic, metadata index in `evtx_data.csv`  
**License:** Check repo — samples for research use

**Technique-to-file mapping used for benchmarking:**

| File | ATT&CK Technique | Source |
|------|-----------------|--------|
| `Credential Access/4794_DSRM_password_change_t1098.evtx` | T1098 | filename + metadata |
| `Credential Access/CA_DCSync_4662.evtx` | T1003.006 | metadata |
| `Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` | T1003.001 | metadata |
| `Defense Evasion/` (EventID 1102 files) | T1070.001 | folder + event ID |
| `Persistence/` (EventID 4720 files) | T1136.001 | folder + event ID |

**Benchmark invocation:**
```bash
# After running triage and placing report JSON in /tmp/preds/
glassbox benchmark \
  demo_case/ground_truth \
  /tmp/preds \
  --report benchmark_report.json
```

---

### 4. Network — malware-traffic-analysis.net (Optional, for PCAP testing)

**Source:** https://www.malware-traffic-analysis.net/training-exercises.html  
**Author:** Brad Duncan (SANS ISC handler / Palo Alto Unit 42)  
**Format:** Password-protected ZIP (password: `infected`), PCAP + answers page documenting C2 IPs/domains/malware family  
**License:** For research/educational use; see site About page

**How to use:**
```bash
unzip -P infected 2024-09-04-traffic-analysis-exercise.pcap.zip
cp *.pcap /cases/pcap-exercise/evidence/
glassbox triage /cases/pcap-exercise
```

---

## Reproducibility

All core functionality and the hallucination gate demonstration are **fully reproducible** without any evidence download:

```bash
pip install -e .
pytest tests/ -v           # unit tests — all offline
glassbox demo              # end-to-end demo — all offline
```

The demo is deterministic: same fixture files + same (heuristic, no-LLM) backend = identical report every run.
