# GLASSBOX Triage Report — `demo-cridex-evtx`

Generated: 2026-06-03T18:20:41.323755Z  
GLASSBOX version: 0.1.0  
Evidence types: disk, evtx, memory, pcap  
Iterations: 2/3  
Audit chain valid: ✅  
Spoliation detected: ✅ No  
Total tokens: 0  

> **33 reportable finding(s) across 4 evidence type(s); 5 cross-source discrepancy(ies); 1 claim(s) quarantined as unsupported.**

## Evidence Integrity

| File | SHA-256 (before) | SHA-256 (after) | Unchanged |
|------|-----------------|-----------------|-----------|
| `capture.pcap` | `c3f393114eb252df…` | `c3f393114eb252df…` | ✅ |
| `cridex.vmem` | `857769df029cc77f…` | `857769df029cc77f…` | ✅ |
| `disk.img` | `9940413e4c84a70d…` | `9940413e4c84a70d…` | ✅ |
| `Security.evtx` | `5e047199bc681a17…` | `5e047199bc681a17…` | ✅ |

## Incident Narrative — demo-cridex-evtx

GLASSBOX reconstructed the following attack chain from cross-source evidence:

**Phase 1: Disk Artifact**
  [+] `[TE0007-yara_scan]` YARA match: Cridex_Reader_SL_Masquerade [T1036.005]
  [+] `[TE0009-disk_list_files]` Executable in suspicious path: reader_sl.exe [T1036.005]

**Phase 2: Service Install** (2012-07-22T02:43:01)
  [+] `[TE0011-evtx_hunt]` EVTX detection: New Service Installed [T1543.003]
  [+] `[TE0015-mem_svcscan]` Suspicious service 'Cridex' [T1543.003]

**Phase 3: Command Execution**
  [+] `[TE0006-mem_cmdline]` Suspicious command line in PID 1640 (reader_sl.exe) [T1059.001, T1027.010]
  [+] `[TE0007-yara_scan]` YARA match: Powershell_Encoded_Command [T1059.001, T1027.010]

**Phase 4: Process Injection**
  [+] `[TE0007-yara_scan]` YARA match: Generic_PE_In_RWX_Region [T1055]
  [+] `[TE0014-mem_malfind]` Injected/RWX code in PID 1484 (explorer.exe) [T1055]
  [+] `[TE0014-mem_malfind]` Injected/RWX code in PID 1640 (reader_sl.exe) [T1055]
  [+] `[TE0016-mem_dlllist]` Suspicious DLL loaded: inject.dll [T1055]

**Phase 5: Network Activity**
  [+] `[TE0001-pcap_conn_summary]` 3 network IOC(s) from pcap_conn_summary
  [+] `[TE0002-pcap_dns]` DNS query: evil-c2.cridex.net [T1071.004]
  [+] `[TE0002-pcap_dns]` DNS query: malware-update.dyndns.org [T1071.004]
  [+] `[TE0002-pcap_dns]` DNS query: 41.168.5.140.in-addr.arpa [T1071.004]
  [+] `[TE0002-pcap_dns]` 4 network IOC(s) from pcap_dns
  ... and 3 more.

**Phase 6: Evtx Detection** (2012-07-22T02:43:55 → 2012-07-22T02:44:12)
  [+] `[TE0011-evtx_hunt]` EVTX detection: Local Account Created [T1136.001]
  [+] `[TE0011-evtx_hunt]` EVTX detection: Security Event Log Cleared [T1070.001]
  [+] `[TE0012-evtx_to_json]` Explicit credential use (Event 4648) — possible pass-the-hash [T1550.002]
  [+] `[TE0012-evtx_to_json]` Kerberos pre-auth failure (Event 4771) — password spray / brute force [T1110.003]

**Phase 7: Cross Source Discrepancy**
  [~] `[TE0013-mem_psscan]` [hidden_process] X-219f985e19
  [~] `[TE0013-mem_psscan]` [hidden_process] X-1c390ee06d
  [~] `[TE0013-mem_psscan]` [hidden_process] X-768d7d25dd
  [~] `[TE0013-mem_psscan]` [hidden_process] X-0a3dbbae03
  [~] `[TE0013-mem_psscan]` [hidden_process] X-70a492c96d

**Phase 8: General**
  [+] `[TE0003-pcap_http]` External destination 125.19.103.198 [T1071.001]
  [+] `[TE0003-pcap_http]` External destination 41.168.5.140 [T1071.001]
  [+] `[TE0001-pcap_conn_summary]` External destination 8.8.8.8 [T1071.001]
  [+] `[TE0007-yara_scan]` YARA match: Cridex_C2_URL_Pattern [T1071.001]
  [+] `[TE0016-mem_dlllist]` Unknown/unmapped DLL in PID 1484 [T1055]
  ... and 6 more.

---
**Summary:** 28 confirmed observations, 10 inferred, 12 ATT&CK technique(s) mapped: `T1027.010`, `T1036.005`, `T1055`, `T1059.001`, `T1070.001`, `T1071.001`, `T1071.004`, `T1110.003` …

## Unified Incident Timeline (38 events)

| Timestamp | Source | Category | Title | Sev | Conf | Tool Exec |
|-----------|--------|----------|-------|-----|------|-----------|
| `2012-07-22T02:43:01` | evtx | service_install | EVTX detection: New Service Installed | HIGH | CON | `TE0011-evtx_hunt` |
| `2012-07-22T02:43:55` | evtx | evtx_detection | EVTX detection: Local Account Created | MEDIUM | CON | `TE0011-evtx_hunt` |
| `2012-07-22T02:44:12` | evtx | evtx_detection | EVTX detection: Security Event Log Cleared | HIGH | CON | `TE0011-evtx_hunt` |
| `unknown` | pcap | general | External destination 125.19.103.198 | MEDIUM | CON | `TE0003-pcap_http` |
| `unknown` | pcap | general | External destination 41.168.5.140 | MEDIUM | CON | `TE0003-pcap_http` |
| `unknown` | pcap | general | External destination 8.8.8.8 | MEDIUM | CON | `TE0001-pcap_conn_summary` |
| `unknown` | pcap | network_activity | 3 network IOC(s) from pcap_conn_summary | INFO | CON | `TE0001-pcap_conn_summary` |
| `unknown` | pcap | network_activity | DNS query: evil-c2.cridex.net | LOW | CON | `TE0002-pcap_dns` |
| `unknown` | pcap | network_activity | DNS query: malware-update.dyndns.org | LOW | CON | `TE0002-pcap_dns` |
| `unknown` | pcap | network_activity | DNS query: 41.168.5.140.in-addr.arpa | LOW | CON | `TE0002-pcap_dns` |
| `unknown` | pcap | network_activity | 4 network IOC(s) from pcap_dns | INFO | CON | `TE0002-pcap_dns` |
| `unknown` | pcap | network_activity | 4 network IOC(s) from pcap_http | INFO | CON | `TE0003-pcap_http` |
| `unknown` | memory | network_activity | External network connection to 41.168.5.140:8080 | HIGH | CON | `TE0005-mem_netscan` |
| `unknown` | memory | network_activity | External network connection to 125.19.103.198:8080 | HIGH | CON | `TE0005-mem_netscan` |
| `unknown` | memory | command_execution | Suspicious command line in PID 1640 (reader_sl.exe) | HIGH | CON | `TE0006-mem_cmdline` |
| `unknown` | memory | general | YARA match: Cridex_C2_URL_Pattern | HIGH | CON | `TE0007-yara_scan` |
| `unknown` | memory | disk_artifact | YARA match: Cridex_Reader_SL_Masquerade | HIGH | CON | `TE0007-yara_scan` |
| `unknown` | memory | process_injection | YARA match: Generic_PE_In_RWX_Region | HIGH | CON | `TE0007-yara_scan` |
| `unknown` | memory | command_execution | YARA match: Powershell_Encoded_Command | HIGH | CON | `TE0007-yara_scan` |
| `unknown` | disk | disk_artifact | Executable in suspicious path: reader_sl.exe | HIGH | CON | `TE0009-disk_list_files` |
| `unknown` | evtx | evtx_detection | Explicit credential use (Event 4648) — possible pass-th | HIGH | CON | `TE0012-evtx_to_json` |
| `unknown` | evtx | evtx_detection | Kerberos pre-auth failure (Event 4771) — password spray | HIGH | CON | `TE0012-evtx_to_json` |
| `unknown` | memory | process_injection | Injected/RWX code in PID 1484 (explorer.exe) | HIGH | CON | `TE0014-mem_malfind` |
| `unknown` | memory | process_injection | Injected/RWX code in PID 1640 (reader_sl.exe) | HIGH | CON | `TE0014-mem_malfind` |
| `unknown` | memory | service_install | Suspicious service 'Cridex' | MEDIUM | CON | `TE0015-mem_svcscan` |
| `unknown` | memory | general | Unknown/unmapped DLL in PID 1484 | HIGH | CON | `TE0016-mem_dlllist` |
| `unknown` | memory | process_injection | Suspicious DLL loaded: inject.dll | HIGH | CON | `TE0016-mem_dlllist` |
| `unknown` | memory | general | Unknown/unmapped DLL in PID 1640 | HIGH | CON | `TE0016-mem_dlllist` |
| `unknown` | memory | general | [Hidden Process] 348 | HIGH | INF | `TE0013-mem_psscan` |
| `unknown` | memory | general | [Hidden Process] 412 | HIGH | INF | `TE0013-mem_psscan` |

*(8 additional events in JSON report)*

## Findings (33 reportable)

### ⚪ 3 network IOC(s) from pcap_conn_summary

- **Severity:** INFO  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0001-pcap_conn_summary]`
- **Evidence type:** pcap
- Indicators extracted from captured network output (grounded).
- **IOCs:** `41[.]168[.]5[.]140`, `125[.]19[.]103[.]198`, `8[.]8[.]8[.]8`
- *Verifier:* all 1 cited locator(s) present in captured output

### ⚪ 4 network IOC(s) from pcap_dns

- **Severity:** INFO  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0002-pcap_dns]`
- **Evidence type:** pcap
- Indicators extracted from captured network output (grounded).
- **IOCs:** `41[.]168[.]5[.]140`, `evil-c2[.]cridex[.]net`, `malware-update[.]dyndns[.]org`, `41[.]168[.]5[.]140[.]in-addr[.]arpa`
- *Verifier:* all 1 cited locator(s) present in captured output

### ⚪ 4 network IOC(s) from pcap_http

- **Severity:** INFO  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0003-pcap_http]`
- **Evidence type:** pcap
- Indicators extracted from captured network output (grounded).
- **IOCs:** `hxxp://41[.]168[.]5[.]140/zb/v_01_a/in/`, `hxxp://125[.]19[.]103[.]198/zb/v_01_a/cfg/`, `41[.]168[.]5[.]140`, `125[.]19[.]103[.]198`
- *Verifier:* all 1 cited locator(s) present in captured output

### 🔵 DNS query: evil-c2.cridex.net

- **Severity:** LOW  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0002-pcap_dns]`
- **Evidence type:** pcap
- DNS query observed from 172.16.112.128 for evil-c2.cridex.net.
- **ATT&CK:** `T1071.004` Application Layer Protocol: DNS
- *Verifier:* all 1 cited locator(s) present in captured output

### 🔵 DNS query: malware-update.dyndns.org

- **Severity:** LOW  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0002-pcap_dns]`
- **Evidence type:** pcap
- DNS query observed from 172.16.112.128 for malware-update.dyndns.org.
- **ATT&CK:** `T1071.004` Application Layer Protocol: DNS
- *Verifier:* all 1 cited locator(s) present in captured output

### 🔵 DNS query: 41.168.5.140.in-addr.arpa

- **Severity:** LOW  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0002-pcap_dns]`
- **Evidence type:** pcap
- DNS query observed from 172.16.112.128 for 41.168.5.140.in-addr.arpa.
- **ATT&CK:** `T1071.004` Application Layer Protocol: DNS
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟡 External destination 125.19.103.198

- **Severity:** MEDIUM  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0003-pcap_http]`
- **Evidence type:** pcap
- Network capture shows traffic to external host 125.19.103.198.
- **ATT&CK:** `T1071.001` Application Layer Protocol: Web Protocols
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟡 External destination 41.168.5.140

- **Severity:** MEDIUM  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0003-pcap_http]`
- **Evidence type:** pcap
- Network capture shows traffic to external host 41.168.5.140.
- **ATT&CK:** `T1071.001` Application Layer Protocol: Web Protocols
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟡 External destination 8.8.8.8

- **Severity:** MEDIUM  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0001-pcap_conn_summary]`
- **Evidence type:** pcap
- Network capture shows traffic to external host 8.8.8.8.
- **ATT&CK:** `T1071.001` Application Layer Protocol: Web Protocols
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟡 EVTX detection: Local Account Created

- **Severity:** MEDIUM  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0011-evtx_hunt]`
- **Evidence type:** evtx
- **Observed at:** 2012-07-22T02:43:55.000Z
- Hayabusa/Sigma matched on VICTIM-PC (EventID 4720, Persistence). TargetUserName=backdoor; SubjectUserName=SYSTEM
- **ATT&CK:** `T1136.001` Create Account: Local Account
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟡 Suspicious service 'Cridex'

- **Severity:** MEDIUM  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0015-mem_svcscan]`
- **Evidence type:** memory
- Service binary path looks non-standard: C:\Users\Public\cridex.exe
- **ATT&CK:** `T1543.003` Create or Modify System Process: Windows Service
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 External network connection to 41.168.5.140:8080

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0005-mem_netscan]`
- **Evidence type:** memory
- Memory shows process 'explorer.exe' connected to external 41.168.5.140:8080 (TCP ESTABLISHED).
- **ATT&CK:** `T1071.001` Application Layer Protocol: Web Protocols
- **IOCs:** `41[.]168[.]5[.]140`
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 External network connection to 125.19.103.198:8080

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0005-mem_netscan]`
- **Evidence type:** memory
- Memory shows process 'explorer.exe' connected to external 125.19.103.198:8080 (TCP ESTABLISHED).
- **ATT&CK:** `T1071.001` Application Layer Protocol: Web Protocols
- **IOCs:** `125[.]19[.]103[.]198`
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Suspicious command line in PID 1640 (reader_sl.exe)

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0006-mem_cmdline]`
- **Evidence type:** memory
- Command line contains '-enc' (obfuscated/encoded execution): reader_sl.exe -enc UABvAHcAZQByAFMAaABlAGwAbAAgAC0ATgBvAFAAcgBvAGYAaQBsAGUA
- **ATT&CK:** `T1059.001` Command and Scripting Interpreter: PowerShell, `T1027.010` Obfuscated Files or Information: Command Obfuscation, `T1140` Deobfuscate/Decode Files or Information
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 YARA match: Cridex_C2_URL_Pattern

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0007-yara_scan]`
- **Evidence type:** memory
- YARA rule 'Cridex_C2_URL_Pattern' matched in /evidence/cridex.vmem.
- **ATT&CK:** `T1071.001` Application Layer Protocol: Web Protocols
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 YARA match: Cridex_Reader_SL_Masquerade

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0007-yara_scan]`
- **Evidence type:** memory
- YARA rule 'Cridex_Reader_SL_Masquerade' matched in /evidence/cridex.vmem.
- **ATT&CK:** `T1036.005` Masquerading: Match Legitimate Name or Location
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 YARA match: Generic_PE_In_RWX_Region

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0007-yara_scan]`
- **Evidence type:** memory
- YARA rule 'Generic_PE_In_RWX_Region' matched in /evidence/cridex.vmem.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 YARA match: Powershell_Encoded_Command

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0007-yara_scan]`
- **Evidence type:** memory
- YARA rule 'Powershell_Encoded_Command' matched in /evidence/cridex.vmem.
- **ATT&CK:** `T1059.001` Command and Scripting Interpreter: PowerShell, `T1027.010` Obfuscated Files or Information: Command Obfuscation, `T1140` Deobfuscate/Decode Files or Information
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Executable in suspicious path: reader_sl.exe

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0009-disk_list_files]`
- **Evidence type:** disk
- Non-standard executable 'Users/ismai/AppData/Local/Temp/reader_sl.exe' found in writable user directory.
- **ATT&CK:** `T1036.005` Masquerading: Match Legitimate Name or Location
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 EVTX detection: New Service Installed

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0011-evtx_hunt]`
- **Evidence type:** evtx
- **Observed at:** 2012-07-22T02:43:01.000Z
- Hayabusa/Sigma matched on VICTIM-PC (EventID 7045, Persistence). ServiceName=Cridex; ImagePath=C:\Users\Public\cridex.exe
- **ATT&CK:** `T1543.003` Create or Modify System Process: Windows Service
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 EVTX detection: Security Event Log Cleared

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0011-evtx_hunt]`
- **Evidence type:** evtx
- **Observed at:** 2012-07-22T02:44:12.000Z
- Hayabusa/Sigma matched on VICTIM-PC (EventID 1102, Defense Evasion). SubjectUserName=SYSTEM
- **ATT&CK:** `T1070.001` Indicator Removal: Clear Windows Event Logs
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Explicit credential use (Event 4648) — possible pass-the-hash

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0012-evtx_to_json]`
- **Evidence type:** evtx
- EventID 4648 detected in EVTX. User: VICTIM-PC$. Detail: SubjectUserName: VICTIM-PC$, TargetUserName: Administrator, TargetServerName: 172.16.112.1
- **ATT&CK:** `T1550.002` Use Alternate Authentication Material: Pass the Hash
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Kerberos pre-auth failure (Event 4771) — password spray / brute force

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0012-evtx_to_json]`
- **Evidence type:** evtx
- EventID 4771 detected in EVTX. User: Administrator. Detail: AccountName: Administrator, FailureCode: 0x18 (wrong password), ClientAddress: ::1
- **ATT&CK:** `T1110.003` Brute Force: Password Spraying
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Injected/RWX code in PID 1484 (explorer.exe)

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0014-mem_malfind]`
- **Evidence type:** memory
- malfind flagged executable private memory (PAGE_EXECUTE_READWRITE) in PID 1484 'explorer.exe' — consistent with code injection.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Injected/RWX code in PID 1640 (reader_sl.exe)

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0014-mem_malfind]`
- **Evidence type:** memory
- malfind flagged executable private memory (PAGE_EXECUTE_READWRITE) in PID 1640 'reader_sl.exe' — consistent with code injection.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Unknown/unmapped DLL in PID 1484

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0016-mem_dlllist]`
- **Evidence type:** memory
- PID 1484 has a loaded DLL with no mapped filename at base 0x03d70000 — possible injection.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Suspicious DLL loaded: inject.dll

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0016-mem_dlllist]`
- **Evidence type:** memory
- DLL 'inject.dll' loaded from suspicious path 'C:\Users\Public\inject.dll' in PID 1640.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 Unknown/unmapped DLL in PID 1640

- **Severity:** HIGH  **Confidence:** **CONFIRMED**  Score: 0.80  `[TE0016-mem_dlllist]`
- **Evidence type:** memory
- PID 1640 has a loaded DLL with no mapped filename at base 0x10000000 — possible injection.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 [Hidden Process] 348

- **Severity:** HIGH  **Confidence:** *INFERRED*  Score: 0.60  `[TE0013-mem_psscan]`
- **Evidence type:** memory
- Process 'csrss.exe' (PID 348) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 [Hidden Process] 412

- **Severity:** HIGH  **Confidence:** *INFERRED*  Score: 0.60  `[TE0013-mem_psscan]`
- **Evidence type:** memory
- Process 'services.exe' (PID 412) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 [Hidden Process] 1896

- **Severity:** HIGH  **Confidence:** *INFERRED*  Score: 0.60  `[TE0013-mem_psscan]`
- **Evidence type:** memory
- Process 'wuauclt.exe' (PID 1896) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 [Hidden Process] 788

- **Severity:** HIGH  **Confidence:** *INFERRED*  Score: 0.60  `[TE0013-mem_psscan]`
- **Evidence type:** memory
- Process 'svchost.exe' (PID 788) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

### 🟠 [Hidden Process] 1520

- **Severity:** HIGH  **Confidence:** *INFERRED*  Score: 0.60  `[TE0013-mem_psscan]`
- **Evidence type:** memory
- Process 'HIDDEN_PROC' (PID 1520) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.
- **ATT&CK:** `T1055` Process Injection
- *Verifier:* all 1 cited locator(s) present in captured output

## Cross-Source Discrepancies (5)

### 🔍 [hidden_process] X-219f985e19

- **Sources:** memory
- **Severity:** HIGH  **Confidence:** INFERRED
- Process 'csrss.exe' (PID 348) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.

### 🔍 [hidden_process] X-1c390ee06d

- **Sources:** memory
- **Severity:** HIGH  **Confidence:** INFERRED
- Process 'services.exe' (PID 412) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.

### 🔍 [hidden_process] X-768d7d25dd

- **Sources:** memory
- **Severity:** HIGH  **Confidence:** INFERRED
- Process 'wuauclt.exe' (PID 1896) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.

### 🔍 [hidden_process] X-0a3dbbae03

- **Sources:** memory
- **Severity:** HIGH  **Confidence:** INFERRED
- Process 'svchost.exe' (PID 788) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.

### 🔍 [hidden_process] X-70a492c96d

- **Sources:** memory
- **Severity:** HIGH  **Confidence:** INFERRED
- Process 'HIDDEN_PROC' (PID 1520) was found by the pool scanner (psscan) but is ABSENT from the active process list (pslist). Consistent with process hiding/unlinking or recent termination.

## MITRE ATT&CK Coverage

- **Execution** (`TA0002`): `T1059.001`
- **Persistence** (`TA0003`): `T1136.001`, `T1543.003`
- **Privilege Escalation** (`TA0004`): `T1055`, `T1543.003`
- **Defense Evasion** (`TA0005`): `T1027.010`, `T1036.005`, `T1055`, `T1070.001`, `T1140`
- **Credential Access** (`TA0006`): `T1110.003`
- **Lateral Movement** (`TA0008`): `T1550.002`
- **Command and Control** (`TA0011`): `T1071.001`, `T1071.004`

## Extracted IOCs (9)

| Type | Value (defanged) | Context |
|------|-----------------|---------|
| filepath | `C:\Users\Public\cridex.exe` | evtx_hunt detections |
| ipv4 | `41[.]168[.]5[.]140` | from TE0001-pcap_conn_summary |
| ipv4 | `125[.]19[.]103[.]198` | from TE0001-pcap_conn_summary |
| ipv4 | `8[.]8[.]8[.]8` | from TE0001-pcap_conn_summary |
| domain | `evil-c2[.]cridex[.]net` | from TE0002-pcap_dns |
| domain | `malware-update[.]dyndns[.]org` | from TE0002-pcap_dns |
| domain | `41[.]168[.]5[.]140[.]in-addr[.]arpa` | from TE0002-pcap_dns |
| url | `hxxp://41[.]168[.]5[.]140/zb/v_01_a/in/` | from TE0003-pcap_http |
| url | `hxxp://125[.]19[.]103[.]198/zb/v_01_a/cfg/` | from TE0003-pcap_http |

## Quarantined Claims (1 — HALLUCINATED / unsupported)

> These findings were proposed but **quarantined by the hallucination gate** because
> the cited value was absent from all captured tool output. They are listed here for
> transparency (per the accuracy report requirement) and must not be treated as fact.

- ~~Assessment: active data exfiltration of ~2.3 GB to C2~~  *(verifier: locator '2.3 GB' absent from output of TE0005-mem_netscan; cited value '2.3 GB' not found in any cited tool output)*

## Agent Execution Summary (20 messages)

| # | From | To | Role | Summary |
|---|------|----|------|---------|
| 0 | `orchestrator` | `case` | status | Case intake: 4 evidence item(s); integrity baseline hashed. |
| 1 | `orchestrator` | `specialists` | plan | Iteration 1 plan (12 step(s)): Iteration 1. Planning 12 step(s): pcap_conn_summa |
| 2 | `orchestrator` | `network_analyst` | request | Analyze capture.pcap with ['pcap_conn_summary', 'pcap_dns', 'pcap_http'] |
| 3 | `network_analyst` | `orchestrator` | result | 11 finding(s). pcap_conn_summary: 4 rows; pcap_dns: 3 rows; pcap_http: 2 rows |
| 4 | `orchestrator` | `memory_analyst` | request | Analyze cridex.vmem with ['mem_pslist', 'mem_netscan', 'mem_cmdline', 'yara_scan |
| 5 | `memory_analyst` | `orchestrator` | result | 8 finding(s). pslist: 10 active processes; netscan: 2 external connection(s); cm |
| 6 | `orchestrator` | `disk_analyst` | request | Analyze disk.img with ['disk_partition_table', 'disk_list_files', 'disk_mft_time |
| 7 | `disk_analyst` | `orchestrator` | result | 1 finding(s). mmls: 4 partitions (offset=63); fls: 13 files (8 images); timeline |
| 8 | `orchestrator` | `evtx_analyst` | request | Analyze Security.evtx with ['evtx_hunt', 'evtx_to_json'] |
| 9 | `evtx_analyst` | `orchestrator` | result | 3 finding(s). evtx_hunt: 3 detection(s); evtx_to_json: 4 events |
| 10 | `correlation_engine` | `orchestrator` | result | 0 cross-source discrepancy(ies): |
| 11 | `verifier` | `orchestrator` | result | Verified: 22 confirmed, 0 inferred, 1 HALLUCINATED (quarantined). |
| 12 | `orchestrator` | `self` | critique | Iteration 1/3: 22 findings, 1 quarantined. Gaps: ['mem_psscan', 'mem_malfind', ' |
| 13 | `orchestrator` | `specialists` | plan | Iteration 2 plan (5 step(s)): Iteration 2. Planning 5 step(s): mem_psscan(cridex |
| 14 | `orchestrator` | `memory_analyst` | request | Analyze cridex.vmem with ['mem_psscan', 'mem_malfind', 'mem_svcscan', 'mem_dllli |
| 15 | `memory_analyst` | `orchestrator` | result | 6 finding(s). psscan: 11 processes by pool scan; malfind: 2 injection candidate( |
| 16 | `correlation_engine` | `orchestrator` | result | 5 cross-source discrepancy(ies): hidden_process, hidden_process, hidden_process, |
| 17 | `verifier` | `orchestrator` | result | Verified: 28 confirmed, 5 inferred, 0 HALLUCINATED (quarantined). |
| 18 | `orchestrator` | `self` | critique | Iteration 2/3: 33 findings, 0 quarantined. Gaps: none. Concluding. |
| 19 | `orchestrator` | `analyst` | status | Triage complete in 2 iteration(s). 33 reportable finding(s) across 4 evidence ty |

---
*Report generated by GLASSBOX v0.1.0. Audit log: `case.audit.jsonl`. Every finding cites a `[TExxxx]` tool execution ID traceable in the JSONL execution log.*