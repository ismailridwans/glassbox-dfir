"""MITRE ATT&CK (Enterprise) reference data.

Every technique ID / name / tactic association below was verified against
attack.mitre.org on 2026-06-03 (see docs/ACCURACY_REPORT.md for the source
URLs). The table deliberately covers the full kill chain so the orchestrator
can report ATT&CK coverage across reconnaissance → impact.

NOTE: this is a *curated* table for fast, offline, dependency-free mapping of
the artifacts GLASSBOX's tools surface. It is not the full ATT&CK corpus. A
finding whose technique is not in this table is still reported — just without
an enrichment, and flagged so coverage gaps are visible (never silently
dropped).
"""

from __future__ import annotations

# Canonical ordered Enterprise tactics (14). IDs are NOT sequential by design.
TACTICS: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]
TACTIC_NAME: dict[str, str] = {tid: name for tid, name in TACTICS}
TACTIC_ORDER: dict[str, int] = {tid: i for i, (tid, _) in enumerate(TACTICS)}

# technique_id -> (name, [tactic_ids])
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1543.003": ("Create or Modify System Process: Windows Service", ["TA0003", "TA0004"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1547.001": (
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        ["TA0003", "TA0004"],
    ),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["TA0002"]),
    "T1027": ("Obfuscated Files or Information", ["TA0005"]),
    "T1027.010": ("Obfuscated Files or Information: Command Obfuscation", ["TA0005"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["TA0005"]),
    "T1055": ("Process Injection", ["TA0005", "TA0004"]),
    "T1055.012": ("Process Injection: Process Hollowing", ["TA0005", "TA0004"]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["TA0006"]),
    "T1003.006": ("OS Credential Dumping: DCSync", ["TA0006"]),
    "T1550.002": ("Use Alternate Authentication Material: Pass the Hash", ["TA0008"]),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ["TA0008"]),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ["TA0008"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1569.002": ("System Services: Service Execution", ["TA0002"]),
    "T1047": ("Windows Management Instrumentation", ["TA0002"]),
    "T1036.003": ("Masquerading: Rename System Utilities", ["TA0005"]),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", ["TA0005"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["TA0005"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["TA0011"]),
    "T1071.004": ("Application Layer Protocol: DNS", ["TA0011"]),
    "T1560.001": ("Archive Collected Data: Archive via Utility", ["TA0009"]),
    "T1074.001": ("Data Staged: Local Data Staging", ["TA0009"]),
    "T1136.001": ("Create Account: Local Account", ["TA0003"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["TA0005"]),
    "T1110.003": ("Brute Force: Password Spraying", ["TA0006"]),
    "T1210": ("Exploitation of Remote Services", ["TA0008"]),
    "T1098": ("Account Manipulation", ["TA0003", "TA0004"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["TA0010"]),
    # --- LOLBAS / System Binary Proxy Execution ---
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["TA0005"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["TA0005"]),
    "T1218.007": ("System Binary Proxy Execution: Msiexec", ["TA0005"]),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ["TA0005"]),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", ["TA0002"]),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", ["TA0002"]),
    "T1197": ("BITS Jobs", ["TA0003", "TA0005"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1021.006": ("Remote Services: Windows Remote Management", ["TA0008"]),
    # --- Discovery ---
    "T1057": ("Process Discovery", ["TA0007"]),
    "T1082": ("System Information Discovery", ["TA0007"]),
    "T1083": ("File and Directory Discovery", ["TA0007"]),
    "T1049": ("System Network Connections Discovery", ["TA0007"]),
    "T1012": ("Query Registry", ["TA0007"]),
    # --- Collection ---
    "T1005": ("Data from Local System", ["TA0009"]),
    "T1113": ("Screen Capture", ["TA0009"]),
    # --- Initial Access ---
    "T1566.001": ("Phishing: Spearphishing Attachment", ["TA0001"]),
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    # --- Credential Access (additional) ---
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ["TA0006"]),
    "T1555.003": ("Credentials from Password Stores: Credentials from Web Browsers", ["TA0006"]),
    "T1555":     ("Credentials from Password Stores", ["TA0006"]),
    # --- Privilege Escalation (additional) ---
    "T1134.001": ("Access Token Manipulation: Token Impersonation/Theft", ["TA0004", "TA0005"]),
    "T1134.002": ("Access Token Manipulation: Create Process with Token", ["TA0004", "TA0005"]),
    # --- Persistence (additional) ---
    "T1546.003": ("Event Triggered Execution: Windows Management Instrumentation Event Subscription", ["TA0003", "TA0004"]),
    "T1546.015": ("Event Triggered Execution: Component Object Model Hijacking", ["TA0003"]),
    "T1574.001": ("Hijack Execution Flow: DLL Search Order Hijacking", ["TA0003", "TA0004", "TA0005"]),
    # --- Defense Evasion (additional) ---
    "T1562.006": ("Impair Defenses: Indicator Blocking", ["TA0005"]),
    "T1106":     ("Native API", ["TA0002"]),
    "T1014":     ("Rootkit", ["TA0005"]),
    # --- Impact ---
    "T1486":     ("Data Encrypted for Impact", ["TA0040"]),
    "T1561.002": ("Disk Wipe: Disk Structure Wipe", ["TA0040"]),
}

# Artifact key (set by parsers/specialists) -> [technique_ids]. Where an
# artifact legitimately implies several techniques, all are listed.
ARTIFACT_TECHNIQUES: dict[str, list[str]] = {
    "service_install": ["T1543.003"],
    "scheduled_task": ["T1053.005"],
    "registry_run_key": ["T1547.001"],
    "powershell_encoded": ["T1059.001", "T1027.010", "T1140"],
    "powershell_suspicious": ["T1059.001"],
    "process_injection": ["T1055"],
    "process_hollowing": ["T1055.012"],
    "lsass_dump": ["T1003.001"],
    "dcsync": ["T1003.006"],
    "pass_the_hash": ["T1550.002"],
    "remote_logon_ntlm": ["T1021.002", "T1078"],
    "rdp_logon": ["T1021.001"],
    "psexec": ["T1569.002", "T1021.002"],
    "wmi_exec": ["T1047"],
    "masquerade_rename": ["T1036.003"],
    "masquerade_path": ["T1036.005"],
    "clear_event_log": ["T1070.001"],
    "dns_c2": ["T1071.004"],
    "http_c2": ["T1071.001"],
    "archive_exfil": ["T1560.001", "T1074.001"],
    "exfil_network": ["T1048"],
    "local_account_created": ["T1136.001"],
    "defender_tamper": ["T1562.001"],
    "password_spray": ["T1110.003"],
    "account_manipulation": ["T1098"],
    "exploit_remote_service": ["T1210"],
    # Discovery (process / file / system enumeration artifacts)
    "process_discovery": ["T1057"],
    "file_directory_discovery": ["T1083"],
    "system_info_discovery": ["T1082"],
    "network_conn_discovery": ["T1049"],
    "query_registry": ["T1012"],
    # Collection
    "local_data_collection": ["T1005"],
    # Initial access
    "phishing": ["T1566.001"],
    # LOLBAS
    "lolbas_certutil": ["T1140", "T1105"],
    "lolbas_regsvr32": ["T1218.010"],
    "lolbas_mshta": ["T1218.005"],
    "lolbas_bits": ["T1197"],
    "lolbas_msiexec": ["T1218.007"],
    "lolbas_rundll32": ["T1218.011"],
    "lolbas_cmd": ["T1059.003"],
    "lolbas_vbs": ["T1059.005"],
    "winrm": ["T1021.006"],
    "kerberoasting": ["T1558.003"],
    "token_impersonation": ["T1134.001"],
    "browser_credential": ["T1555.003"],
    "wmi_persistence": ["T1546.003"],
    "com_hijacking": ["T1546.015"],
    "dll_hijacking": ["T1574.001"],
    "rootkit": ["T1014"],
}

# Windows Security/Sysmon event ID -> artifact key (a hint, not a verdict).
EVENTID_ARTIFACT: dict[int, str] = {
    7045: "service_install",         # System log: A service was installed
    4698: "scheduled_task",          # Security: Scheduled task created
    4104: "powershell_suspicious",   # PowerShell ScriptBlock logging
    1102: "clear_event_log",         # Security log was cleared
    4720: "local_account_created",   # A user account was created
    4662: "dcsync",                  # Directory service access (DS-Replication)
    4771: "password_spray",          # Kerberos pre-auth failed
    4625: "password_spray",          # Failed logon (volume => spray/bruteforce)
    4648: "pass_the_hash",           # Explicit credential use
    4768: "pass_the_hash",           # Kerberos TGT request
    4769: "pass_the_hash",           # Kerberos TGS request (RC4)
    4776: "remote_logon_ntlm",       # NTLM authentication
    4624: "remote_logon_ntlm",       # Successful logon
    4688: "process_discovery",        # Process created (Sysmon-equivalent)
    4663: "file_directory_discovery", # Object access: file/dir enumeration
    4657: "query_registry",           # Registry value modified/queried
    # Kerberoasting
    4769: "kerberoasting",            # Kerberos TGS request — check for RC4 EncType=0x17
    4768: "kerberoasting",            # Kerberos TGT request
    # Token/Credential
    4693: "browser_credential",       # DPAPI master key recovery
    4692: "browser_credential",       # DPAPI master key backup
    # Token impersonation
    # (4624 w/ LogonType=9 handled specially in specialist code)
    # WMI persistence events
    5861: "wmi_persistence",          # WMI permanent event consumer created
    5859: "wmi_persistence",          # WMI ESS notification triggered
    5857: "wmi_persistence",          # WMI provider DLL load
    # Scheduled task modification/deletion
    140:  "scheduled_task",           # Scheduled task modified
    141:  "scheduled_task",           # Scheduled task deleted
    # AppLocker blocks
    8004: "defender_tamper",          # AppLocker EXE blocked
    8007: "defender_tamper",          # AppLocker Script blocked
}
