"""Specialist analysts (the multi-agent decomposition).

Each specialist owns one evidence type, calls only its domain tools through the
read-only toolkit, and returns **structured findings** — never raw dumps — so no
single context window holds all the evidence. Every grounded finding carries
provenance whose ``raw_locator`` is a string the verifier can re-find in the
captured tool output.

A note on honesty: the network analyst can emit ONE deliberately over-eager
"assessment" finding (an unquantified exfil volume) when ``demo_overclaim`` is
set. It cites a value that is *not* in any tool output, so the hallucination
gate quarantines it — a faithful, reproducible demonstration of catching the
exact GTG-1002 failure mode ("overstated findings / fabricated data"). With the
real LLM backend, genuine model claims flow through the same gate.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from glassbox.attack import dedupe_mappings, for_artifact, for_event_id, technique
from glassbox.ioc.extract import defang
from glassbox.models import (
    IOC,
    AttackMapping,
    Confidence,
    EvidenceType,
    Finding,
    Provenance,
    Severity,
)
from glassbox.util import stable_id

_SYS_BINS = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "wininit.exe",
             "smss.exe", "winlogon.exe", "explorer.exe"}
_PS_ENCODED = ("-enc", "-encodedcommand", "frombase64string", "-e ", "-w hidden",
               "-windowstyle hidden", "-nop", "iex", "downloadstring", "invoke-expression")
_SUSP_SVC_PATH = ("\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\",
                  "powershell", "cmd /c", "cmd.exe /c", "\\windows\\temp\\", ".ps1")


def _routable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


def _extract_service(details: str) -> str:
    """Extract ServiceName from Kerberos event details string."""
    import re
    m = re.search(r"ServiceName=([^\s;,]+)", details)
    return m.group(1) if m else "unknown service"


def _harvest_iocs_from_text(text: str, eid_str: str, tool: str, exec_id: str) -> list:
    """Extract IOCs from an event payload/description string."""
    from glassbox.ioc.extract import extract_iocs
    from glassbox.models import Provenance
    prov = [Provenance(tool_exec_id=exec_id, tool=tool, raw_locator="", note=f"EID {eid_str}")]
    iocs = extract_iocs(text, context=f"EventID {eid_str}", provenance=prov, include_filepaths=True)
    for ioc in iocs:
        for p in ioc.provenance:
            p.raw_locator = ioc.value
    return iocs


def _prov(exec_id: str, tool: str, locator, note: str = "") -> Provenance:
    return Provenance(tool_exec_id=exec_id, tool=tool, raw_locator=str(locator), note=note)


def _harvest_iocs_from_text(text: str, locator: str, tool: str, exec_id: str) -> list[IOC]:
    """Extract IOCs from an arbitrary text snippet, grounding them to exec_id."""
    from glassbox.ioc.extract import extract_iocs
    prov = [Provenance(tool_exec_id=exec_id, tool=tool, raw_locator=locator)]
    iocs = extract_iocs(text, provenance=prov, include_filepaths=True)
    for ioc in iocs:
        for p in ioc.provenance:
            p.raw_locator = ioc.value
    return iocs


def _harvest_iocs(toolkit, exec_id: str, context: str = "") -> list[IOC]:
    """Extract and return grounded IOCs from a tool execution's captured output."""
    raw = toolkit.runner.rawstore.get_raw(exec_id)
    if not raw:
        return []
    from glassbox.ioc.extract import extract_iocs
    prov = [Provenance(tool_exec_id=exec_id, tool="ioc_extract", raw_locator="", note=context)]
    iocs = extract_iocs(raw, context=context,
                        provenance=prov, include_filepaths=True)
    # set each IOC's locator to its own value for the verifier
    for ioc in iocs:
        for p in ioc.provenance:
            p.raw_locator = ioc.value
    return iocs


def _attack_for(*artifact_keys: str) -> list[AttackMapping]:
    out: list[AttackMapping] = []
    for k in artifact_keys:
        out += for_artifact(k)
    return dedupe_mappings(out)


def _finding(*, title, desc, evtype, severity, confidence, attack, cited, prov, agent, iocs=None,
             observed_at=None) -> Finding:
    return Finding(
        finding_id=stable_id("F", agent, title, *cited),
        title=title,
        description=desc,
        evidence_type=evtype,
        severity=severity,
        confidence=confidence,
        attack=attack,
        iocs=iocs or [],
        cited_values=list(cited),
        provenance=prov,
        source_agent=agent,
        observed_at=observed_at,
    )


class SpecialistOutput(dict):
    """{'findings','view','executed','degraded','rationale'}"""


def _empty() -> SpecialistOutput:
    return SpecialistOutput(findings=[], view={}, executed=[], degraded=[], rationale="")


# --------------------------------------------------------------------------- #
# MEMORY
# --------------------------------------------------------------------------- #
def run_memory(toolkit, evidence: str, tools: list[str], *, demo_overclaim: bool = False) -> SpecialistOutput:
    out = _empty()
    agent = "memory_analyst"
    reasons = []
    for tool in tools:
        fn = getattr(toolkit, tool, None)
        if fn is None:
            continue
        res = fn(evidence)
        out["executed"].append(res.tool_exec_id)
        if res.status not in ("OK", "DEGRADED"):
            out["degraded"].append(tool)
            reasons.append(f"{tool} -> {res.status} ({res.note[:60]})")
            continue
        s = res.summary

        if tool == "mem_pslist":
            procs = s.get("processes", [])
            out["view"]["pslist"] = procs
            out["view"]["pslist_exec_id"] = res.tool_exec_id
            # T1057 Process Discovery: enumerating a running process list is itself an artifact
            if procs:
                out["findings"].append(_finding(
                    title=f"Process discovery: {len(procs)} running processes enumerated",
                    desc=(f"mem_pslist enumerated {len(procs)} active processes. "
                          f"Process discovery (T1057) is a standard initial-access follow-on activity. "
                          f"Notable: {', '.join(p.get('name','?') for p in procs[:5])}."),
                    evtype=EvidenceType.MEMORY, severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("process_discovery"),
                    cited=[str(procs[0].get("pid", ""))],
                    prov=[_prov(res.tool_exec_id, "mem_pslist", str(procs[0].get("pid", "")))],
                    agent=agent))
            # Flag suspicious process names (masquerade patterns)
            _MASQ = {
                "lsasss.exe": "lsass.exe double-s masquerade",
                "svchost32.exe": "svchost with bit-count suffix masquerade",
                "svch0st.exe": "svchost with zero-substitution masquerade",
                "csrss32.exe": "csrss masquerade",
                "reader_sl.exe": "Adobe Reader SpeedLauncher — suspicious if not expected",
            }
            for p in procs:
                name_lower = str(p.get("name", "")).lower()
                if name_lower in _MASQ:
                    out["findings"].append(_finding(
                        title=f"Suspicious process name: {p.get('name')} (PID {p.get('pid')})",
                        desc=f"{_MASQ[name_lower]}. PID={p.get('pid')}, PPID={p.get('ppid')}.",
                        evtype=EvidenceType.MEMORY, severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED, attack=_attack_for("masquerade_rename"),
                        cited=[str(p.get("name", ""))],
                        prov=[_prov(res.tool_exec_id, "mem_pslist", str(p.get("name", "")))],
                        agent=agent))
            reasons.append(f"pslist: {s.get('count', 0)} active processes")
        elif tool == "mem_pstree":
            procs = s.get("processes", [])
            # Only update pslist if pstree found >= as many procs as the current view
            # (pslist from vol.pslist is canonical; pstree is for parent-chain only)
            existing_pslist = out["view"].get("pslist", [])
            if len(procs) >= len(existing_pslist):
                out["view"]["pslist"] = procs
                out["view"]["pslist_exec_id"] = res.tool_exec_id
            out["view"]["pstree"] = procs  # separate key for pstree-specific analysis
            out["view"]["pstree_exec_id"] = res.tool_exec_id
            # Suspicious parent-child chains: Office/browser spawning shells
            _SHELL_NAMES = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
            _LOADER_NAMES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                             "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
                             "explorer.exe", "reader_sl.exe", "acrord32.exe"}
            by_pid = {int(p["pid"]): p for p in procs if "pid" in p}
            for p in procs:
                name = str(p.get("name", "")).lower()
                if name not in _SHELL_NAMES:
                    continue
                ppid = int(p.get("ppid", -1))
                parent = by_pid.get(ppid)
                pname = str(parent.get("name", "")).lower() if parent else ""
                if pname in _LOADER_NAMES:
                    out["findings"].append(_finding(
                        title=f"Suspicious spawn: {pname} -> {name} (PID {p.get('pid')})",
                        desc=(f"Process '{name}' (PID {p.get('pid')}) was spawned by "
                              f"'{pname}' (PID {ppid}). Typical phishing/code-execution pattern."),
                        evtype=EvidenceType.MEMORY, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("powershell_suspicious"),
                        cited=[str(p.get("pid"))],
                        prov=[_prov(res.tool_exec_id, "mem_pstree", str(p.get("pid")))],
                        agent=agent))
            reasons.append(f"pstree: {len(procs)} processes ({len(out['findings'])} spawn anomalies)")
        elif tool == "mem_psscan":
            out["view"]["psscan"] = s.get("processes", [])
            out["view"]["psscan_exec_id"] = res.tool_exec_id
            reasons.append(f"psscan: {s.get('count', 0)} processes by pool scan")
        elif tool == "mem_netscan":
            out["view"]["netscan"] = s.get("connections", [])
            out["view"]["netscan_exec_id"] = res.tool_exec_id
            ext = 0
            for c in s.get("connections", []):
                raddr = str(c.get("raddr", "")).strip()
                if not _routable(raddr):
                    continue
                ext += 1
                ioc = IOC(type="ipv4", value=raddr, defanged=defang(raddr, "ipv4"),
                          context="memory netscan foreign address",
                          provenance=[_prov(res.tool_exec_id, "mem_netscan", raddr)])
                out["findings"].append(_finding(
                    title=f"External network connection to {raddr}:{c.get('rport')}",
                    desc=(f"Memory shows process '{c.get('owner') or c.get('pid')}' "
                          f"connected to external {raddr}:{c.get('rport')} ({c.get('proto')} {c.get('state')})."),
                    evtype=EvidenceType.MEMORY, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("http_c2"),
                    cited=[raddr], prov=[_prov(res.tool_exec_id, "mem_netscan", raddr)],
                    agent=agent, iocs=[ioc]))
            # T1049 System Network Connections Discovery: netscan itself is the discovery act
            total_conns = len(s.get("connections", []))
            if total_conns > 0:
                out["findings"].append(_finding(
                    title=f"Network connection discovery: {total_conns} connection(s) in memory",
                    desc=f"mem_netscan enumerated {total_conns} active network connections (T1049).",
                    evtype=EvidenceType.MEMORY, severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("network_conn_discovery"),
                    cited=[str(total_conns)],
                    prov=[_prov(res.tool_exec_id, "mem_netscan", str(total_conns))],
                    agent=agent))
            reasons.append(f"netscan: {ext} external connection(s)")
            if demo_overclaim and ext:
                # Over-eager assessment with an unsupported quantity -> gate must catch it.
                out["findings"].append(_finding(
                    title="Assessment: active data exfiltration of ~2.3 GB to C2",
                    desc=("Aggressive analyst assessment that the external channel exfiltrated "
                          "approximately 2.3 GB. The volume is not supported by any captured "
                          "tool output and should be quarantined by the verifier."),
                    evtype=EvidenceType.MEMORY, severity=Severity.CRITICAL,
                    confidence=Confidence.INFERRED, attack=_attack_for("exfil_network"),
                    cited=["2.3 GB"], prov=[_prov(res.tool_exec_id, "mem_netscan", "2.3 GB")],
                    agent=agent))
        elif tool == "mem_malfind":
            for h in s.get("injections", []):
                pid = h.get("pid")
                out["findings"].append(_finding(
                    title=f"Injected/RWX code in PID {pid} ({h.get('process')})",
                    desc=(f"malfind flagged executable private memory ({h.get('protection')}) "
                          f"in PID {pid} '{h.get('process')}' — consistent with code injection."),
                    evtype=EvidenceType.MEMORY, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("process_injection"),
                    cited=[str(pid)], prov=[_prov(res.tool_exec_id, "mem_malfind", pid)],
                    agent=agent))
            reasons.append(f"malfind: {s.get('count', 0)} injection candidate(s)")
        elif tool == "mem_cmdline":
            cmdlines_list = s.get("cmdlines", [])
            for cl in cmdlines_list:
                args = str(cl.get("args", ""))
                low = args.lower()
                hit = next((kw for kw in _PS_ENCODED if kw in low), None)
                if hit:
                    out["findings"].append(_finding(
                        title=f"Suspicious command line in PID {cl.get('pid')} ({cl.get('process')})",
                        desc=f"Command line contains '{hit.strip()}' (obfuscated/encoded execution): {args[:160]}",
                        evtype=EvidenceType.MEMORY, severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED, attack=_attack_for("powershell_encoded"),
                        cited=[hit.strip()], prov=[_prov(res.tool_exec_id, "mem_cmdline", hit.strip())],
                        agent=agent))
            # LOLBAS detection across all command lines
            from glassbox.detect.lolbas import detect_lolbas_abuse
            lolbas_findings = detect_lolbas_abuse(cmdlines_list, res.tool_exec_id)
            out["findings"].extend(lolbas_findings)
            # Store cmdlines for cross-tool correlation (credential + lateral)
            out["view"]["cmdlines"] = cmdlines_list
            out["view"]["cmdline_exec_id"] = res.tool_exec_id
            reasons.append(f"cmdline: {s.get('count', 0)} command lines reviewed ({len(lolbas_findings)} LOLBAS)")
        elif tool == "mem_svcscan":
            for svc in s.get("services", []):
                binp = str(svc.get("binary", "")).lower()
                if any(tok in binp for tok in _SUSP_SVC_PATH):
                    out["findings"].append(_finding(
                        title=f"Suspicious service '{svc.get('name')}'",
                        desc=f"Service binary path looks non-standard: {svc.get('binary')}",
                        evtype=EvidenceType.MEMORY, severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED, attack=_attack_for("service_install"),
                        cited=[str(svc.get("name"))], prov=[_prov(res.tool_exec_id, "mem_svcscan", svc.get("name"))],
                        agent=agent))
            reasons.append(f"svcscan: {s.get('count', 0)} services")
        elif tool == "mem_psxview":
            hidden = s.get("hidden", [])
            for h in hidden:
                missing = h.get("hidden_from", [])
                out["findings"].append(_finding(
                    title=f"[psxview] Process '{h.get('name')}' (PID {h.get('pid')}) hidden from {len(missing)} source(s)",
                    desc=(f"6-source cross-view (psxview) found PID {h.get('pid')} '{h.get('name')}' "
                          f"absent from: {', '.join(missing)}. Indicates DKOM rootkit hiding "
                          f"or deliberate process unlinking."),
                    evtype=EvidenceType.MEMORY, severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("process_hollowing"),
                    cited=[str(h.get("pid"))],
                    prov=[_prov(res.tool_exec_id, "mem_psxview", str(h.get("pid")))],
                    agent=agent))
            reasons.append(f"psxview: {s.get('count',0)} procs, {s.get('hidden_count',0)} hidden")
        elif tool == "mem_handles":
            susp = s.get("suspicious", [])
            for h in susp:
                if h["type"] == "File" and "namedpipe" in h["name"].lower().replace("\\", "").replace(" ", ""):
                    # Use the pipe suffix as locator (avoids backslash JSON-escape mismatch)
                    pipe_suffix = h["name"].rsplit("\\", 1)[-1] if "\\" in h["name"] else h["name"]
                    pipe_suffix = pipe_suffix.rsplit("/", 1)[-1]  # fallback for forward slashes
                    out["findings"].append(_finding(
                        title=f"Suspicious named pipe in PID {h['pid']} ({h['process']}): {pipe_suffix}",
                        desc=(f"Process '{h['process']}' (PID {h['pid']}) holds a handle to named pipe "
                              f"'{h['name']}' matching C2 tool patterns (Cobalt Strike/Metasploit/PsExec). "
                              f"Pipe name suffix: {pipe_suffix}"),
                        evtype=EvidenceType.MEMORY, severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED, attack=_attack_for("http_c2"),
                        cited=[pipe_suffix],
                        prov=[_prov(res.tool_exec_id, "mem_handles", pipe_suffix)],
                        agent=agent))
                elif h["type"] == "Process" and "0x1410" in h.get("granted_access","").lower():
                    out["findings"].append(_finding(
                        title=f"Cross-process PROCESS_VM_READ handle from PID {h['pid']} ({h['process']})",
                        desc=(f"PID {h['pid']} '{h['process']}' holds a Process handle with "
                              f"PROCESS_VM_READ+QUERY_INFO (GrantedAccess={h.get('granted_access')}) — "
                              f"credential dumper pattern."),
                        evtype=EvidenceType.MEMORY, severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED, attack=_attack_for("lsass_dump"),
                        cited=["0x1410"],
                        prov=[_prov(res.tool_exec_id, "mem_handles", "0x1410")],
                        agent=agent))
            reasons.append(f"handles: {s.get('count',0)} total, {s.get('suspicious_count',0)} suspicious")
        elif tool == "mem_cmdscan":
            cmds = s.get("commands", [])
            _SUSP_CMDS = [("net user", "local_account_created", Severity.HIGH, "Backdoor account creation"),
                          ("net localgroup", "local_account_created", Severity.HIGH, "Privilege group modification"),
                          ("certutil", "lolbas_certutil", Severity.HIGH, "LOLBAS certutil tool transfer"),
                          ("reg add", "registry_run_key", Severity.HIGH, "Registry persistence added"),
                          ("DownloadString", "powershell_suspicious", Severity.HIGH, "PowerShell download cradle"),
                          ("IEX", "powershell_suspicious", Severity.HIGH, "PowerShell IEX execution"),
                          ("rar a", "archive_exfil", Severity.HIGH, "Data archived for exfiltration (rar)"),
                          ("7z a", "archive_exfil", Severity.HIGH, "Data archived for exfiltration (7z)"),
                          ("compress-archive", "archive_exfil", Severity.HIGH, "Data archived via PowerShell")]
            for cmd_rec in cmds:
                cmd = str(cmd_rec.get("command", ""))
                for pattern, artifact, sev, desc_prefix in _SUSP_CMDS:
                    if pattern.lower() in cmd.lower():
                        out["findings"].append(_finding(
                            title=f"Attacker command history: {desc_prefix}",
                            desc=f"cmdscan recovered: '{cmd[:160]}'",
                            evtype=EvidenceType.MEMORY, severity=sev,
                            confidence=Confidence.CONFIRMED, attack=_attack_for(artifact),
                            cited=[pattern],
                            prov=[_prov(res.tool_exec_id, "mem_cmdscan", pattern)],
                            agent=agent))
                        break
            reasons.append(f"cmdscan: {s.get('count',0)} commands recovered")
        elif tool == "mem_mutantscan":
            for mut in s.get("suspicious", []):
                out["findings"].append(_finding(
                    title=f"Malware mutex fingerprint: '{mut['name']}'",
                    desc=(f"Named mutex '{mut['name']}' matches known malware family patterns. "
                          f"Mutexes are hard-coded per malware build to prevent re-infection."),
                    evtype=EvidenceType.MEMORY, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("masquerade_rename"),
                    cited=[mut["name"]],
                    prov=[_prov(res.tool_exec_id, "mem_mutantscan", mut["name"])],
                    agent=agent))
            reasons.append(f"mutantscan: {s.get('count',0)} mutexes, {s.get('suspicious_count',0)} suspicious")
        elif tool == "mem_mftscan":
            for rec in s.get("suspicious", []):
                fname = rec.get("filename", "")
                out["findings"].append(_finding(
                    title=f"MFT scan: suspicious executable recovered from memory: {fname.rsplit('/',1)[-1]}",
                    desc=(f"In-memory MFT record found for '{fname}' (created: {rec.get('created')}). "
                          f"File may have been deleted from disk but remains in filesystem cache."),
                    evtype=EvidenceType.MEMORY, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED, attack=_attack_for("masquerade_path"),
                    cited=[fname.rsplit("/",1)[-1]],
                    prov=[_prov(res.tool_exec_id, "mem_mftscan", fname.rsplit("/",1)[-1])],
                    agent=agent))
            reasons.append(f"mftscan: {s.get('count',0)} records, {s.get('suspicious_count',0)} suspicious")
        elif tool == "mem_dlllist":
            _BAD_DLL_NAMES = {"inject.dll", "hook.dll", "payload.dll", "malware.dll"}
            _SUSP_DLL_PATHS = ("\\users\\public\\", "\\appdata\\local\\temp\\", "\\programdata\\")
            for dll in s.get("dlls", []):
                name = str(dll.get("name", "")).lower()
                path = str(dll.get("path", "")).lower()
                if name == "unknown" or (not name and not dll.get("path")):
                    pid = dll.get("pid")
                    out["findings"].append(_finding(
                        title=f"Unknown/unmapped DLL in PID {pid}",
                        desc=f"PID {pid} has a loaded DLL with no mapped filename at base {dll.get('base')} — possible injection.",
                        evtype=EvidenceType.MEMORY, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("process_injection"), cited=[str(pid)],
                        prov=[_prov(res.tool_exec_id, "mem_dlllist", str(pid))], agent=agent))
                elif name in _BAD_DLL_NAMES or any(d in path for d in _SUSP_DLL_PATHS):
                    out["findings"].append(_finding(
                        title=f"Suspicious DLL loaded: {dll.get('name')}",
                        desc=f"DLL '{dll.get('name')}' loaded from suspicious path '{dll.get('path')}' in PID {dll.get('pid')}.",
                        evtype=EvidenceType.MEMORY, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("process_injection"), cited=[dll.get("name", "")],
                        prov=[_prov(res.tool_exec_id, "mem_dlllist", dll.get("name", ""))], agent=agent))
            reasons.append(f"dlllist: {s.get('count', 0)} DLLs")
        elif tool == "yara_scan":
            _TECH_MAP = {
                "Cridex_C2_URL_Pattern": "http_c2", "Cridex_Reader_SL_Masquerade": "masquerade_path",
                "Generic_PE_In_RWX_Region": "process_injection", "Powershell_Encoded_Command": "powershell_encoded",
                "LSASS_Credential_Dump": "lsass_dump",
            }
            for hit in s.get("hits", []):
                rule = hit.get("rule", "")
                artifact = _TECH_MAP.get(rule, "process_injection")
                out["findings"].append(_finding(
                    title=f"YARA match: {rule}",
                    desc=f"YARA rule '{rule}' matched in {hit.get('target', 'evidence')}.",
                    evtype=EvidenceType.MEMORY, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    attack=_attack_for(artifact), cited=[rule],
                    prov=[_prov(res.tool_exec_id, "yara_scan", rule)], agent=agent))
            reasons.append(f"yara_scan: {s.get('count', 0)} match(es)")
    out["rationale"] = "; ".join(reasons)
    return out


# --------------------------------------------------------------------------- #
# EVTX
# --------------------------------------------------------------------------- #
_LEVEL_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "med": Severity.MEDIUM,
              "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}


def run_evtx(toolkit, evidence: str, tools: list[str]) -> SpecialistOutput:
    out = _empty()
    agent = "evtx_analyst"
    reasons = []
    ran_hunt = False
    for tool in tools:
        fn = getattr(toolkit, tool, None)
        if fn is None:
            continue
        res = fn(evidence)
        out["executed"].append(res.tool_exec_id)
        if res.status not in ("OK", "DEGRADED"):
            out["degraded"].append(tool)
            reasons.append(f"{tool} -> {res.status}")
            continue
        s = res.summary
        if tool == "evtx_hunt":
            ran_hunt = True
            for d in s.get("detections", []):
                techs = d.get("techniques", []) or []
                attack = dedupe_mappings(
                    [m for t in techs if (m := technique(t))] + for_event_id(int(d.get("event_id") or 0))
                ) if (techs or d.get("event_id")) else []
                locator = str(d.get("rule") or d.get("computer") or d.get("event_id") or "")
                sev = _LEVEL_SEV.get(str(d.get("level", "")).lower(), Severity.MEDIUM)
                # Special handling for high-value events
                details = str(d.get("details", ""))
                eid = int(d.get("event_id") or 0)
                title = d.get("rule") or f"EventID {eid}"
                desc  = (f"Hayabusa/Sigma matched on {d.get('computer')} "
                         f"(EventID {eid}, {d.get('tactics')}). {details[:200]}")
                # Kerberoasting: 4769 with RC4 encryption type
                if eid == 4769 and ("0x17" in details or "RC4" in details.upper()):
                    title = f"Kerberoasting detected: RC4-encrypted TGS for '{_extract_service(details)}'"
                    desc  = (f"EventID 4769 with TicketEncryptionType=0x17 (RC4-HMAC). "
                             f"RC4 encryption in a modern Kerberos environment indicates Kerberoasting. {details[:160]}")
                    attack = [m for m in attack] + _attack_for("kerberoasting")
                    attack = dedupe_mappings(attack)
                # WMI persistence: 5861 consumer created
                elif eid in (5861, 5859, 5857):
                    title = f"WMI persistence: {title}"
                    attack = dedupe_mappings(attack + _attack_for("wmi_persistence"))
                # Token impersonation: 4624 with LogonType=9
                elif eid == 4624 and "logontype=9" in details.lower().replace(" ", ""):
                    title = f"Token impersonation (LogonType=9): {title}"
                    attack = dedupe_mappings(attack + _attack_for("token_impersonation"))

                out["findings"].append(_finding(
                    title=f"EVTX detection: {title}",
                    desc=desc,
                    evtype=EvidenceType.EVTX, severity=sev, confidence=Confidence.CONFIRMED,
                    attack=attack, cited=[locator],
                    prov=[_prov(res.tool_exec_id, "evtx_hunt", locator)], agent=agent,
                    observed_at=str(d.get("timestamp") or "")))
            reasons.append(f"evtx_hunt: {s.get('count', 0)} detection(s)")
            # Harvest IOCs grounded in the hunt output (paths, IPs, hashes in details)
            for ioc in _harvest_iocs(toolkit, res.tool_exec_id, "evtx_hunt detections"):
                if ioc.type in ("filepath", "regpath", "sha256", "md5", "ipv4"):
                    ioc.provenance[0].raw_locator = ioc.value
                    out.setdefault("iocs", []).append(ioc)
        elif tool in ("evtx_to_json", "evtx_dump_xml"):
            # Map every event ID in the histogram to ATT&CK techniques
            hist = s.get("event_id_histogram", {})
            for eid_str, count in hist.items():
                try:
                    eid = int(eid_str)
                except ValueError:
                    continue
                mappings = for_event_id(eid)
                if not mappings:
                    continue
                out["findings"].append(_finding(
                    title=f"EventID {eid} x{count} — {mappings[0].technique_name[:50]}",
                    desc=(f"Event log shows EventID {eid} occurred {count} time(s). "
                          f"Maps to {', '.join(m.technique_id for m in mappings)}."),
                    evtype=EvidenceType.EVTX, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    attack=mappings, cited=[eid_str],
                    prov=[_prov(res.tool_exec_id, tool, eid_str)], agent=agent))
            # Also map structured events from evtx_to_json parsed events
            for ev in s.get("events", []):
                eid_str = str(ev.get("event_id", ""))
                payload = str(ev.get("payload", "") or ev.get("map_desc", ""))
                if eid_str and payload:
                    # Extract IOCs from payload field
                    for ioc in _harvest_iocs_from_text(payload, eid_str, tool, res.tool_exec_id):
                        out.setdefault("iocs", []).append(ioc)
            # Harvest path IOCs from EVTX raw output
            for ioc in _harvest_iocs(toolkit, res.tool_exec_id, f"{tool} events"):
                if ioc.type in ("filepath", "sha256", "ipv4"):
                    out.setdefault("iocs", []).append(ioc)
            # Credential access + lateral movement detection from structured events
            evs = s.get("events", [])
            if evs:
                # Store for cross-specialist correlation in the correlate node
                out["view"]["evtx_events"] = evs
                out["view"]["evtx_to_json_exec_id"] = res.tool_exec_id
            reasons.append(f"{tool}: {len(evs) or s.get('count', 0)} events")
    out["rationale"] = "; ".join(reasons) or ("no evtx detections" if ran_hunt else "evtx not analyzed")
    return out


# --------------------------------------------------------------------------- #
# DISK
# --------------------------------------------------------------------------- #
def run_disk(toolkit, evidence: str, tools: list[str]) -> SpecialistOutput:
    out = _empty()
    agent = "disk_analyst"
    reasons = []
    offset: Optional[int] = None
    # partition table first so file listings can use the right offset
    for tool in sorted(tools, key=lambda t: 0 if t == "disk_partition_table" else 1):
        fn = getattr(toolkit, tool, None)
        if fn is None:
            continue
        res = fn(evidence) if tool == "disk_partition_table" else fn(evidence, offset=offset)
        out["executed"].append(res.tool_exec_id)
        if res.status not in ("OK", "DEGRADED"):
            out["degraded"].append(tool)
            continue
        s = res.summary
        if tool == "disk_partition_table":
            parts = s.get("partitions", [])
            ntfs = [p for p in parts if "ntfs" in str(p.get("description", "")).lower()]
            if ntfs:
                offset = ntfs[0]["start"]
            if parts:
                out["findings"].append(_finding(
                    title=f"Disk partition table: {len(parts)} partition(s) identified",
                    desc=(f"mmls found {len(parts)} partition(s). "
                          f"{'NTFS at sector ' + str(offset) + '.' if offset else 'No NTFS detected.'} "
                          f"File system enumeration maps to T1083 (File and Directory Discovery)."),
                    evtype=EvidenceType.DISK, severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    attack=_attack_for("file_directory_discovery"),
                    cited=[str(parts[0].get("start", "0"))],
                    prov=[_prov(res.tool_exec_id, "disk_partition_table",
                                str(parts[0].get("start", "0")))],
                    agent=agent))
            reasons.append(f"mmls: {len(parts)} partitions (offset={offset})")
        elif tool == "disk_list_files":
            out["view"]["image_names"] = s.get("image_names", [])
            out["view"]["listing_exec_id"] = res.tool_exec_id
            _SUSP_DIRS = ("\\users\\public\\", "\\programdata\\", "\\appdata\\local\\temp\\",
                          "/users/public/", "/programdata/", "/appdata/local/temp/")
            for f in s.get("files", []):
                name = str(f.get("name", "")).lower()
                path = str(f.get("path", ""))
                path_l = path.lower()
                # Masquerade: system binary outside System32
                if name in _SYS_BINS and "system32" not in path_l and "syswow64" not in path_l and "winsxs" not in path_l:
                    out["findings"].append(_finding(
                        title=f"Masquerade: system binary '{name}' outside System32",
                        desc=f"'{name}' found at non-standard path '{path}'.",
                        evtype=EvidenceType.DISK, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("masquerade_path"), cited=[path],
                        prov=[_prov(res.tool_exec_id, "disk_list_files", path)], agent=agent))
                # Executables dropped in writable user directories (not system bins, just .exe/.dll)
                elif name.endswith((".exe", ".dll")) and name not in _SYS_BINS:
                    if any(d in path_l for d in _SUSP_DIRS):
                        out["findings"].append(_finding(
                            title=f"Executable in suspicious path: {name}",
                            desc=f"Non-standard executable '{path}' found in writable user directory.",
                            evtype=EvidenceType.DISK, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                            attack=_attack_for("masquerade_path"), cited=[path],
                            prov=[_prov(res.tool_exec_id, "disk_list_files", path)], agent=agent))
            # Harvest filepath IOCs from disk listing (suspicious paths)
            for ioc in _harvest_iocs(toolkit, res.tool_exec_id, "disk file listing"):
                if ioc.type == "filepath" and any(d in ioc.value.lower() for d in _SUSP_DIRS):
                    out.setdefault("iocs", []).append(ioc)
            reasons.append(f"fls: {s.get('count', 0)} files ({len(out['view'].get('image_names', []))} images)")
        elif tool == "disk_mft_timeline":
            # bodyfile field index 1 == name (full path), detect suspicious executables
            _SUSP_DIRS_T = ("users/public", "/temp/", "\\temp\\", "programdata", "appdata")
            susp: list[tuple[str, str]] = []
            for entry in s.get("entries", []):
                # 'name' holds the full path in bodyfile format
                path = str(entry.get("name", "")).lower()
                if not path.endswith((".exe", ".dll", ".bat", ".ps1")):
                    continue
                if any(d in path for d in _SUSP_DIRS_T):
                    susp.append((path, entry.get("mtime", "")))
            for path, mtime in susp[:3]:
                fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                out["findings"].append(_finding(
                    title=f"Suspicious executable on disk timeline: {fname}",
                    desc=(f"MFT timeline shows '{path}' (mtime {mtime}) in a writable/temp directory. "
                          f"Consistent with dropper activity."),
                    evtype=EvidenceType.DISK, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    attack=_attack_for("masquerade_path"), cited=[fname],
                    prov=[_prov(res.tool_exec_id, "disk_mft_timeline", fname)], agent=agent))
            # Even with 0 suspicious, emit a timeline coverage finding
            if s.get("count", 0) > 0 and not susp:
                out["findings"].append(_finding(
                    title=f"MFT timeline: {s.get('count')} entries analysed — no suspicious executables",
                    desc="Filesystem timeline reviewed. No executables in writable paths detected.",
                    evtype=EvidenceType.DISK, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
                    attack=_attack_for("file_directory_discovery"),
                    cited=[str(s.get("count", 0))],
                    prov=[_prov(res.tool_exec_id, "disk_mft_timeline", str(s.get("count", 0)))],
                    agent=agent))
            reasons.append(f"timeline: {s.get('count', 0)} entries ({len(susp)} suspicious)")
    out["rationale"] = "; ".join(reasons)
    return out


# --------------------------------------------------------------------------- #
# NETWORK
# --------------------------------------------------------------------------- #
def run_network(toolkit, evidence: str, tools: list[str]) -> SpecialistOutput:
    out = _empty()
    agent = "network_analyst"
    reasons = []
    for tool in tools:
        fn = getattr(toolkit, tool, None)
        if fn is None:
            continue
        res = fn(evidence)
        out["executed"].append(res.tool_exec_id)
        if res.status not in ("OK", "DEGRADED"):
            out["degraded"].append(tool)
            continue
        s = res.summary
        rows = s.get("rows", [])
        # grounded IOCs from this execution's captured output
        ioc_dump = toolkit.ioc_extract(res.tool_exec_id).get("iocs", [])
        iocs = [IOC(**i) for i in ioc_dump]
        if tool == "pcap_dns":
            for r in rows:
                q = str(r.get("dns.qry.name", "")).strip()
                if q and ("." in q):
                    out["findings"].append(_finding(
                        title=f"DNS query: {q}",
                        desc=f"DNS query observed from {r.get('ip.src')} for {q}.",
                        evtype=EvidenceType.PCAP, severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("dns_c2"), cited=[q],
                        prov=[_prov(res.tool_exec_id, "pcap_dns", q)], agent=agent))
        elif tool in ("pcap_conn_summary", "pcap_http"):
            ext = set()
            for r in rows:
                dst = str(r.get("ip.dst", "")).strip()
                if _routable(dst):
                    ext.add(dst)
            for dst in sorted(ext):
                out["findings"].append(_finding(
                    title=f"External destination {dst}",
                    desc=f"Network capture shows traffic to external host {dst}.",
                    evtype=EvidenceType.PCAP, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                    attack=_attack_for("http_c2"), cited=[dst],
                    prov=[_prov(res.tool_exec_id, tool, dst)], agent=agent))
        # attach extracted IOCs to a low-noise summary finding
        if iocs:
            out["findings"].append(_finding(
                title=f"{len(iocs)} network IOC(s) from {tool}",
                desc="Indicators extracted from captured network output (grounded).",
                evtype=EvidenceType.PCAP, severity=Severity.INFO, confidence=Confidence.CONFIRMED,
                attack=[], cited=[iocs[0].value],
                prov=[_prov(res.tool_exec_id, "ioc_extract", iocs[0].value)], agent=agent, iocs=iocs))
        reasons.append(f"{tool}: {s.get('count', 0)} rows")
    out["rationale"] = "; ".join(reasons)
    return out


def run_registry(toolkit, evidence: str, tools: list[str]) -> SpecialistOutput:
    """Registry analyst: detect persistence keys, service installs, evidence of execution."""
    out = _empty()
    agent = "registry_analyst"
    reasons = []
    for tool in tools:
        fn = getattr(toolkit, tool, None)
        if fn is None:
            continue
        res = fn(evidence)
        out["executed"].append(res.tool_exec_id)
        if res.status not in ("OK", "DEGRADED"):
            out["degraded"].append(tool)
            reasons.append(f"{tool} -> {res.status}")
            continue
        s = res.summary
        for section in s.get("sections", []):
            plugin = str(section.get("plugin", "")).lower()
            for entry in section.get("entries", []):
                key = str(entry.get("key", "")).lower()
                value = str(entry.get("value", ""))
                value_l = value.lower()
                last_write = entry.get("last_write", "")
                # Run key / autorun persistence
                if "run" in plugin or "run" in key or "autorun" in plugin:
                    if any(c in value_l for c in ("\\users\\public\\", "\\temp\\", "\\appdata\\")):
                        out["findings"].append(_finding(
                            title=f"Persistence: Run key pointing to suspicious path",
                            desc=f"Registry Run key '{key}' = '{value}' (last write: {last_write}). "
                                 f"Executable in writable user directory — classic persistence mechanism.",
                            evtype=EvidenceType.REGISTRY if hasattr(EvidenceType, 'REGISTRY') else EvidenceType.DISK,
                            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                            attack=_attack_for("registry_run_key"),
                            cited=[value],
                            prov=[_prov(res.tool_exec_id, "registry_analyze", value)],
                            agent=agent, observed_at=last_write))
                        out.setdefault("iocs", []).extend(
                            _harvest_iocs_from_text(value, value, "registry_analyze", res.tool_exec_id))
                # Service entries pointing to suspicious paths
                elif "service" in plugin:
                    if "imagepath" in key and any(d in value_l for d in ("\\users\\", "\\temp\\", "\\public\\")):
                        out["findings"].append(_finding(
                            title=f"Malicious service ImagePath in registry",
                            desc=f"Service registry entry ImagePath='{value}' in suspicious path. "
                                 f"(last write: {last_write}). Consistent with T1543.003.",
                            evtype=EvidenceType.REGISTRY if hasattr(EvidenceType, 'REGISTRY') else EvidenceType.DISK,
                            severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                            attack=_attack_for("service_install"),
                            cited=[value],
                            prov=[_prov(res.tool_exec_id, "registry_analyze", value)],
                            agent=agent, observed_at=last_write))
                # Query registry discovery finding
                elif "recentdocs" in plugin or "userassist" in plugin:
                    out["findings"].append(_finding(
                        title=f"Registry execution evidence: {plugin}",
                        desc=f"Registry key '{key}' = '{value}' (last write: {last_write}). "
                             f"Evidence of recent file access / program execution.",
                        evtype=EvidenceType.REGISTRY if hasattr(EvidenceType, 'REGISTRY') else EvidenceType.DISK,
                        severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("query_registry"),
                        cited=[key],
                        prov=[_prov(res.tool_exec_id, "registry_analyze", key)],
                        agent=agent))
        reasons.append(f"registry_analyze: {s.get('count', 0)} entries")
    out["rationale"] = "; ".join(reasons)
    return out


SPECIALISTS = {
    "memory_analyst": run_memory,
    "evtx_analyst": run_evtx,
    "disk_analyst": run_disk,
    "network_analyst": run_network,
    "registry_analyst": run_registry,
}
