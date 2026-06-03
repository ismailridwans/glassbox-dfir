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


def _prov(exec_id: str, tool: str, locator, note: str = "") -> Provenance:
    return Provenance(tool_exec_id=exec_id, tool=tool, raw_locator=str(locator), note=note)


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

        if tool in ("mem_pslist", "mem_pstree"):
            out["view"]["pslist"] = s.get("processes", [])
            out["view"]["pslist_exec_id"] = res.tool_exec_id
            reasons.append(f"pslist: {s.get('count', 0)} active processes")
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
            for cl in s.get("cmdlines", []):
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
            reasons.append(f"cmdline: {s.get('count', 0)} command lines reviewed")
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
                out["findings"].append(_finding(
                    title=f"EVTX detection: {d.get('rule') or 'event ' + str(d.get('event_id'))}",
                    desc=(f"Hayabusa/Sigma matched on {d.get('computer')} "
                          f"(EventID {d.get('event_id')}, {d.get('tactics')}). {str(d.get('details'))[:160]}"),
                    evtype=EvidenceType.EVTX, severity=sev, confidence=Confidence.CONFIRMED,
                    attack=attack, cited=[locator],
                    prov=[_prov(res.tool_exec_id, "evtx_hunt", locator)], agent=agent,
                    observed_at=str(d.get("timestamp") or "")))
            reasons.append(f"evtx_hunt: {s.get('count', 0)} detection(s)")
        elif tool in ("evtx_to_json", "evtx_dump_xml"):
            hist = s.get("event_id_histogram", {})
            if "1102" in hist:
                out["findings"].append(_finding(
                    title="Windows event log cleared (EventID 1102)",
                    desc="Security event log clearing observed — common anti-forensic / defense-evasion action.",
                    evtype=EvidenceType.EVTX, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    attack=_attack_for("clear_event_log"), cited=["1102"],
                    prov=[_prov(res.tool_exec_id, tool, "1102")], agent=agent))
            reasons.append(f"{tool}: {s.get('count', 0)} events")
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
            reasons.append(f"mmls: {len(parts)} partitions (offset={offset})")
        elif tool == "disk_list_files":
            out["view"]["image_names"] = s.get("image_names", [])
            out["view"]["listing_exec_id"] = res.tool_exec_id
            for f in s.get("files", []):
                name = str(f.get("name", "")).lower()
                path = str(f.get("path", "")).lower()
                if name in _SYS_BINS and "system32" not in path and "syswow64" not in path and "winsxs" not in path:
                    out["findings"].append(_finding(
                        title=f"Masquerade: system binary '{name}' outside System32",
                        desc=f"'{name}' found at non-standard path '{f.get('path')}'.",
                        evtype=EvidenceType.DISK, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        attack=_attack_for("masquerade_path"), cited=[f.get("path")],
                        prov=[_prov(res.tool_exec_id, "disk_list_files", f.get("path"))], agent=agent))
            reasons.append(f"fls: {s.get('count', 0)} files ({len(out['view'].get('image_names', []))} images)")
        elif tool == "disk_mft_timeline":
            reasons.append(f"timeline: {s.get('count', 0)} entries")
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


SPECIALISTS = {
    "memory_analyst": run_memory,
    "evtx_analyst": run_evtx,
    "disk_analyst": run_disk,
    "network_analyst": run_network,
}
