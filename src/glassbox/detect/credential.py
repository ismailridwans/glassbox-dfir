"""Credential access detection from EVTX events and memory artifacts."""

from __future__ import annotations

from typing import Any

from glassbox.models import AttackMapping, Confidence, EvidenceType, Finding, Provenance, Severity
from glassbox.util import stable_id

# EventID -> (artifact_key, title, technique_ids)
_CRED_EVENTS: dict[int, tuple[str, str, list[str]]] = {
    4648: ("remote_logon_ntlm", "Explicit credential use (Event 4648) — possible pass-the-hash",
           ["T1550.002"]),
    4771: ("password_spray", "Kerberos pre-auth failure (Event 4771) — password spray / brute force",
           ["T1110.003"]),
    4768: ("pass_the_hash", "Kerberos TGT request with RC4 encryption — possible overpass-the-hash",
           ["T1550.002"]),
    4769: ("pass_the_hash", "Kerberos TGS request with RC4 — possible pass-the-ticket",
           ["T1550.002"]),
    4776: ("remote_logon_ntlm", "NTLM authentication attempt (Event 4776)",
           ["T1550.002", "T1078"]),
}

# In-memory strings indicating LSASS dump
_LSASS_STRINGS = [
    ("sekurlsa", "T1003.001", "Mimikatz sekurlsa module — LSASS credential dump"),
    ("procdump -ma lsass", "T1003.001", "procdump targeting LSASS — credential dump"),
    ("lsass.dmp", "T1003.001", "LSASS memory dump file reference"),
    ("NtReadVirtualMemory", "T1003.001", "NtReadVirtualMemory against LSASS — credential dump"),
    ("nanodump", "T1003.001", "nanodump LSASS credential dump tool"),
    ("comsvcs.dll,mini", "T1003.001", "MiniDump via comsvcs.dll — LSASS credential dump"),
]


def detect_credential_access(
    evtx_events: list[dict[str, Any]],
    cmdlines: list[dict[str, Any]],
    evtx_exec_id: str,
    cmdline_exec_id: str,
) -> list[Finding]:
    """Detect credential access from EVTX events and process command lines."""
    findings: list[Finding] = []

    # EVTX-based credential detections
    seen_eids: set[int] = set()
    for ev in evtx_events:
        eid_raw = ev.get("event_id") or ev.get("EventId", "")
        try:
            eid = int(eid_raw)
        except (TypeError, ValueError):
            continue
        if eid in seen_eids or eid not in _CRED_EVENTS:
            continue
        seen_eids.add(eid)
        _, title, techs = _CRED_EVENTS[eid]
        from glassbox.attack.mapping import technique as lookup
        mappings = [m for t in techs if (m := lookup(t))]
        findings.append(Finding(
            finding_id=stable_id("F", "cred", str(eid)),
            title=title,
            description=(f"EventID {eid} detected in EVTX. "
                         f"User: {ev.get('user') or ev.get('UserName', 'unknown')}. "
                         f"Detail: {str(ev.get('payload') or ev.get('PayloadData1', ''))[:120]}"),
            evidence_type=EvidenceType.EVTX,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            attack=mappings,
            cited_values=[str(eid)],
            provenance=[Provenance(tool_exec_id=evtx_exec_id, tool="evtx_to_json",
                                   raw_locator=str(eid))],
            source_agent="credential_detector",
        ))

    # Command-line-based LSASS dump detection
    for cl in cmdlines:
        args_l = str(cl.get("args", "")).lower()
        for pattern, tech_id, desc in _LSASS_STRINGS:
            if pattern.lower() in args_l:
                from glassbox.attack.mapping import technique as lookup
                m = lookup(tech_id)
                findings.append(Finding(
                    finding_id=stable_id("F", "lsass_dump", pattern, str(cl.get("pid"))),
                    title=f"Credential dump indicator in PID {cl.get('pid')}",
                    description=f"{desc}. Command: {str(cl.get('args',''))[:200]}",
                    evidence_type=EvidenceType.MEMORY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    attack=[m] if m else [],
                    cited_values=[pattern],
                    provenance=[Provenance(tool_exec_id=cmdline_exec_id, tool="mem_cmdline",
                                           raw_locator=pattern)],
                    source_agent="credential_detector",
                ))
                break

    return findings
