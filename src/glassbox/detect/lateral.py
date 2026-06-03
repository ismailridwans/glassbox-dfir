"""Lateral movement detection from EVTX logon events and network connections."""

from __future__ import annotations

from typing import Any

from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
from glassbox.util import stable_id

# Logon type -> (technique_id, description)
_LOGON_TYPES: dict[int, tuple[str, str]] = {
    3:  ("T1021.002", "Network logon (Type 3) — possible SMB/admin-share lateral movement"),
    10: ("T1021.001", "Remote interactive logon (Type 10) — RDP lateral movement"),
    4:  ("T1078",     "Batch logon (Type 4) — possible scheduled-task lateral movement"),
}

# Suspicious source processes for remote execution
_REMOTE_EXEC_INDICATORS = [
    ("psexesvc", "T1569.002", "PsExec service running — remote service execution"),
    ("schtasks /create /s", "T1053.005", "Remote scheduled task creation"),
    ("sc \\\\", "T1543.003", "Remote service creation (sc \\\\host)"),
    ("wmic /node:", "T1047", "WMIC remote execution"),
    ("winrm", "T1021.006", "WinRM remote management"),
]


def detect_lateral_movement(
    evtx_events: list[dict[str, Any]],
    cmdlines: list[dict[str, Any]],
    evtx_exec_id: str,
    cmdline_exec_id: str,
) -> list[Finding]:
    """Detect lateral movement patterns in EVTX logon events and command lines."""
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for ev in evtx_events:
        eid_raw = ev.get("event_id") or ev.get("EventId", "")
        try:
            eid = int(eid_raw)
        except (TypeError, ValueError):
            continue
        if eid not in (4624, 4625, 4648):
            continue
        payload = str(ev.get("payload") or ev.get("PayloadData1", "")).lower()
        logon_type = None
        for lt in (3, 10, 4):
            if f"logon type: {lt}" in payload or f"logontype: {lt}" in payload or f"type {lt}" in payload:
                logon_type = lt
                break
        if logon_type is None:
            continue
        tech_id, title = _LOGON_TYPES.get(logon_type, (None, None))
        if not tech_id:
            continue
        key = (eid, logon_type, ev.get("computer", ""))
        if key in seen:
            continue
        seen.add(key)
        from glassbox.attack.mapping import technique as lookup
        m = lookup(tech_id)
        findings.append(Finding(
            finding_id=stable_id("F", "lateral", str(eid), str(logon_type)),
            title=f"{title} (EventID {eid})",
            description=(f"Logon type {logon_type} on {ev.get('computer','unknown')}. "
                         f"User: {ev.get('user','?')}. {payload[:120]}"),
            evidence_type=EvidenceType.EVTX,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            attack=[m] if m else [],
            cited_values=[str(eid)],
            provenance=[Provenance(tool_exec_id=evtx_exec_id, tool="evtx_to_json",
                                   raw_locator=str(eid))],
            source_agent="lateral_detector",
        ))

    # Cmdline-based remote execution
    for cl in cmdlines:
        args_l = str(cl.get("args", "")).lower()
        for pattern, tech_id, desc in _REMOTE_EXEC_INDICATORS:
            if pattern.lower() in args_l:
                from glassbox.attack.mapping import technique as lookup
                m = lookup(tech_id)
                k = (pattern, str(cl.get("pid")))
                if k in seen:
                    continue
                seen.add(k)
                findings.append(Finding(
                    finding_id=stable_id("F", "lateral_cmd", pattern, str(cl.get("pid"))),
                    title=f"Remote execution indicator: {pattern.split()[0]} (PID {cl.get('pid')})",
                    description=f"{desc}. Command: {str(cl.get('args',''))[:200]}",
                    evidence_type=EvidenceType.MEMORY,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    attack=[m] if m else [],
                    cited_values=[pattern],
                    provenance=[Provenance(tool_exec_id=cmdline_exec_id, tool="mem_cmdline",
                                           raw_locator=pattern)],
                    source_agent="lateral_detector",
                ))
                break
    return findings
