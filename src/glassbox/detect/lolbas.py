"""LOLBAS (Living-Off-The-Land Binaries and Scripts) abuse detection.

Parses command lines and EVTX event data to surface abuse of built-in Windows
tools. Each pattern maps directly to a MITRE ATT&CK technique.
"""

from __future__ import annotations

import re
from typing import Any

from glassbox.models import AttackMapping, Confidence, EvidenceType, Finding, Provenance, Severity
from glassbox.util import stable_id

# (binary_name, suspicious_pattern, technique_ids, description)
_LOLBAS_RULES: list[tuple[str, re.Pattern, list[str], str]] = [
    ("certutil.exe", re.compile(r"-url|-decode|-encode|-urlcache|-split", re.I),
     ["T1140", "T1105"], "certutil used for download/decode — common dropper pattern"),
    ("regsvr32.exe", re.compile(r"\/s\s.+\.(sct|dll)", re.I),
     ["T1218.010"], "regsvr32 /s executing script/DLL — Squiblydoo bypass"),
    ("mshta.exe", re.compile(r"http|\.sct|vbscript|javascript", re.I),
     ["T1218.005"], "mshta executing remote/inline script"),
    ("wscript.exe", re.compile(r"\.js|\.vbs|\.wsf", re.I),
     ["T1059.005"], "wscript executing script file"),
    ("cscript.exe", re.compile(r"\.js|\.vbs|\.wsf", re.I),
     ["T1059.005"], "cscript executing script file"),
    ("bitsadmin.exe", re.compile(r"/transfer|/download|/addfile", re.I),
     ["T1197"], "bitsadmin downloading/transferring files"),
    ("msiexec.exe", re.compile(r"/q.*/i\s+http|msiexec.*http", re.I),
     ["T1218.007"], "msiexec installing MSI from remote URL"),
    ("rundll32.exe", re.compile(r"javascript:|shell32\.dll.*ShellExec|advpack|ieadvpack", re.I),
     ["T1218.011"], "rundll32 executing non-DLL or inline script"),
    ("powershell.exe", re.compile(r"-w\s*hidden|\-nop|\-exec\s+bypass|invoke-expression|iex\s|downloadstring", re.I),
     ["T1059.001"], "PowerShell evasion flags or download cradle"),
    ("cmd.exe", re.compile(r"/c\s+.*(\|\s*regsvr32|certutil|bitsadmin|mshta)", re.I),
     ["T1059.003"], "cmd.exe chaining to LOLBAS tool"),
    ("wmic.exe", re.compile(r"process\s+call\s+create|/node:\s*\d+\.\d+", re.I),
     ["T1047"], "WMIC remote process creation"),
]

# Mapping technique_id -> (name, tactics) for techniques not in core mapping table
_EXTRA_TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1105": ("Ingress Tool Transfer", ["TA0002"]),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["TA0005"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["TA0005"]),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", ["TA0002"]),
    "T1197": ("BITS Jobs", ["TA0003", "TA0005"]),
    "T1218.007": ("System Binary Proxy Execution: Msiexec", ["TA0005"]),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ["TA0005"]),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", ["TA0002"]),
}


def _make_mapping(technique_id: str) -> AttackMapping:
    from glassbox.attack.mapping import technique as lookup
    m = lookup(technique_id)
    if m:
        return m
    extra = _EXTRA_TECHNIQUES.get(technique_id)
    if extra:
        from glassbox.attack.attack_data import TACTIC_NAME
        return AttackMapping(
            technique_id=technique_id,
            technique_name=extra[0],
            tactic_ids=extra[1],
            tactic_names=[TACTIC_NAME.get(t, t) for t in extra[1]],
            source="lolbas",
            confidence=Confidence.CONFIRMED,
        )
    return AttackMapping(technique_id=technique_id, technique_name="(see attack.mitre.org)",
                         source="lolbas")


def detect_lolbas_abuse(
    cmdlines: list[dict[str, Any]],
    tool_exec_id: str,
) -> list[Finding]:
    """Detect LOLBAS abuse in a list of process command lines.

    ``cmdlines`` is the ``cmdlines`` list from a ``mem_cmdline`` parsed summary:
    ``[{"pid": int, "process": str, "args": str}, ...]``
    """
    findings: list[Finding] = []
    for cl in cmdlines:
        args = str(cl.get("args", ""))
        args_l = args.lower()
        proc = str(cl.get("process", "")).lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        pid = cl.get("pid")
        for binary, pattern, techs, desc in _LOLBAS_RULES:
            if proc != binary.lower():
                continue
            if not pattern.search(args):
                continue
            mappings = [_make_mapping(t) for t in techs]
            fid = stable_id("F", "lolbas", binary, str(pid), args[:40])
            findings.append(Finding(
                finding_id=fid,
                title=f"LOLBAS abuse: {binary} (PID {pid})",
                description=f"{desc}. Command: {args[:200]}",
                evidence_type=EvidenceType.MEMORY,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                attack=mappings,
                cited_values=[binary],
                provenance=[Provenance(
                    tool_exec_id=tool_exec_id,
                    tool="mem_cmdline",
                    raw_locator=binary,
                    note=f"LOLBAS: {binary}"
                )],
                source_agent="lolbas_detector",
            ))
            break  # one rule per process
    return findings
