"""Parsers: raw SIFT tool output -> compact structured summaries.

Parsing happens in the MCP server (server-side), exactly as the hackathon's
Custom-MCP-Server pattern prescribes: "The MCP server handles raw tool output
natively and can parse it before returning to the LLM, preventing context
window overload from massive text dumps." The model receives normalized rows,
never a 40 MB ``fls`` listing.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional


def _first(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
        # case-insensitive fallback
        for dk in d:
            if dk.lower() == k.lower() and d[dk] not in (None, ""):
                return d[dk]
    return default


def _load_rows(raw: str) -> list[dict]:
    """Volatility 3 ``-r json`` emits a JSON array; tolerate JSONL too."""
    raw = raw.strip()
    if not raw:
        return []
    try:
        obj = json.loads(raw)
        if isinstance(obj, list):
            return [r for r in obj if isinstance(r, dict)]
        if isinstance(obj, dict):
            return [obj]
    except json.JSONDecodeError:
        pass
    rows: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    rows.append(o)
            except json.JSONDecodeError:
                continue
    return rows


# --------------------------------------------------------------------------- #
# Memory (Volatility 3 JSON)
# --------------------------------------------------------------------------- #
def normalize_processes(raw: str) -> dict:
    rows = _load_rows(raw)
    procs = []
    for r in rows:
        pid = _first(r, "PID", "Pid")
        if pid is None:
            continue
        procs.append(
            {
                "pid": int(pid),
                "ppid": int(_first(r, "PPID", "Ppid", default=-1) or -1),
                "name": _first(r, "ImageFileName", "Process", "Name", "ImageName", default=""),
                "create_time": _first(r, "CreateTime", "Created", default=None),
            }
        )
    return {"count": len(procs), "processes": procs}


def normalize_netscan(raw: str) -> dict:
    rows = _load_rows(raw)
    conns = []
    for r in rows:
        conns.append(
            {
                "pid": int(_first(r, "PID", "Pid", default=-1) or -1),
                "owner": _first(r, "Owner", default=""),
                "proto": _first(r, "Proto", "Protocol", default=""),
                "laddr": _first(r, "LocalAddr", "LocalAddress", default=""),
                "lport": _first(r, "LocalPort", default=""),
                "raddr": _first(r, "ForeignAddr", "ForeignAddress", default=""),
                "rport": _first(r, "ForeignPort", default=""),
                "state": _first(r, "State", default=""),
            }
        )
    return {"count": len(conns), "connections": conns}


def normalize_malfind(raw: str) -> dict:
    rows = _load_rows(raw)
    hits = []
    for r in rows:
        hits.append(
            {
                "pid": int(_first(r, "PID", "Pid", default=-1) or -1),
                "process": _first(r, "Process", "ImageFileName", default=""),
                "protection": _first(r, "Protection", default=""),
                "start_vpn": _first(r, "Start VPN", "Start", "Address", default=""),
            }
        )
    return {"count": len(hits), "injections": hits}


def normalize_cmdline(raw: str) -> dict:
    rows = _load_rows(raw)
    cmds = []
    for r in rows:
        cmds.append(
            {
                "pid": int(_first(r, "PID", "Pid", default=-1) or -1),
                "process": _first(r, "Process", "ImageFileName", default=""),
                "args": _first(r, "Args", "CommandLine", default=""),
            }
        )
    return {"count": len(cmds), "cmdlines": cmds}


def normalize_svcscan(raw: str) -> dict:
    rows = _load_rows(raw)
    svcs = []
    for r in rows:
        svcs.append(
            {
                "pid": _first(r, "PID", "Pid", default=None),
                "name": _first(r, "Name", "ServiceName", default=""),
                "display": _first(r, "Display", "DisplayName", default=""),
                "binary": _first(r, "Binary", "BinaryPath", "Binary Path", default=""),
                "state": _first(r, "State", default=""),
                "start": _first(r, "Start", default=""),
            }
        )
    return {"count": len(svcs), "services": svcs}


def normalize_psxview(raw: str) -> dict:
    """Parse windows.malware.psxview output — 6-source cross-view.
    Each row has presence flags across pslist/psscan/csrss/session/deskthrd/handles.
    A process missing from ANY source (False in that column) is suspicious."""
    rows = _load_rows(raw)
    procs = []
    for r in rows:
        pid = _first(r, "PID", "Pid")
        if pid is None:
            continue
        sources = {
            "pslist":   _first(r, "pslist",   default="False"),
            "psscan":   _first(r, "psscan",   default="False"),
            "csrss":    _first(r, "csrss",    default="False"),
            "session":  _first(r, "session",  default="False"),
            "deskthrd": _first(r, "deskthrd", default="False"),
            "handles":  _first(r, "handles",  default="False"),
        }
        # Count how many sources see this process
        seen_count = sum(1 for v in sources.values() if str(v).lower() == "true")
        missing = [k for k, v in sources.items() if str(v).lower() != "true"]
        procs.append({
            "pid": int(pid),
            "name": _first(r, "ImageFileName", "Process", "Name", default=""),
            "sources": sources,
            "seen_in": seen_count,
            "hidden_from": missing,
            "is_hidden": len(missing) > 0,
        })
    hidden = [p for p in procs if p["is_hidden"]]
    return {"count": len(procs), "processes": procs, "hidden_count": len(hidden), "hidden": hidden}


def normalize_handles(raw: str) -> dict:
    """Parse windows.handles.Handles — open handles per process.
    Focus on: File handles to named pipes (C2), cross-process handles (injection),
    Section handles (DLL injection via mapping), Key handles (persistence registry)."""
    rows = _load_rows(raw)
    handles = []
    # Suspicious named pipe patterns (Cobalt Strike, Metasploit, PsExec)
    _SUSP_PIPES = ["\\MSSE-", "\\msagent_", "\\postex_", "\\status_", "\\PSEXESVC",
                   "\\msf-pipe", "\\paexec", "\\svcctl", "\\samr", "\\wkssvc"]
    for r in rows:
        htype = str(_first(r, "Type", default=""))
        name  = str(_first(r, "Name", default=""))
        pid   = int(_first(r, "PID", "Pid", default=-1) or -1)
        access = str(_first(r, "GrantedAccess", default=""))
        is_susp = (
            (htype == "File" and any(p.lower() in name.lower() for p in _SUSP_PIPES)) or
            (htype == "Process" and "0x1410" in access.lower()) or  # PROCESS_VM_READ on another proc
            (htype == "Section" and "lsass" in name.lower())
        )
        handles.append({
            "pid": pid,
            "process": str(_first(r, "Process", default="")),
            "type": htype,
            "name": name,
            "granted_access": access,
            "suspicious": is_susp,
        })
    suspicious = [h for h in handles if h["suspicious"]]
    return {"count": len(handles), "handles": handles[:500],  # cap to avoid context flood
            "suspicious_count": len(suspicious), "suspicious": suspicious}


def normalize_cmdscan(raw: str) -> dict:
    """Parse windows.cmdscan.CmdScan — attacker command history from COMMAND_HISTORY."""
    rows = _load_rows(raw)
    cmds = []
    for r in rows:
        cmd = str(_first(r, "Command", "cmd", "CommandLine", default="")).strip()
        if cmd:
            cmds.append({
                "pid": int(_first(r, "PID", "Pid", default=-1) or -1),
                "process": str(_first(r, "Process", "ImageFileName", default="")),
                "command": cmd,
            })
    return {"count": len(cmds), "commands": cmds}


def normalize_consoles(raw: str) -> dict:
    """Parse windows.consoles.Consoles — full console screen buffer."""
    rows = _load_rows(raw)
    entries = []
    for r in rows:
        buf = str(_first(r, "ScreenBuffer", "Buffer", "Output", "ConsoleInput", default="")).strip()
        if buf:
            entries.append({
                "pid": int(_first(r, "PID", "Pid", default=-1) or -1),
                "process": str(_first(r, "Process", default="")),
                "buffer": buf[:2000],  # cap buffer size
            })
    return {"count": len(entries), "consoles": entries}


def normalize_mutantscan(raw: str) -> dict:
    """Parse windows.mutantscan.MutantScan — named mutex enumeration."""
    # Known malware mutex patterns
    _MALWARE_MUTEXES = [
        "avira_2109", "avira", "cridex", "dridex", "zeus", "citadel",
        "conficker", "waledac", "sality", "gamarue", "emotet", "trickbot",
        "{b9ef4ac8", "winnti", "cobalt", "msf-",
    ]
    rows = _load_rows(raw)
    mutexes = []
    for r in rows:
        name = str(_first(r, "Name", default="")).strip()
        name_lower = name.lower()
        is_susp = (
            name and
            any(m in name_lower for m in _MALWARE_MUTEXES)
        )
        if name:  # skip unnamed mutexes to reduce noise
            mutexes.append({
                "name": name,
                "suspicious": is_susp,
                "cid": str(_first(r, "CID", default="")),
            })
    suspicious = [m for m in mutexes if m["suspicious"]]
    return {"count": len(mutexes), "mutexes": mutexes, "suspicious": suspicious,
            "suspicious_count": len(suspicious)}


def normalize_mftscan(raw: str) -> dict:
    """Parse windows.mftscan.MFTScan — in-memory MFT records (recovers deleted files)."""
    rows = _load_rows(raw)
    records = []
    # Use partial substrings without leading slash so paths like "Users/Public/x.exe" match
    _SUSP_DIRS = ["temp/", "temp\\", "appdata/", "appdata\\",
                  "users/public/", "users\\public\\", "programdata/", "programdata\\"]
    for r in rows:
        fname = str(_first(r, "Filename", "FileName", "File Name", default="")).strip()
        created = str(_first(r, "Created", default=""))
        modified = str(_first(r, "Modified", "Modified0x10", default=""))
        rec_type = str(_first(r, "Record Type", "RecordType", default=""))
        fname_lower = fname.lower()
        is_susp = (
            fname_lower.endswith((".exe", ".dll", ".bat", ".ps1", ".vbs")) and
            any(d in fname_lower for d in _SUSP_DIRS)
        )
        if fname:
            records.append({
                "filename": fname,
                "record_type": rec_type,
                "created": created,
                "modified": modified,
                "suspicious": is_susp,
            })
    suspicious = [r for r in records if r.get("suspicious")]
    return {"count": len(records), "records": records[:200], "suspicious": suspicious,
            "suspicious_count": len(suspicious)}


# --------------------------------------------------------------------------- #
# Disk (Sleuth Kit text)
# --------------------------------------------------------------------------- #
_MMLS = re.compile(r"^\s*(\d+):\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")


def parse_mmls(raw: str) -> dict:
    parts = []
    for line in raw.splitlines():
        m = _MMLS.match(line)
        if m:
            parts.append(
                {
                    "slot": int(m.group(1)),
                    "start": int(m.group(2)),
                    "end": int(m.group(3)),
                    "length": int(m.group(4)),
                    "description": m.group(5).strip(),
                }
            )
    return {"count": len(parts), "partitions": parts}


# fls -r -p output: "r/r 38003-128-3:\tWindows/System32/cmd.exe"
_FLS = re.compile(r"^\s*([d\-r])/([d\-r])\s+\*?\s*([0-9\-]+):\s+(.*)$")


def parse_fls(raw: str, *, limit: int = 5000) -> dict:
    files = []
    names: set[str] = set()
    truncated = False
    for line in raw.splitlines():
        m = _FLS.match(line)
        if not m:
            continue
        if len(files) >= limit:
            truncated = True
            break
        path = m.group(4).strip()
        base = path.rsplit("/", 1)[-1]
        files.append({"type": m.group(2), "inode": m.group(3), "path": path, "name": base})
        if base:
            names.add(base.lower())
    return {
        "count": len(files),
        "files": files,
        "image_names": sorted(n for n in names if n.endswith((".exe", ".dll", ".sys"))),
        "truncated": truncated,
    }


# mactime/bodyfile: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
def parse_bodyfile(raw: str, *, limit: int = 20000) -> dict:
    rows = []
    for i, line in enumerate(raw.splitlines()):
        if i >= limit:
            break
        f = line.split("|")
        if len(f) >= 11:
            rows.append(
                {
                    "name": f[1],
                    "inode": f[2],
                    "size": f[6],
                    "mtime": f[8],
                    "ctime": f[9],
                    "crtime": f[10],
                }
            )
    return {"count": len(rows), "entries": rows}


# --------------------------------------------------------------------------- #
# EVTX
# --------------------------------------------------------------------------- #
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def parse_hayabusa_json(raw: str) -> dict:
    rows = _load_rows(raw)
    detections = []
    for r in rows:
        tactics = _first(r, "MitreTactics", "MITRE Tactics", default="")
        tags = _first(r, "MitreTags", "MITRE Tags", "Tags", default="")
        details_blob = json.dumps(r, default=str)
        techniques = sorted(set(_TECH.findall(str(tags) + " " + details_blob)))
        detections.append(
            {
                "timestamp": _first(r, "Timestamp", "Time", default=""),
                "computer": _first(r, "Computer", default=""),
                "channel": _first(r, "Channel", default=""),
                "event_id": _first(r, "EventID", "EventId", default=""),
                "level": _first(r, "Level", default=""),
                "rule": _first(r, "RuleTitle", "Rule", "Title", default=""),
                "details": _first(r, "Details", default=""),
                "tactics": tactics,
                "techniques": techniques,
            }
        )
    return {"count": len(detections), "detections": detections}


def parse_evtxecmd_json(raw: str) -> dict:
    rows = _load_rows(raw)
    events = []
    for r in rows:
        events.append(
            {
                "event_id": _first(r, "EventId", "EventID", default=""),
                "time": _first(r, "TimeCreated", "Time", default=""),
                "computer": _first(r, "Computer", default=""),
                "channel": _first(r, "Channel", default=""),
                "map_desc": _first(r, "MapDescription", default=""),
                "payload": _first(r, "PayloadData1", "Payload", default=""),
                "user": _first(r, "UserName", "User", default=""),
            }
        )
    return {"count": len(events), "events": events}


def parse_evtx_xml(raw: str) -> dict:
    """Light parse of python-evtx XML dump: count events, pull EventIDs."""
    ids = re.findall(r"<EventID[^>]*>(\d+)</EventID>", raw)
    n = raw.count("<Event ") or raw.count("<Event>")
    from collections import Counter

    return {"count": n, "event_id_histogram": dict(Counter(ids))}


# --------------------------------------------------------------------------- #
# Network (tshark -T fields, tab-separated)
# --------------------------------------------------------------------------- #
def parse_tshark_tsv(raw: str, columns: list[str], *, limit: int = 20000) -> dict:
    rows = []
    for i, line in enumerate(raw.splitlines()):
        if i == 0 and line.lower().startswith(columns[0].lower()):
            continue  # header row (header=y)
        if not line.strip() or len(rows) >= limit:
            continue
        fields = line.split("\t")
        rows.append({columns[j]: (fields[j] if j < len(fields) else "") for j in range(len(columns))})
    return {"count": len(rows), "rows": rows}
