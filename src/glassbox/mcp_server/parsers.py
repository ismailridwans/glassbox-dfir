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
