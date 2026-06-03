"""Extra parsers for YARA, RegRipper, DLL list, and handles output."""

from __future__ import annotations

import json
import re
from typing import Any


def parse_yara_output(raw: str) -> dict:
    """Parse yara CLI output: each line is 'RULE_NAME PATH'."""
    hits: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) >= 1:
            hits.append({"rule": parts[0], "target": parts[1] if len(parts) > 1 else ""})
    return {"count": len(hits), "hits": hits}


def parse_regripper_output(raw: str) -> dict:
    """Parse RegRipper output: section headers + key=value lines.

    RegRipper emits blocks like::

        pluginname v1.0
        (C) <author>
        ----------------------------------------
        LastWrite Time YYYY-MM-DD HH:MM:SS
        key = value

    We extract the key-value pairs and attach the most recent section header.
    """
    sections: list[dict] = []
    current: dict[str, Any] = {}
    last_write = ""
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("(C)") or set(line) <= {"-", "="}:
            continue
        lw = re.match(r"LastWrite Time\s+(.*)", line, re.IGNORECASE)
        if lw:
            last_write = lw.group(1).strip()
            continue
        kv = re.match(r"^([^=\|:]+?)\s*[=\|:]\s*(.+)$", line)
        if kv:
            current.setdefault("entries", []).append(
                {"key": kv.group(1).strip(), "value": kv.group(2).strip(),
                 "last_write": last_write}
            )
        elif re.match(r"^[A-Za-z].*v\d", line):
            if current:
                sections.append(current)
            current = {"plugin": line, "entries": [], "last_write": ""}
    if current:
        sections.append(current)
    total_entries = sum(len(s.get("entries", [])) for s in sections)
    return {"count": total_entries, "sections": sections}


def parse_dlllist(raw: str) -> dict:
    """Parse Volatility 3 windows.dlllist JSON output."""
    rows = []
    raw = raw.strip()
    if not raw:
        return {"count": 0, "dlls": []}
    try:
        obj = json.loads(raw)
        items = obj if isinstance(obj, list) else []
    except json.JSONDecodeError:
        items = []
        for line in raw.splitlines():
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    for r in items:
        name = (r.get("Name") or r.get("BaseDllName") or r.get("name") or "").strip()
        base = r.get("Base") or r.get("base") or ""
        path = r.get("FullDllName") or r.get("full_name") or ""
        pid = r.get("PID") or r.get("pid") or -1
        rows.append({"pid": int(pid) if pid not in (None, "") else -1,
                     "name": name, "base": str(base), "path": str(path)})
    return {"count": len(rows), "dlls": rows}
