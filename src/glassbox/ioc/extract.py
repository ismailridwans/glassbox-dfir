"""Regex-based IOC extraction.

Pulls IPv4/IPv6, domains, URLs, file hashes (md5/sha1/sha256), emails, Windows
file paths, and registry paths out of parsed tool output. Every IOC carries the
provenance of the tool execution it came from, and a defanged rendering so the
report is safe to open. Private/reserved IPs are tagged (not C2 by default) so
they don't inflate the IOC list.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional

from glassbox.models import IOC, Provenance

_RE = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE),
    "url": re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
    ),
    "regpath": re.compile(
        r"\b(?:HK(?:LM|CU|CR|U|CC)|HKEY_[A-Z_]+)\\[\\A-Za-z0-9 _\-.${}]+", re.IGNORECASE
    ),
    "filepath": re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),
}

# Don't treat these as domains (file artifacts that look domain-ish).
_FILE_EXTS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "tmp", "dat",
    "log", "txt", "doc", "docx", "xls", "xlsx", "zip", "rar", "7z", "evtx", "lnk",
}


def defang(value: str, kind: str) -> str:
    if kind in ("ipv4", "ipv6"):
        return value.replace(".", "[.]").replace(":", "[:]")
    if kind in ("url", "domain", "email"):
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    return value


def _is_routable_ip(value: str) -> Optional[bool]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def extract_iocs(
    text: str,
    *,
    context: str = "",
    provenance: Optional[Iterable[Provenance]] = None,
    include_private_ips: bool = False,
    include_filepaths: bool = False,
) -> list[IOC]:
    """Extract de-duplicated IOCs from ``text``.

    ``provenance`` is attached to every IOC so each indicator traces back to the
    tool execution that produced it. By default, private/reserved IPs and local
    file paths are excluded (they are rarely network IOCs and add noise);
    enable them explicitly when needed.
    """
    prov = list(provenance or [])
    found: dict[tuple[str, str], IOC] = {}

    def add(kind: str, value: str, note: str = "") -> None:
        key = (kind, value.lower())
        if key in found:
            return
        found[key] = IOC(
            type=kind,
            value=value,
            defanged=defang(value, kind),
            context=(context + (f" — {note}" if note else "")).strip(" —"),
            provenance=prov,
        )

    # Order matters: hashes before domains so 64-hex isn't mis-parsed, etc.
    for value in _RE["url"].findall(text):
        add("url", value.rstrip(".,);]"))
    for value in _RE["sha256"].findall(text):
        add("sha256", value.lower())
    sha256_hits = {v.lower() for v in _RE["sha256"].findall(text)}
    for value in _RE["sha1"].findall(text):
        add("sha1", value.lower())
    for value in _RE["md5"].findall(text):
        # avoid flagging a 32-hex slice that is part of a sha1/sha256
        if not any(value.lower() in h for h in sha256_hits):
            add("md5", value.lower())
    for value in _RE["email"].findall(text):
        add("email", value)
    for value in _RE["ipv4"].findall(text):
        routable = _is_routable_ip(value)
        if routable is False and not include_private_ips:
            continue
        add("ipv4", value, note="" if routable else "private/reserved")
    for value in _RE["regpath"].findall(text):
        add("regpath", value)
    if include_filepaths:
        for value in _RE["filepath"].findall(text):
            add("filepath", value)

    emails = {v.lower() for v in _RE["email"].findall(text)}
    for value in _RE["domain"].findall(text):
        tld = value.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXTS:
            continue  # e.g. reader_sl.exe
        if any(value.lower() in e for e in emails):
            continue  # part of an email we already captured
        add("domain", value.lower())

    return list(found.values())
