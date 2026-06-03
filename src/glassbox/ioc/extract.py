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
    # Matches Windows file paths (must have at least one filename after the last separator).
    # Stops at whitespace, comma, semicolon, quote, angle-brackets.
    # Also matches JSON-escaped double-backslash paths.
    "filepath": re.compile(
        r"[A-Za-z]:\\\\[A-Za-z0-9 ._\-]+(?:\\\\[A-Za-z0-9 ._\-]+)+|"
        r"[A-Za-z]:\\[A-Za-z0-9 ._\-]+(?:\\[A-Za-z0-9 ._\-]+)+"
    ),
}

# Don't treat these as domains (file artifacts that look domain-ish).
_FILE_EXTS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "tmp", "dat",
    "log", "txt", "doc", "docx", "xls", "xlsx", "zip", "rar", "7z", "evtx", "lnk",
}

# Known tool-output field names that look like domains but aren't.
# Pattern: short dotted names used by tshark/volatility/zeek as column headers.
_FIELD_PATTERNS = re.compile(
    r"^(?:ip|tcp|udp|dns|http|_ws|frame|eth|ssl|tls|smb|ftp|ssh|"
    r"kerberos|ntlm|ldap|col|ws|zeek|suricata|snort)"
    r"(?:\.[a-z_][a-z0-9_\.]*)+$"
)


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
            # Normalise JSON-escaped paths (replace \\ with \)
            normalised = value.replace("\\\\", "\\")
            # Require at least 2 path separators (e.g. C:\dir\file — not just C:\dir)
            parts = [p for p in normalised.rstrip("\\").split("\\") if p]
            if len(parts) < 3:  # drive + 2 components minimum
                continue
            add("filepath", normalised)

    emails = {v.lower() for v in _RE["email"].findall(text)}
    urls_found = {v.lower() for v in _RE["url"].findall(text)}
    for value in _RE["domain"].findall(text):
        val_l = value.lower()
        tld = val_l.rsplit(".", 1)[-1]
        if tld in _FILE_EXTS:
            continue  # e.g. reader_sl.exe
        if any(val_l in e for e in emails):
            continue  # part of an email
        if any(val_l in u for u in urls_found):
            continue  # subdomain of an already-captured URL
        if _FIELD_PATTERNS.match(val_l):
            continue  # tshark/zeek/volatility field name — not a real domain
        # Require at least 4-char TLD or 2 proper labels (filter single-word "domains")
        labels = val_l.split(".")
        if len(labels) < 2 or len(labels[-1]) < 2:
            continue
        # Skip all-numeric labels that look like version numbers (1.2.3)
        if all(lbl.replace("-", "").isdigit() for lbl in labels):
            continue
        add("domain", val_l)

    return list(found.values())
