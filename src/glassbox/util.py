"""Small shared helpers: stable IDs and file hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path


def stable_id(prefix: str, *parts: object) -> str:
    """Deterministic short ID from content. Same inputs -> same ID (good for
    dedupe and reproducible reports). e.g. ``stable_id("F", "hidden", 1640)``."""
    h = hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{h}"


def sha256_file(path: str | Path, *, chunk: int = 1 << 20) -> str:
    """Stream a file through SHA-256 (chunked, so large images don't blow RAM)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
