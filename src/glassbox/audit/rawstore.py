"""Content-addressed store for verbatim tool output.

When a read-only MCP tool runs, its *raw* stdout is written here keyed by the
``tool_exec_id``, and a *parsed/structured* summary is what gets returned to the
LLM. Two reasons:

1. **Context-window protection** — the model sees compact structured findings,
   never a 40 MB ``fls`` dump.
2. **Mechanical verification** — the hallucination gate re-opens the raw output
   for a finding's ``tool_exec_id`` and confirms the cited value is actually
   present. The model cannot retroactively alter what a tool emitted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


class RawStore:
    """On-disk + in-memory store of raw tool output, keyed by tool_exec_id."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._raw_cache: dict[str, str] = {}
        self._parsed_cache: dict[str, dict[str, Any]] = {}

    def _raw_path(self, key: str) -> Path:
        return self.root / f"{key}.raw.txt"

    def _parsed_path(self, key: str) -> Path:
        return self.root / f"{key}.parsed.json"

    def put(self, key: str, raw_text: str, parsed: Optional[dict[str, Any]] = None) -> None:
        self._raw_cache[key] = raw_text
        self._raw_path(key).write_text(raw_text, encoding="utf-8")
        if parsed is not None:
            self._parsed_cache[key] = parsed
            self._parsed_path(key).write_text(
                json.dumps(parsed, indent=2, default=str), encoding="utf-8"
            )

    def get_raw(self, key: str) -> Optional[str]:
        if key in self._raw_cache:
            return self._raw_cache[key]
        p = self._raw_path(key)
        if p.exists():
            text = p.read_text(encoding="utf-8")
            self._raw_cache[key] = text
            return text
        return None

    def get_parsed(self, key: str) -> Optional[dict[str, Any]]:
        if key in self._parsed_cache:
            return self._parsed_cache[key]
        p = self._parsed_path(key)
        if p.exists():
            obj = json.loads(p.read_text(encoding="utf-8"))
            self._parsed_cache[key] = obj
            return obj
        return None

    def contains(self, key: str, needle: str, *, case_insensitive: bool = True) -> bool:
        """True if ``needle`` appears in the raw output captured for ``key``.

        This is the primitive the hallucination verifier relies on: a claimed
        value is only honored if it physically exists in what the tool emitted.
        """
        raw = self.get_raw(key)
        if raw is None or needle is None or needle == "":
            return False
        if case_insensitive:
            return needle.lower() in raw.lower()
        return needle in raw

    def keys(self) -> list[str]:
        return sorted(
            {p.name[: -len(".raw.txt")] for p in self.root.glob("*.raw.txt")}
            | set(self._raw_cache)
        )
