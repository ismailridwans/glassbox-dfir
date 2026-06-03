"""Hash-chained, append-only audit log (WORM-style).

Every tool execution, every inter-agent message, every self-correction
decision, and every integrity check is appended here as one JSON line. Each
record carries ``prev_hash`` and ``record_hash`` where::

    record_hash = SHA-256( prev_hash || canonical_json({seq, ts, event}) )

so any insertion, deletion, reordering, or edit of a past record breaks the
chain and is detected by :meth:`AuditChain.verify`. This is the
chain-of-custody guarantee the report leans on.

Crucially, **the agent has no MCP tool that can write to this log.** Only the
trusted runner/orchestrator (outside the model's tool surface) appends to it.
That is what makes it an *architectural* control rather than a prompt-based one.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Optional

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    """Deterministic JSON for hashing: sorted keys, no whitespace, str fallback."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


class AuditChain:
    """Append-only, hash-chained JSONL audit log.

    Parameters
    ----------
    path:
        Destination ``.jsonl`` file. Opened in append mode; an existing chain is
        re-loaded and continued (its tip hash becomes the new ``prev_hash``).
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._tip = GENESIS
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last is not None:
            self._seq = int(last["seq"]) + 1
            self._tip = last["record_hash"]

    def append(self, event_type: str, **fields: Any) -> dict[str, Any]:
        """Append one event. Returns the full stored record (incl. hashes)."""
        with self._lock:
            from glassbox.models import utcnow_iso  # local import avoids cycle

            body = {
                "seq": self._seq,
                "ts": utcnow_iso(),
                "event": {"type": event_type, **fields},
            }
            record_hash = _hash(self._tip, body)
            record = {**body, "prev_hash": self._tip, "record_hash": record_hash}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(record) + "\n")
            self._seq += 1
            self._tip = record_hash
            return record

    @property
    def tip(self) -> str:
        """Current head hash of the chain (changes on every append)."""
        return self._tip

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    @classmethod
    def verify(cls, path: str | Path) -> tuple[bool, list[str]]:
        """Re-walk a chain file and confirm it is intact.

        Returns ``(ok, errors)``. ``ok`` is True only if every record's hash
        recomputes correctly and every ``prev_hash`` links to the prior record.
        """
        path = Path(path)
        errors: list[str] = []
        if not path.exists():
            return False, [f"audit log not found: {path}"]

        prev = GENESIS
        expected_seq = 0
        n = 0
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                n += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {lineno}: invalid JSON ({exc})")
                    return False, errors

                if rec.get("seq") != expected_seq:
                    errors.append(f"line {lineno}: seq {rec.get('seq')} != expected {expected_seq}")
                if rec.get("prev_hash") != prev:
                    errors.append(
                        f"line {lineno}: prev_hash mismatch (chain broken at seq {rec.get('seq')})"
                    )
                body = {"seq": rec.get("seq"), "ts": rec.get("ts"), "event": rec.get("event")}
                recomputed = _hash(rec.get("prev_hash", ""), body)
                if recomputed != rec.get("record_hash"):
                    errors.append(f"line {lineno}: record_hash mismatch (record was altered)")
                prev = rec.get("record_hash", "")
                expected_seq += 1

        if n == 0:
            errors.append("audit log is empty")
        return (len(errors) == 0), errors

    def verify_self(self) -> tuple[bool, list[str]]:
        return self.verify(self.path)

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())
