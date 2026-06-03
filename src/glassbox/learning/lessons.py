"""Lessons log — cross-run hallucination memory.

File format: JSONL, one lesson per line::

    {"ts":"...", "run_id":"...", "pattern":"2.3 GB", "tool":"mem_netscan",
     "finding_title":"Assessment: active data exfiltration...",
     "reason":"locator absent from captured output", "suppressed_count":0}

The ``pattern`` is the ``raw_locator`` that failed verification.  On
subsequent runs the verifier will pre-downgrade any finding whose
``raw_locator`` matches a known-bad pattern to ``UNVERIFIED`` (rather than
CONFIRMED), so the gate catches it faster and the run's quarantine rate
improves.

The ``suppressed_count`` field tracks how many times the lesson prevented a
false positive in later runs — visible evidence of measurable improvement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from glassbox.models import Finding, utcnow_iso


class LessonsLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._patterns: set[str] = set()
        self._lessons: list[dict] = []
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                lesson = json.loads(line)
                self._lessons.append(lesson)
                pat = lesson.get("pattern", "").lower()
                if pat:
                    self._patterns.add(pat)
            except json.JSONDecodeError:
                continue

    def is_known_bad(self, raw_locator: str) -> Optional[dict]:
        """Return the matching lesson if this locator has been quarantined before."""
        return next(
            (l for l in self._lessons if l.get("pattern", "").lower() == raw_locator.lower()),
            None
        )

    def append_from_quarantined(
        self, quarantined: list[Finding], run_id: str = ""
    ) -> int:
        """Extract lessons from newly-quarantined findings and persist them.

        Returns the number of new lessons added.
        """
        new = 0
        for f in quarantined:
            for prov in f.provenance:
                pattern = prov.raw_locator.lower()
                if not pattern or pattern in self._patterns:
                    continue
                lesson = {
                    "ts": utcnow_iso(),
                    "run_id": run_id,
                    "pattern": prov.raw_locator,
                    "tool": prov.tool,
                    "finding_title": f.title[:120],
                    "reason": f.verifier_note[:200],
                    "suppressed_count": 0,
                }
                self._patterns.add(pattern)
                self._lessons.append(lesson)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(lesson) + "\n")
                new += 1
        return new

    def apply_to_findings(self, findings: list[Finding]) -> int:
        """Pre-downgrade findings whose locators match known-bad patterns.

        Modifies findings in place; returns how many were suppressed.
        Suppression means marking confidence as UNVERIFIED *before* the
        gate runs, so the verifier has less work and the run improves.
        """
        from glassbox.models import Confidence

        suppressed = 0
        for f in findings:
            for prov in f.provenance:
                lesson = self.is_known_bad(prov.raw_locator)
                if lesson and f.confidence == Confidence.CONFIRMED:
                    f.confidence = Confidence.UNVERIFIED
                    f.verifier_note = (
                        f"[lessons-log] Pre-downgraded: pattern '{prov.raw_locator}' "
                        f"was quarantined in a previous run "
                        f"(tool={lesson['tool']}, reason={lesson['reason'][:80]})"
                    )
                    lesson["suppressed_count"] = lesson.get("suppressed_count", 0) + 1
                    suppressed += 1
                    break
        return suppressed

    def summary(self) -> dict:
        return {
            "total_lessons": len(self._lessons),
            "unique_patterns": len(self._patterns),
            "total_suppressed": sum(l.get("suppressed_count", 0) for l in self._lessons),
        }
