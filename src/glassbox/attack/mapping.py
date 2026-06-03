"""Resolvers that turn observable artifacts into MITRE ATT&CK mappings.

Three entry points the specialists use:
  * ``for_artifact(key)``    — map a parser-assigned artifact key.
  * ``for_event_id(eid)``    — map a Windows event ID hint.
  * ``from_sigma_tags(tags)``— map Sigma/Hayabusa ``attack.tXXXX`` rule tags.

All return :class:`AttackMapping` objects with full tactic enrichment, so the
report can show coverage across the kill chain in canonical tactic order.
"""

from __future__ import annotations

import re
from typing import Iterable

from glassbox.attack.attack_data import (
    ARTIFACT_TECHNIQUES,
    EVENTID_ARTIFACT,
    TACTIC_NAME,
    TACTIC_ORDER,
    TECHNIQUES,
)
from glassbox.models import AttackMapping, Confidence

# matches sigma/hayabusa tags like "attack.t1059.001" or "attack.t1003"
_SIGMA_TECH = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def technique(technique_id: str, *, source: str = "glassbox.attack") -> AttackMapping | None:
    """Look up one technique by ID and enrich with its tactics."""
    technique_id = technique_id.strip().upper()
    entry = TECHNIQUES.get(technique_id)
    if entry is None:
        return None
    name, tactic_ids = entry
    return AttackMapping(
        technique_id=technique_id,
        technique_name=name,
        tactic_ids=list(tactic_ids),
        tactic_names=[TACTIC_NAME[t] for t in tactic_ids],
        source=source,
        confidence=Confidence.INFERRED,
    )


def for_artifact(artifact_key: str, *, source: str | None = None) -> list[AttackMapping]:
    """Map a parser-assigned artifact key (e.g. ``"service_install"``)."""
    src = source or f"artifact:{artifact_key}"
    out: list[AttackMapping] = []
    for tid in ARTIFACT_TECHNIQUES.get(artifact_key, []):
        m = technique(tid, source=src)
        if m:
            out.append(m)
    return out


def for_event_id(event_id: int) -> list[AttackMapping]:
    """Map a Windows event ID via its artifact hint."""
    key = EVENTID_ARTIFACT.get(int(event_id))
    if not key:
        return []
    return for_artifact(key, source=f"eventid:{event_id}")


def from_sigma_tags(tags: Iterable[str]) -> list[AttackMapping]:
    """Extract technique mappings from Sigma/Hayabusa ``tags`` (``attack.tNNNN``)."""
    out: list[AttackMapping] = []
    seen: set[str] = set()
    for tag in tags or []:
        m = _SIGMA_TECH.search(str(tag))
        if not m:
            continue
        tid = m.group(1).upper()
        if tid in seen:
            continue
        seen.add(tid)
        mapping = technique(tid, source="sigma-tag")
        if mapping:
            out.append(mapping)
        else:
            # Unknown-to-our-table but real ATT&CK ID: surface it, don't drop it.
            out.append(
                AttackMapping(
                    technique_id=tid,
                    technique_name="(technique not in GLASSBOX curated table — verify on attack.mitre.org)",
                    source="sigma-tag",
                    confidence=Confidence.INFERRED,
                )
            )
    return out


def dedupe_mappings(mappings: Iterable[AttackMapping]) -> list[AttackMapping]:
    """Collapse duplicate technique IDs, keeping the richest entry."""
    by_id: dict[str, AttackMapping] = {}
    for m in mappings:
        cur = by_id.get(m.technique_id)
        if cur is None or (not cur.tactic_ids and m.tactic_ids):
            by_id[m.technique_id] = m
    return list(by_id.values())


def coverage_by_tactic(mappings: Iterable[AttackMapping]) -> list[dict]:
    """Roll mappings up into kill-chain coverage, in canonical tactic order.

    Returns a list of ``{tactic_id, tactic_name, technique_ids}`` covering only
    the tactics that have at least one mapped technique, ordered recon→impact.
    """
    bucket: dict[str, set[str]] = {}
    for m in dedupe_mappings(mappings):
        for tid in m.tactic_ids:
            bucket.setdefault(tid, set()).add(m.technique_id)
    rows = [
        {
            "tactic_id": tid,
            "tactic_name": TACTIC_NAME.get(tid, tid),
            "technique_ids": sorted(techs),
        }
        for tid, techs in bucket.items()
    ]
    rows.sort(key=lambda r: TACTIC_ORDER.get(r["tactic_id"], 999))
    return rows
