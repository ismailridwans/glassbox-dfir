"""Unified cross-source incident timeline.

Pulls timestamped events from every specialist's findings and discrepancies,
normalises them to UTC, and sorts them chronologically so the report can
present a coherent attack-chain narrative. This is the "Analyst Training Loop"
feature: the agent makes its reasoning transparent by showing *which artifact,
when, from which source*.

The output is deterministic (no LLM required) and is grounded — every event
cites the tool_exec_id that produced it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from glassbox.models import Discrepancy, EvidenceType, Finding, Severity


# Epoch seconds for rough sorting when we only have a process create-time string
_DT_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{10})"),  # unix epoch
]


def _parse_ts(raw: Optional[str]) -> Optional[str]:
    """Return a sortable ISO-like timestamp string or None."""
    if not raw:
        return None
    raw = str(raw).strip()
    for pat in _DT_PATTERNS:
        m = pat.search(raw)
        if m:
            return m.group(1).replace(" ", "T")
    return None


def _ts_key(ts: Optional[str]) -> str:
    """Sort key: unknown timestamps sort last."""
    return ts if ts else "9999-12-31T23:59:59"


@dataclass
class TimelineEvent:
    ts: Optional[str]                   # ISO-8601 or None
    source: str                         # evidence type / agent
    category: str                       # e.g. "process_start", "network_connection", "evtx_detection"
    title: str
    severity: str
    confidence: str
    tool_exec_id: str
    technique_ids: list[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "ts": self.ts or "unknown",
            "source": self.source,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "tool_exec_id": self.tool_exec_id,
            "technique_ids": self.technique_ids,
            "detail": self.detail,
        }


def build_timeline(
    findings: list[Finding],
    discrepancies: list[Discrepancy],
) -> list[TimelineEvent]:
    """Build a sorted unified incident timeline from all analyst findings."""
    events: list[TimelineEvent] = []

    for f in findings:
        ts = _parse_ts(f.observed_at)
        exec_id = f.provenance[0].tool_exec_id if f.provenance else "unknown"
        events.append(TimelineEvent(
            ts=ts,
            source=f.evidence_type.value,
            category=_category(f),
            title=f.title,
            severity=f.severity.value,
            confidence=f.confidence.value,
            tool_exec_id=exec_id,
            technique_ids=[m.technique_id for m in f.attack],
            detail=f.description[:200],
        ))

    for d in discrepancies:
        exec_id = d.provenance[0].tool_exec_id if d.provenance else "unknown"
        events.append(TimelineEvent(
            ts=None,  # discrepancies don't have wall-clock timestamps
            source=" + ".join(e.value for e in d.sources),
            category="cross_source_discrepancy",
            title=f"[{d.kind}] {d.discrepancy_id}",
            severity=d.severity.value,
            confidence=d.confidence.value,
            tool_exec_id=exec_id,
            technique_ids=[],
            detail=d.description[:200],
        ))

    # Sort: timestamped events first (chronological), then unknowns at end
    events.sort(key=lambda e: _ts_key(e.ts))
    return events


def _category(f: Finding) -> str:
    title_l = f.title.lower()
    if "inject" in title_l or "rwx" in title_l or "malfind" in title_l:
        return "process_injection"
    if "connect" in title_l or "network" in title_l or "dns" in title_l or "http" in title_l:
        return "network_activity"
    if "service" in title_l:
        return "service_install"
    if "evtx" in title_l or "detection" in title_l or "event" in title_l:
        return "evtx_detection"
    if "command" in title_l or "cmdline" in title_l or "powershell" in title_l:
        return "command_execution"
    if "account" in title_l:
        return "account_activity"
    if "log cleared" in title_l or "indicator removal" in title_l:
        return "defense_evasion"
    if "disk" in f.evidence_type.value or "masquerade" in title_l or "executable" in title_l:
        return "disk_artifact"
    return "general"


# ATT&CK kill-chain category order for narrative reconstruction
_CHAIN_ORDER = [
    "disk_artifact", "service_install", "command_execution",
    "process_injection", "network_activity", "account_activity",
    "defense_evasion", "evtx_detection", "cross_source_discrepancy", "general",
]


def narrative_summary(events: list[TimelineEvent], *, case_id: str = "") -> str:
    """Generate a concise, structured incident narrative from the timeline.

    The narrative groups events by kill-chain phase, states what was found and
    when (if timestamps are available), and names the tools that observed each
    event. This is the 'transparent reasoning' feature for analyst training.
    """
    if not events:
        return "No events to narrate."

    # Group by category
    by_cat: dict[str, list[TimelineEvent]] = {}
    for e in events:
        by_cat.setdefault(e.category, []).append(e)

    lines = [f"## Incident Narrative — {case_id}",  ""]
    lines.append("GLASSBOX reconstructed the following attack chain from cross-source evidence:")
    lines.append("")

    phase_num = 1
    for cat in _CHAIN_ORDER + [c for c in by_cat if c not in _CHAIN_ORDER]:
        evs = by_cat.get(cat, [])
        if not evs:
            continue
        label = cat.replace("_", " ").title()
        crit = [e for e in evs if e.severity in ("CRITICAL", "HIGH")]
        ts_evs = [e for e in evs if e.ts]
        ts_range = ""
        if ts_evs:
            ts_range = f" ({ts_evs[0].ts} → {ts_evs[-1].ts})" if len(ts_evs) > 1 else f" ({ts_evs[0].ts})"
        lines.append(f"**Phase {phase_num}: {label}**{ts_range}")
        for e in evs[:5]:  # cap at 5 per phase for readability
            conf_tag = "[+]" if e.confidence == "CONFIRMED" else "[~]"
            tech_str = f" [{', '.join(e.technique_ids[:2])}]" if e.technique_ids else ""
            lines.append(f"  {conf_tag} `[{e.tool_exec_id}]` {e.title}{tech_str}")
        if len(evs) > 5:
            lines.append(f"  ... and {len(evs) - 5} more.")
        lines.append("")
        phase_num += 1

    # High-confidence summary sentence
    confirmed = [e for e in events if e.confidence == "CONFIRMED"]
    inferred = [e for e in events if e.confidence == "INFERRED"]
    tech_ids = sorted({t for e in events for t in e.technique_ids})
    lines.append("---")
    lines.append(f"**Summary:** {len(confirmed)} confirmed observations, "
                 f"{len(inferred)} inferred, "
                 f"{len(tech_ids)} ATT&CK technique(s) mapped: "
                 + (", ".join(f"`{t}`" for t in tech_ids[:8])
                    + (" …" if len(tech_ids) > 8 else "") if tech_ids else "none"))
    return "\n".join(lines)
