"""Unified timeline: cross-source ordering and narrative generation."""

import pytest

from glassbox.models import Confidence, Discrepancy, EvidenceType, Finding, Provenance, Severity
from glassbox.timeline import build_timeline, narrative_summary
from glassbox.util import stable_id


def _f(title, ts=None, confidence=Confidence.CONFIRMED, evtype=EvidenceType.MEMORY):
    return Finding(
        finding_id=stable_id("F", title),
        title=title,
        evidence_type=evtype,
        severity=Severity.HIGH,
        confidence=confidence,
        provenance=[Provenance(tool_exec_id="TE001", tool="t", raw_locator="x")],
        observed_at=ts,
        source_agent="test",
    )


def _d(kind):
    return Discrepancy(
        discrepancy_id=stable_id("X", kind),
        kind=kind,
        description=f"Test discrepancy: {kind}",
        sources=[EvidenceType.MEMORY],
        severity=Severity.HIGH,
        provenance=[Provenance(tool_exec_id="TE002", tool="t", raw_locator="pid")],
    )


def test_timeline_sorted_chronologically():
    findings = [
        _f("Event B", ts="2012-07-22T02:44:00"),
        _f("Event A", ts="2012-07-22T02:43:00"),
        _f("Event C"),  # no timestamp — sorts last
    ]
    tl = build_timeline(findings, [])
    assert tl[0].title == "Event A"
    assert tl[1].title == "Event B"
    assert tl[2].title == "Event C"  # unknown ts last


def test_timeline_includes_discrepancies():
    findings = [_f("Injection", ts="2012-07-22T02:43:00")]
    discs = [_d("hidden_process")]
    tl = build_timeline(findings, discs)
    kinds = {e.category for e in tl}
    assert "cross_source_discrepancy" in kinds
    assert "process_injection" in kinds or "general" in kinds


def test_narrative_contains_phase_labels():
    findings = [
        _f("New service installed", ts="2012-07-22T02:43:01", evtype=EvidenceType.EVTX),
        _f("C2 connection to 41.168.5.140", ts="2012-07-22T02:43:09"),
        _f("Log cleared", ts="2012-07-22T02:44:12", evtype=EvidenceType.EVTX),
    ]
    tl = build_timeline(findings, [])
    narr = narrative_summary(tl, case_id="test-case")
    assert "Phase" in narr
    assert "test-case" in narr
    assert "confirmed" in narr.lower()


def test_narrative_summary_line():
    findings = [_f("Injection")]
    tl = build_timeline(findings, [])
    narr = narrative_summary(tl)
    assert "1 confirmed" in narr


def test_empty_timeline_graceful():
    tl = build_timeline([], [])
    assert tl == []
    narr = narrative_summary(tl)
    assert "No events" in narr
