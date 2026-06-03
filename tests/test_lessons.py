"""Persistent learning loop: lessons log persists and pre-suppresses."""

import pytest
from glassbox.learning.lessons import LessonsLog
from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
from glassbox.util import stable_id


def _finding(title, locator, exec_id, confidence=Confidence.CONFIRMED):
    return Finding(
        finding_id=stable_id("F", title),
        title=title,
        evidence_type=EvidenceType.MEMORY,
        severity=Severity.HIGH,
        confidence=confidence,
        provenance=[Provenance(tool_exec_id=exec_id, tool="mem_netscan",
                               raw_locator=locator)],
        verifier_note="test",
        source_agent="test",
    )


def test_append_and_persist(tmp_path):
    log_path = tmp_path / "lessons.jsonl"
    ll = LessonsLog(log_path)
    quarantined = [_finding("Hallucinated claim", "FAKE_VALUE", "TE001",
                             confidence=Confidence.HALLUCINATED)]
    quarantined[0].verifier_note = "locator FAKE_VALUE absent"
    n = ll.append_from_quarantined(quarantined, run_id="run1")
    assert n == 1
    assert log_path.exists()
    # Reload and verify persistence
    ll2 = LessonsLog(log_path)
    assert ll2.summary()["total_lessons"] == 1
    assert ll2.is_known_bad("FAKE_VALUE") is not None


def test_no_duplicate_lessons(tmp_path):
    ll = LessonsLog(tmp_path / "lessons.jsonl")
    q = [_finding("F1", "BAD", "TE001", confidence=Confidence.HALLUCINATED)]
    q[0].verifier_note = "absent"
    ll.append_from_quarantined(q)
    n2 = ll.append_from_quarantined(q)  # same pattern again
    assert n2 == 0  # no duplicate
    assert ll.summary()["total_lessons"] == 1


def test_apply_pre_suppresses_known_bad(tmp_path):
    ll = LessonsLog(tmp_path / "lessons.jsonl")
    q = [_finding("Bad claim", "KNOWN_BAD", "TE001", confidence=Confidence.HALLUCINATED)]
    q[0].verifier_note = "absent"
    ll.append_from_quarantined(q)

    # New run: a finding that cites the same locator
    new_finding = _finding("New claim about KNOWN_BAD", "KNOWN_BAD", "TE002")
    assert new_finding.confidence == Confidence.CONFIRMED
    suppressed = ll.apply_to_findings([new_finding])
    assert suppressed == 1
    assert new_finding.confidence == Confidence.UNVERIFIED
    assert "lessons-log" in new_finding.verifier_note


def test_unknown_pattern_not_suppressed(tmp_path):
    ll = LessonsLog(tmp_path / "lessons.jsonl")
    # Lessons log is empty
    f = _finding("Good finding", "VALID_VALUE_123", "TE001")
    suppressed = ll.apply_to_findings([f])
    assert suppressed == 0
    assert f.confidence == Confidence.CONFIRMED


def test_suppression_count_increments(tmp_path):
    ll = LessonsLog(tmp_path / "lessons.jsonl")
    q = [_finding("Bad", "REPEAT_BAD", "TE001", confidence=Confidence.HALLUCINATED)]
    q[0].verifier_note = "absent"
    ll.append_from_quarantined(q)
    f1 = _finding("F1", "REPEAT_BAD", "TE002")
    f2 = _finding("F2", "REPEAT_BAD", "TE003")
    ll.apply_to_findings([f1, f2])
    assert ll.summary()["total_suppressed"] == 2
