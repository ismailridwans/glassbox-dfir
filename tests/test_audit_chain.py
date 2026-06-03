"""Audit chain: tamper detection (insertion, deletion, alteration)."""

import json
import tempfile
from pathlib import Path

import pytest

from glassbox.audit.chain import AuditChain, GENESIS


def make_chain(n: int, tmp: Path) -> AuditChain:
    path = tmp / "test.audit.jsonl"
    chain = AuditChain(path)
    for i in range(n):
        chain.append("test_event", seq_hint=i, value=f"data-{i}")
    return chain


def test_empty_chain_verifies(tmp_path):
    chain = AuditChain(tmp_path / "c.jsonl")
    # empty chain fails (no records)
    ok, errors = chain.verify_self()
    assert not ok
    assert "empty" in errors[0].lower()


def test_valid_chain(tmp_path):
    chain = make_chain(5, tmp_path)
    ok, errors = chain.verify_self()
    assert ok, errors


def test_tamper_record_value(tmp_path):
    chain = make_chain(3, tmp_path)
    path = chain.path

    # Alter the second record's field value
    lines = path.read_text("utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["event"]["value"] = "TAMPERED"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, errors = AuditChain.verify(path)
    assert not ok
    assert any("mismatch" in e.lower() or "hash" in e.lower() for e in errors)


def test_tamper_insert_record(tmp_path):
    chain = make_chain(3, tmp_path)
    path = chain.path
    lines = path.read_text("utf-8").splitlines()
    # Insert a fake record between line 0 and 1
    fake = json.dumps({"seq": 99, "ts": "x", "event": {"type": "injected"},
                       "prev_hash": GENESIS, "record_hash": GENESIS},
                      sort_keys=True, separators=(",", ":"))
    lines.insert(1, fake)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, errors = AuditChain.verify(path)
    assert not ok


def test_resume_continues_chain(tmp_path):
    path = tmp_path / "resume.jsonl"
    c1 = AuditChain(path)
    c1.append("first")
    tip_after_first = c1.tip

    # Resume from disk
    c2 = AuditChain(path)
    assert c2.tip == tip_after_first
    c2.append("second")

    ok, errors = AuditChain.verify(path)
    assert ok, errors
    assert c2.count() == 2
