"""Hallucination gate: fabricated claims quarantined; grounded claims confirmed."""

import tempfile
from pathlib import Path

import pytest

from glassbox.audit.chain import AuditChain
from glassbox.audit.rawstore import RawStore
from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
from glassbox.util import stable_id
from glassbox.verify import verify_findings


def _prov(exec_id, locator):
    return Provenance(tool_exec_id=exec_id, tool="test_tool", raw_locator=locator)


def _finding(title, prov, cited, confidence=Confidence.CONFIRMED):
    return Finding(
        finding_id=stable_id("F", title),
        title=title,
        evidence_type=EvidenceType.MEMORY,
        severity=Severity.HIGH,
        confidence=confidence,
        provenance=prov,
        cited_values=cited,
        source_agent="test",
    )


@pytest.fixture
def store_audit(tmp_path):
    store = RawStore(tmp_path / "raw")
    audit = AuditChain(tmp_path / "audit.jsonl")
    return store, audit


def test_grounded_finding_confirmed(store_audit):
    store, audit = store_audit
    store.put("TE0001-mem", "reader_sl.exe PID 1640 41.168.5.140", None)

    f = _finding("Cridex process found",
                 prov=[_prov("TE0001-mem", "reader_sl.exe")],
                 cited=["reader_sl.exe", "1640"])

    result = verify_findings([f], store, ["TE0001-mem"], audit=audit)
    assert len(result.verified) == 1
    assert len(result.quarantined) == 0
    assert result.verified[0].confidence == Confidence.CONFIRMED


def test_fabricated_locator_quarantined(store_audit):
    store, audit = store_audit
    store.put("TE0002-mem", "normal output with no evil here", None)

    f = _finding("Hallucinated finding",
                 prov=[_prov("TE0002-mem", "FABRICATED_VALUE_NOT_IN_OUTPUT")],
                 cited=["FABRICATED_VALUE_NOT_IN_OUTPUT"])

    result = verify_findings([f], store, ["TE0002-mem"], audit=audit)
    assert len(result.quarantined) == 1
    assert len(result.verified) == 0
    assert result.quarantined[0].confidence == Confidence.HALLUCINATED


def test_no_provenance_quarantined(store_audit):
    store, audit = store_audit
    f = _finding("No backing evidence", prov=[], cited=["something"])
    result = verify_findings([f], store, [], audit=audit)
    assert result.quarantined[0].confidence == Confidence.HALLUCINATED


def test_unknown_exec_id_quarantined(store_audit):
    store, audit = store_audit
    f = _finding("Unknown tool",
                 prov=[_prov("TE9999-NONEXISTENT", "reader_sl.exe")],
                 cited=["reader_sl.exe"])
    result = verify_findings([f], store, ["TE0001-real"], audit=audit)
    assert len(result.quarantined) == 1


def test_cited_value_not_in_output(store_audit):
    store, audit = store_audit
    store.put("TE0003", "real output: 41.168.5.140", None)
    f = _finding("Exfil 2.3 GB",
                 prov=[_prov("TE0003", "2.3 GB")],
                 cited=["2.3 GB"])
    result = verify_findings([f], store, ["TE0003"], audit=audit)
    assert len(result.quarantined) == 1
    # This is the exact GTG-1002 failure mode: the agent overstated exfil volume;
    # the gate caught it because "2.3 GB" is not in the tool output.


def test_hallucination_rate_in_summary(store_audit):
    store, audit = store_audit
    store.put("TE0010", "reader_sl.exe 1640", None)
    good = _finding("Good", prov=[_prov("TE0010", "reader_sl.exe")], cited=["reader_sl.exe"])
    bad  = _finding("Bad",  prov=[_prov("TE0010", "PHANTOM")],       cited=["PHANTOM"])
    result = verify_findings([good, bad], store, ["TE0010"], audit=audit)
    s = result.summary()
    assert s["confirmed"] == 1
    assert s["hallucinated"] == 1
    assert s["total_proposed"] == 2
