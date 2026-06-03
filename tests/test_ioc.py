"""IOC extraction: grounded extraction and defanging."""

from glassbox.ioc.extract import extract_iocs, defang


SAMPLE = (
    "Connection from 172.16.112.128:1038 to 41.168.5.140:8080. "
    "DNS query: malware.evil-c2.net "
    "SHA256: a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2 "
    "POST to http://41.168.5.140/zb/v_01_a/in/ "
    "Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Cridex"
)


def test_extracts_routable_ip():
    iocs = extract_iocs(SAMPLE)
    vals = [i.value for i in iocs]
    assert "41.168.5.140" in vals


def test_does_not_extract_private_ip_by_default():
    iocs = extract_iocs(SAMPLE)
    vals = [i.value for i in iocs]
    assert "172.16.112.128" not in vals


def test_extracts_private_ip_when_enabled():
    iocs = extract_iocs(SAMPLE, include_private_ips=True)
    vals = [i.value for i in iocs]
    assert "172.16.112.128" in vals


def test_extracts_sha256():
    iocs = extract_iocs(SAMPLE)
    sha_iocs = [i for i in iocs if i.type == "sha256"]
    assert len(sha_iocs) == 1
    assert len(sha_iocs[0].value) == 64


def test_extracts_url():
    iocs = extract_iocs(SAMPLE)
    url_iocs = [i for i in iocs if i.type == "url"]
    assert any("/zb/v_01_a/in/" in i.value for i in url_iocs)


def test_extracts_registry_path():
    iocs = extract_iocs(SAMPLE)
    reg_iocs = [i for i in iocs if i.type == "regpath"]
    assert any("CurrentVersion\\Run" in i.value for i in reg_iocs)


def test_defang_ipv4():
    assert defang("41.168.5.140", "ipv4") == "41[.]168[.]5[.]140"


def test_defang_url():
    assert defang("http://evil.com/path", "url") == "hxxp://evil[.]com/path"


def test_no_duplicates():
    text = "41.168.5.140 41.168.5.140 41.168.5.140"
    iocs = extract_iocs(text)
    ip_iocs = [i for i in iocs if i.type == "ipv4"]
    assert len(ip_iocs) == 1
