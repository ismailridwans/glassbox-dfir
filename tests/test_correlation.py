"""Cross-source correlation: hidden processes, bad parents, orphan connections."""

from glassbox.correlate import MemoryView, DiskView, correlate_disk_memory
from glassbox.correlate.cross_source import (
    detect_hidden_processes,
    detect_parent_anomalies,
    detect_orphan_connections,
    detect_memory_only_executables,
)


def _mem(**kwargs):
    return MemoryView(
        pslist=kwargs.get("pslist", []),
        psscan=kwargs.get("psscan", []),
        netscan=kwargs.get("netscan", []),
        pslist_exec_id=kwargs.get("pslist_exec_id", "TE001"),
        psscan_exec_id=kwargs.get("psscan_exec_id", "TE002"),
        netscan_exec_id=kwargs.get("netscan_exec_id", "TE003"),
    )


LIVE = [
    {"pid": 4, "ppid": 0, "name": "System"},
    {"pid": 424, "ppid": 368, "name": "lsass.exe"},
    {"pid": 1484, "ppid": 1464, "name": "explorer.exe"},
]
SCAN = LIVE + [
    {"pid": 1520, "ppid": 0, "name": "HIDDEN_PROC"},   # NOT in live list
]


def test_hidden_process_detected():
    mem = _mem(pslist=LIVE, psscan=SCAN)
    disc = detect_hidden_processes(mem)
    assert any(d.kind == "hidden_process" and "1520" in d.description for d in disc)


def test_no_hidden_process_when_psscan_absent():
    mem = _mem(pslist=LIVE, psscan=[], psscan_exec_id=None)
    disc = detect_hidden_processes(mem)
    assert disc == []


def test_duplicate_singleton_detected():
    # Three lsass.exe instances = Stuxnet pattern
    procs = [
        {"pid": 424,  "ppid": 368, "name": "lsass.exe"},
        {"pid": 868,  "ppid": 412, "name": "lsass.exe"},
        {"pid": 1928, "ppid": 412, "name": "lsass.exe"},
    ]
    mem = _mem(pslist=procs)
    disc = detect_parent_anomalies(mem)
    assert any(d.kind == "duplicate_singleton_process" and "lsass" in d.description.lower() for d in disc)


def test_bad_parent_lsass():
    procs = [
        {"pid": 412, "ppid": 0, "name": "services.exe"},  # wrong parent for lsass
        {"pid": 424, "ppid": 412, "name": "lsass.exe"},   # lsass parented by services!
    ]
    mem = _mem(pslist=procs)
    disc = detect_parent_anomalies(mem)
    assert any(d.kind == "unexpected_parent_process" for d in disc)


def test_orphan_connection():
    # Conn owned by PID 9999 which is not in pslist
    netscan = [{"pid": 9999, "owner": "malware.exe", "proto": "TCP",
                "raddr": "41.168.5.140", "rport": 8080, "state": "ESTABLISHED"}]
    mem = _mem(pslist=LIVE, netscan=netscan)
    disc = detect_orphan_connections(mem)
    assert any(d.kind == "orphan_connection" and "41.168.5.140" in d.description for d in disc)


def test_memory_only_executable():
    mem = _mem(pslist=[{"pid": 1640, "ppid": 1484, "name": "ghostware.exe"}])
    disk = DiskView(image_names=["explorer.exe", "lsass.exe"], listing_exec_id="TE010")
    disc = detect_memory_only_executables(mem, disk)
    assert any(d.kind == "memory_only_executable" and "ghostware" in d.description.lower() for d in disc)


def test_correlate_returns_all_types():
    mem = _mem(pslist=LIVE, psscan=SCAN,
               netscan=[{"pid": 9999, "raddr": "41.168.5.140", "rport": 80}])
    disk = DiskView(image_names=["explorer.exe"], listing_exec_id="TE011")
    all_disc = correlate_disk_memory(mem, disk)
    kinds = {d.kind for d in all_disc}
    # must include hidden process from psscan gap
    assert "hidden_process" in kinds
