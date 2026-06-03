"""Cross-source correlation (starter idea #2).

A single evidence source can be defeated: a rootkit unlinks its process from
the active list (so ``pslist`` misses it) but the pool scanner ``psscan`` still
finds it; a binary on disk can differ from what is actually running in memory.
This module compares the **memory view** against the **disk view** and emits
:class:`Discrepancy` objects.

Every discrepancy is INFERRED (a derivation), and its provenance cites the
*positive* observation (e.g. the PID as seen by ``psscan``) so the hallucination
gate can ground it. The reasoning that makes it suspicious (absence elsewhere)
is performed here in deterministic code, not by the model.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from glassbox.models import (
    Discrepancy,
    EvidenceType,
    Finding,
    Provenance,
    Severity,
)
from glassbox.util import stable_id

# Processes Windows runs as singletons; >1 (esp. with a wrong parent) is a flag.
_SINGLETONS = {"lsass.exe", "wininit.exe", "smss.exe", "lsm.exe"}
# Expected parent for sensitive processes (lowercased).
_EXPECTED_PARENT = {"lsass.exe": {"wininit.exe", "winlogon.exe"}}


class MemoryView(BaseModel):
    """Normalized memory observations + the tool executions that produced them."""

    pslist: list[dict] = Field(default_factory=list)   # [{pid,ppid,name}]
    psscan: list[dict] = Field(default_factory=list)
    netscan: list[dict] = Field(default_factory=list)  # [{pid,owner,raddr,rport,proto,state}]
    pslist_exec_id: Optional[str] = None
    psscan_exec_id: Optional[str] = None
    netscan_exec_id: Optional[str] = None


class DiskView(BaseModel):
    """Normalized disk observations."""

    # executable image names observed on disk (lowercased), and the exec that listed them
    image_names: list[str] = Field(default_factory=list)
    listing_exec_id: Optional[str] = None


def _name(rec: dict) -> str:
    return str(rec.get("name", "")).strip()


def detect_hidden_processes(mem: MemoryView) -> list[Discrepancy]:
    """PIDs found by the pool scanner (psscan) but missing from the active list
    (pslist) are classic process-hiding / already-terminated artifacts."""
    out: list[Discrepancy] = []
    if not mem.psscan or mem.psscan_exec_id is None:
        return out
    live_pids = {int(p["pid"]) for p in mem.pslist if "pid" in p}
    for rec in mem.psscan:
        pid = int(rec.get("pid", -1))
        if pid < 0 or pid in live_pids:
            continue
        name = _name(rec)
        prov = [
            Provenance(
                tool_exec_id=mem.psscan_exec_id,
                tool="mem_psscan",
                raw_locator=str(pid),
                note=f"PID {pid} ({name}) present in psscan output",
            )
        ]
        out.append(
            Discrepancy(
                discrepancy_id=stable_id("X", "hidden_proc", pid, name),
                kind="hidden_process",
                description=(
                    f"Process '{name}' (PID {pid}) was found by the pool scanner "
                    f"(psscan) but is ABSENT from the active process list (pslist). "
                    f"Consistent with process hiding/unlinking or recent termination."
                ),
                sources=[EvidenceType.MEMORY],
                severity=Severity.HIGH,
                provenance=prov,
            )
        )
    return out


def detect_parent_anomalies(mem: MemoryView) -> list[Discrepancy]:
    """Sensitive processes with the wrong parent, or singletons appearing more
    than once (e.g. the Stuxnet 3×lsass.exe pattern)."""
    out: list[Discrepancy] = []
    src_id = mem.pslist_exec_id or mem.psscan_exec_id
    procs = mem.pslist or mem.psscan
    if not procs or src_id is None:
        return out

    by_pid = {int(p["pid"]): p for p in procs if "pid" in p}

    # singletons appearing multiple times
    name_counts: dict[str, list[int]] = {}
    for p in procs:
        name_counts.setdefault(_name(p).lower(), []).append(int(p.get("pid", -1)))
    for name, pids in name_counts.items():
        if name in _SINGLETONS and len([x for x in pids if x >= 0]) > 1:
            pid_list = ", ".join(str(x) for x in sorted(pids) if x >= 0)
            out.append(
                Discrepancy(
                    discrepancy_id=stable_id("X", "dup_singleton", name),
                    kind="duplicate_singleton_process",
                    description=(
                        f"'{name}' should be a singleton but appears {len(pids)} times "
                        f"(PIDs {pid_list}). Strong indicator of process masquerading/injection."
                    ),
                    sources=[EvidenceType.MEMORY],
                    severity=Severity.CRITICAL,
                    provenance=[
                        Provenance(tool_exec_id=src_id, tool="mem_pslist", raw_locator=name)
                    ],
                )
            )

    # wrong-parent for sensitive processes
    for pid, p in by_pid.items():
        name = _name(p).lower()
        if name not in _EXPECTED_PARENT:
            continue
        ppid = int(p.get("ppid", -1))
        parent = by_pid.get(ppid)
        parent_name = _name(parent).lower() if parent else f"PID {ppid} (not present)"
        if parent_name not in _EXPECTED_PARENT[name]:
            out.append(
                Discrepancy(
                    discrepancy_id=stable_id("X", "bad_parent", name, pid),
                    kind="unexpected_parent_process",
                    description=(
                        f"'{name}' (PID {pid}) has unexpected parent '{parent_name}'. "
                        f"Expected one of: {sorted(_EXPECTED_PARENT[name])}."
                    ),
                    sources=[EvidenceType.MEMORY],
                    severity=Severity.HIGH,
                    provenance=[
                        Provenance(tool_exec_id=src_id, tool="mem_pslist", raw_locator=str(pid))
                    ],
                )
            )
    return out


def detect_orphan_connections(mem: MemoryView) -> list[Discrepancy]:
    """Network connections whose owning PID is not in the active process list —
    the connection outlived (or hid from) its process."""
    out: list[Discrepancy] = []
    if not mem.netscan or mem.netscan_exec_id is None:
        return out
    live_pids = {int(p["pid"]) for p in mem.pslist if "pid" in p}
    for conn in mem.netscan:
        pid = conn.get("pid")
        raddr = conn.get("raddr")
        if pid is None or raddr in (None, "", "*", "0.0.0.0"):
            continue
        if int(pid) not in live_pids and live_pids:
            out.append(
                Discrepancy(
                    discrepancy_id=stable_id("X", "orphan_conn", pid, raddr, conn.get("rport")),
                    kind="orphan_connection",
                    description=(
                        f"Network connection to {raddr}:{conn.get('rport')} is owned by "
                        f"PID {pid}, which is not in the active process list. "
                        f"Possible hidden/terminated malware retaining a socket."
                    ),
                    sources=[EvidenceType.MEMORY],
                    severity=Severity.HIGH,
                    provenance=[
                        Provenance(
                            tool_exec_id=mem.netscan_exec_id,
                            tool="mem_netscan",
                            raw_locator=str(raddr),
                        )
                    ],
                )
            )
    return out


# Windows system processes that legitimately run from memory but may not
# appear in a partial disk listing (excluded from memory-only detection).
_WINDOWS_SYSTEM_PROCS = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "spoolsv.exe",
    "taskhost.exe", "taskhostw.exe", "dwm.exe", "explorer.exe",
    "wuauclt.exe", "searchindexer.exe", "msiexec.exe", "regsvr32.exe",
    "dllhost.exe", "conhost.exe", "audiodg.exe", "werfault.exe",
}


def detect_memory_only_executables(mem: MemoryView, disk: DiskView) -> list[Discrepancy]:
    """Running images (from memory) that have no corresponding file on disk —
    fileless / injected / process-hollowed code. System processes are excluded."""
    out: list[Discrepancy] = []
    if not disk.image_names or disk.listing_exec_id is None:
        return out
    on_disk = {n.lower() for n in disk.image_names}
    src_id = mem.pslist_exec_id or mem.psscan_exec_id
    if src_id is None:
        return out
    seen: set[str] = set()
    for p in (mem.pslist or mem.psscan):
        name = _name(p).lower()
        if not name or name in seen:
            continue
        seen.add(name)
        # Skip well-known system processes — absence from disk listing is expected
        if name in _WINDOWS_SYSTEM_PROCS:
            continue
        if name not in on_disk:
            out.append(
                Discrepancy(
                    discrepancy_id=stable_id("X", "mem_only", name),
                    kind="memory_only_executable",
                    description=(
                        f"Process image '{name}' is running in memory but no matching "
                        f"file was found in the disk listing. Possible fileless or "
                        f"hollowed process (verify the disk listing scope before concluding)."
                    ),
                    sources=[EvidenceType.MEMORY, EvidenceType.DISK],
                    severity=Severity.MEDIUM,
                    provenance=[
                        Provenance(tool_exec_id=src_id, tool="mem_pslist", raw_locator=name)
                    ],
                )
            )
    return out


def correlate_disk_memory(
    mem: MemoryView,
    disk: Optional[DiskView] = None,
) -> list[Discrepancy]:
    """Run all cross-source checks and return the combined discrepancy list."""
    out: list[Discrepancy] = []
    out += detect_hidden_processes(mem)
    out += detect_parent_anomalies(mem)
    out += detect_orphan_connections(mem)
    if disk is not None:
        out += detect_memory_only_executables(mem, disk)
    return out
