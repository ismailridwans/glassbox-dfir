"""GLASSBOX read-only MCP server (stdio).

Launched by Claude Code / Claude Desktop (see config/claude_desktop_config.example.json).
Exposes ONLY the typed read-only tools from :class:`ReadOnlyToolKit`. There is no
shell, write, or delete tool registered here — that absence is the guardrail.

Run directly::

    GLASSBOX_CASE=/cases/incident-001 python -m glassbox.mcp_server.server

The case's evidence dir must already exist (and ideally be mounted read-only).
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from mcp.server.fastmcp import FastMCP

from glassbox.config import GlassboxConfig
from glassbox.context import CaseContext
from glassbox.mcp_server.toolkit import ReadOnlyToolKit, ToolResult

mcp = FastMCP("glassbox-sift")


@lru_cache(maxsize=1)
def _ctx() -> CaseContext:
    case = os.getenv("GLASSBOX_CASE")
    if not case:
        raise RuntimeError("set GLASSBOX_CASE to the case directory before launching the server")
    cfg = GlassboxConfig.for_case(case, evidence_dir=os.getenv("GLASSBOX_EVIDENCE"))
    return CaseContext(cfg)


def _kit() -> ReadOnlyToolKit:
    return _ctx().toolkit


# --- memory ---------------------------------------------------------------- #
@mcp.tool()
def mem_pslist(evidence: str) -> ToolResult:
    """List active processes from a memory image (Volatility windows.pslist). Read-only."""
    return _kit().mem_pslist(evidence)


@mcp.tool()
def mem_pstree(evidence: str) -> ToolResult:
    """Process tree from a memory image (windows.pstree). Read-only."""
    return _kit().mem_pstree(evidence)


@mcp.tool()
def mem_psscan(evidence: str) -> ToolResult:
    """Pool-scan for processes — surfaces hidden/unlinked procs (windows.psscan). Read-only."""
    return _kit().mem_psscan(evidence)


@mcp.tool()
def mem_netscan(evidence: str) -> ToolResult:
    """Network connections recovered from a memory image (windows.netscan). Read-only."""
    return _kit().mem_netscan(evidence)


@mcp.tool()
def mem_malfind(evidence: str) -> ToolResult:
    """Detect injected/hidden code, RWX private memory (windows.malfind). Read-only."""
    return _kit().mem_malfind(evidence)


@mcp.tool()
def mem_cmdline(evidence: str) -> ToolResult:
    """Per-process command lines from a memory image (windows.cmdline). Read-only."""
    return _kit().mem_cmdline(evidence)


@mcp.tool()
def mem_svcscan(evidence: str) -> ToolResult:
    """Enumerate Windows services from a memory image (windows.svcscan). Read-only."""
    return _kit().mem_svcscan(evidence)


@mcp.tool()
def mem_dlllist(evidence: str, pid: Optional[int] = None) -> ToolResult:
    """Enumerate loaded DLLs per process (windows.dlllist). Surfaces unmapped/injected DLLs. Read-only."""
    return _kit().mem_dlllist(evidence, pid=pid)


# --- YARA ------------------------------------------------------------------ #
@mcp.tool()
def yara_scan(evidence: str, rules_path: Optional[str] = None) -> ToolResult:
    """Scan memory image or file against YARA rules (bundled Cridex/Stuxnet/generic rules). Read-only."""
    return _kit().yara_scan(evidence, rules_path=rules_path)


# --- registry -------------------------------------------------------------- #
@mcp.tool()
def registry_analyze(evidence: str, plugin: str = "all") -> ToolResult:
    """Analyze a registry hive with RegRipper (Run keys, services, UserAssist, etc.). Read-only."""
    return _kit().registry_analyze(evidence, plugin=plugin)


# --- disk ------------------------------------------------------------------ #
@mcp.tool()
def disk_partition_table(evidence: str) -> ToolResult:
    """Partition table of a disk image (Sleuth Kit mmls). Read-only."""
    return _kit().disk_partition_table(evidence)


@mcp.tool()
def disk_list_files(evidence: str, offset: Optional[int] = None) -> ToolResult:
    """Recursive file listing with inodes (fls -r -p). Read-only."""
    return _kit().disk_list_files(evidence, offset=offset)


@mcp.tool()
def disk_mft_timeline(evidence: str, offset: Optional[int] = None) -> ToolResult:
    """Filesystem timeline body file (fls -r -m). Read-only."""
    return _kit().disk_mft_timeline(evidence, offset=offset)


# --- evtx ------------------------------------------------------------------ #
@mcp.tool()
def evtx_hunt(evidence: str) -> ToolResult:
    """Sigma hunt over an EVTX directory with ATT&CK tags (Hayabusa). Read-only on evidence."""
    return _kit().evtx_hunt(evidence)


@mcp.tool()
def evtx_to_json(evidence: str) -> ToolResult:
    """Parse one EVTX file to structured events (EvtxECmd). Read-only on evidence."""
    return _kit().evtx_to_json(evidence)


@mcp.tool()
def evtx_dump_xml(evidence: str) -> ToolResult:
    """Pure-Python EVTX->XML dump fallback (python-evtx). Read-only."""
    return _kit().evtx_dump_xml(evidence)


# --- network --------------------------------------------------------------- #
@mcp.tool()
def pcap_conn_summary(evidence: str) -> ToolResult:
    """Connection summary from a PCAP (tshark). Read-only."""
    return _kit().pcap_conn_summary(evidence)


@mcp.tool()
def pcap_dns(evidence: str) -> ToolResult:
    """DNS queries from a PCAP (tshark). Read-only."""
    return _kit().pcap_dns(evidence)


@mcp.tool()
def pcap_http(evidence: str) -> ToolResult:
    """HTTP requests from a PCAP (tshark). Read-only."""
    return _kit().pcap_http(evidence)


# --- meta ------------------------------------------------------------------ #
@mcp.tool()
def evidence_manifest() -> dict:
    """List evidence files with SHA-256 and size — the integrity baseline."""
    return _kit().evidence_manifest()


@mcp.tool()
def hash_verify(evidence: str, expected_sha256: str) -> dict:
    """Recompute a file's SHA-256 and compare to expected (integrity check)."""
    return _kit().hash_verify(evidence, expected_sha256)


@mcp.tool()
def ioc_extract(tool_exec_id: str) -> dict:
    """Extract IOCs from the captured output of a prior tool execution (grounded)."""
    return _kit().ioc_extract(tool_exec_id)


@mcp.tool()
def attack_map(artifact_key: Optional[str] = None, event_id: Optional[int] = None) -> dict:
    """Map an artifact key or Windows event ID to MITRE ATT&CK technique(s)."""
    return _kit().attack_map(artifact_key=artifact_key, event_id=event_id)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
