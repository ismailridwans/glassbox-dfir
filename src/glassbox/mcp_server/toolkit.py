"""ReadOnlyToolKit — the typed, read-only tool surface.

This is the entire set of actions the agent can perform on a case. Every method
either reads evidence through the vault or post-processes already-captured tool
output. There is deliberately **no** ``execute_shell``, ``write_file``,
``delete``, ``mount``, or ``icat``-to-evidence method. The agent cannot modify
evidence because no such capability is exposed — the architectural guardrail.

Both transports use this class unchanged:
  * ``server.py``  -> wraps each method in ``@mcp.tool()`` for Claude Code/Desktop.
  * the orchestrator -> calls these methods in-process (no stdio round-trip).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from glassbox.evidence.vault import EvidenceVault, VaultError
from glassbox.ioc.extract import extract_iocs
from glassbox.mcp_server import parsers
from glassbox.mcp_server.parsers_extra import parse_dlllist, parse_regripper_output, parse_yara_output
from glassbox.mcp_server.runner import ToolRunner
from glassbox.models import IOC, Provenance, ToolExecution, ToolStatus
from glassbox.util import sha256_file


class ToolResult(BaseModel):
    """Typed envelope returned by every read-only tool.

    ``tool_exec_id`` + ``evidence_sha256`` are what a downstream finding cites as
    provenance; ``summary`` is the compact parsed structure for the LLM.
    """

    tool: str
    tool_exec_id: str
    status: str
    evidence: Optional[str] = None
    evidence_sha256: Optional[str] = None
    count: Optional[int] = None
    summary: dict = Field(default_factory=dict)
    note: str = ""


class ReadOnlyToolKit:
    def __init__(
        self,
        vault: EvidenceVault,
        runner: ToolRunner,
        *,
        scratch_dir: Optional[str | Path] = None,
        replay: bool = False,
        evidence_hashes: Optional[dict[str, str]] = None,
    ):
        self.vault = vault
        self.runner = runner
        self.replay = replay
        self.scratch = Path(scratch_dir) if scratch_dir else None
        if self.scratch:
            self.scratch.mkdir(parents=True, exist_ok=True)
        self._hashes: dict[str, str] = dict(evidence_hashes or {})
        self.executions: list[ToolExecution] = []

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #
    def _resolve(self, evidence: str) -> tuple[str, Optional[Path]]:
        """Return (label, resolved_path). In replay mode the file need not exist."""
        try:
            p = self.vault.resolve(evidence)
            return str(p), p
        except VaultError:
            if self.replay:
                return evidence, None
            raise

    def _sha(self, label: str, resolved: Optional[Path]) -> Optional[str]:
        if label in self._hashes:
            return self._hashes[label]
        if resolved is not None and resolved.is_file():
            h = sha256_file(resolved)
            self._hashes[label] = h
            return h
        return None

    def _run(
        self,
        *,
        tool: str,
        argv: list[str],
        parser,
        evidence: Optional[str] = None,
        agent: str = "system",
        replay_key: Optional[str] = None,
        capture_file: Optional[Path] = None,
    ) -> ToolResult:
        label, resolved = (None, None)
        sha = None
        if evidence is not None:
            label, resolved = self._resolve(evidence)
            sha = self._sha(label, resolved)
            # substitute the resolved absolute path into argv where the caller
            # used the {EV} placeholder
            argv = [str(resolved) if (a == "{EV}" and resolved) else (label if a == "{EV}" else a)
                    for a in argv]
        te = self.runner.run(
            tool=tool,
            argv=argv,
            parser=parser,
            evidence_path=label,
            evidence_sha256=sha,
            agent=agent,
            replay_key=replay_key or (f"{tool}" if self.replay else None),
            capture_file=capture_file,
        )
        self.executions.append(te)
        return ToolResult(
            tool=tool,
            tool_exec_id=te.tool_exec_id,
            status=te.status.value,
            evidence=label,
            evidence_sha256=sha,
            count=te.parsed_summary.get("count") if isinstance(te.parsed_summary, dict) else None,
            summary=te.parsed_summary,
            note=te.stderr_excerpt[:240],
        )

    # ================================================================== #
    # MEMORY (Volatility 3)
    # ================================================================== #
    def _vol(self, evidence: str, plugin: str, parser, *, tool: str, agent: str) -> ToolResult:
        argv = [*self.runner.tool_paths.argv("vol"), "-q", "-r", "json", "-f", "{EV}", plugin]
        return self._run(tool=tool, argv=argv, parser=parser, evidence=evidence,
                         agent=agent, replay_key=tool if self.replay else None)

    def mem_pslist(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """List active processes (EPROCESS walk) from a memory image. Read-only."""
        return self._vol(evidence, "windows.pslist", parsers.normalize_processes,
                         tool="mem_pslist", agent=agent)

    def mem_pstree(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """Process tree (parent/child) from a memory image. Read-only."""
        return self._vol(evidence, "windows.pstree", parsers.normalize_processes,
                         tool="mem_pstree", agent=agent)

    def mem_psscan(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """Pool-scan for processes — finds hidden/unlinked/terminated procs. Read-only."""
        return self._vol(evidence, "windows.psscan", parsers.normalize_processes,
                         tool="mem_psscan", agent=agent)

    def mem_netscan(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """Network connections/sockets recovered from a memory image. Read-only."""
        return self._vol(evidence, "windows.netscan", parsers.normalize_netscan,
                         tool="mem_netscan", agent=agent)

    def mem_malfind(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """Find injected/hidden code (RWX private memory, PE headers). Read-only."""
        return self._vol(evidence, "windows.malfind", parsers.normalize_malfind,
                         tool="mem_malfind", agent=agent)

    def mem_cmdline(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """Per-process command lines from a memory image. Read-only."""
        return self._vol(evidence, "windows.cmdline", parsers.normalize_cmdline,
                         tool="mem_cmdline", agent=agent)

    def mem_svcscan(self, evidence: str, agent: str = "memory_analyst") -> ToolResult:
        """Enumerate Windows services from a memory image. Read-only."""
        return self._vol(evidence, "windows.svcscan", parsers.normalize_svcscan,
                         tool="mem_svcscan", agent=agent)

    def mem_dlllist(self, evidence: str, pid: Optional[int] = None,
                    agent: str = "memory_analyst") -> ToolResult:
        """Enumerate loaded DLLs per process (windows.dlllist). Read-only.

        Args:
            evidence: memory image path inside the vault.
            pid: optional PID filter; omit to list all processes.
        """
        plugin = "windows.dlllist"
        argv = [*self.runner.tool_paths.argv("vol"), "-q", "-r", "json", "-f", "{EV}", plugin]
        if pid is not None:
            argv += ["--pid", str(pid)]
        return self._run(tool="mem_dlllist", argv=argv, parser=parse_dlllist,
                         evidence=evidence, agent=agent,
                         replay_key="mem_dlllist" if self.replay else None)

    # ================================================================== #
    # YARA (memory and file scanning)
    # ================================================================== #
    def yara_scan(self, evidence: str, rules_path: Optional[str] = None,
                  agent: str = "memory_analyst") -> ToolResult:
        """Scan a memory image or file against YARA rules. Read-only.

        Args:
            evidence: path to the evidence file inside the vault.
            rules_path: path to a .yar file or directory of rules. Defaults to
                        the bundled GLASSBOX rules in rules/yara/.
        """
        if rules_path is None:
            # Bundled rules relative to package root
            pkg_root = Path(__file__).parent.parent.parent.parent
            rp = pkg_root / "rules" / "yara"
            if not rp.exists():
                rp = Path("rules") / "yara"
            rules_path = str(rp)
        argv = [*self.runner.tool_paths.argv("yara"), "-r", rules_path, "{EV}"]
        return self._run(tool="yara_scan", argv=argv, parser=parse_yara_output,
                         evidence=evidence, agent=agent,
                         replay_key="yara_scan" if self.replay else None)

    # ================================================================== #
    # REGISTRY (RegRipper)
    # ================================================================== #
    def registry_analyze(self, evidence: str, plugin: str = "all",
                         agent: str = "disk_analyst") -> ToolResult:
        """Run RegRipper against a registry hive. Read-only.

        Args:
            evidence: path to the registry hive file (NTUSER.DAT, SYSTEM, etc.) inside the vault.
            plugin: RegRipper plugin name (e.g. 'run', 'services', 'all').
        """
        argv = [*self.runner.tool_paths.argv("regripper"), "-r", "{EV}", "-p", plugin]
        return self._run(tool="registry_analyze", argv=argv, parser=parse_regripper_output,
                         evidence=evidence, agent=agent,
                         replay_key=f"registry_analyze_{plugin}" if self.replay else None)

    # ================================================================== #
    # DISK (The Sleuth Kit)
    # ================================================================== #
    def disk_partition_table(self, evidence: str, agent: str = "disk_analyst") -> ToolResult:
        """Partition table of a disk image (mmls). Read-only."""
        argv = [*self.runner.tool_paths.argv("mmls"), "{EV}"]
        return self._run(tool="disk_partition_table", argv=argv, parser=parsers.parse_mmls,
                         evidence=evidence, agent=agent)

    def disk_list_files(self, evidence: str, offset: Optional[int] = None,
                        agent: str = "disk_analyst") -> ToolResult:
        """Recursive file listing with inodes (fls -r -p). Read-only.

        Args:
            evidence: disk image inside the vault.
            offset: partition start sector (from disk_partition_table), if any.
        """
        argv = [*self.runner.tool_paths.argv("fls"), "-r", "-p"]
        if offset is not None:
            argv += ["-o", str(offset)]
        argv += ["{EV}"]
        return self._run(tool="disk_list_files", argv=argv, parser=parsers.parse_fls,
                         evidence=evidence, agent=agent)

    def disk_mft_timeline(self, evidence: str, offset: Optional[int] = None,
                          agent: str = "disk_analyst") -> ToolResult:
        """Filesystem timeline body file (fls -r -m). Read-only."""
        argv = [*self.runner.tool_paths.argv("fls"), "-r", "-m", "/"]
        if offset is not None:
            argv += ["-o", str(offset)]
        argv += ["{EV}"]
        return self._run(tool="disk_mft_timeline", argv=argv, parser=parsers.parse_bodyfile,
                         evidence=evidence, agent=agent)

    # ================================================================== #
    # EVTX (Windows event logs)
    # ================================================================== #
    def evtx_hunt(self, evidence: str, agent: str = "evtx_analyst") -> ToolResult:
        """Sigma-based hunt over an EVTX directory (Hayabusa), with ATT&CK tags.
        Reads evidence; writes only to the scratch output dir. Read-only on evidence."""
        out = (self.scratch / "hayabusa.jsonl") if self.scratch else None
        argv = [*self.runner.tool_paths.argv("hayabusa"), "json-timeline",
                "-d", "{EV}", "-o", str(out) if out else "hayabusa.jsonl", "-L", "-w"]
        return self._run(tool="evtx_hunt", argv=argv, parser=parsers.parse_hayabusa_json,
                         evidence=evidence, agent=agent, capture_file=out)

    def evtx_to_json(self, evidence: str, agent: str = "evtx_analyst") -> ToolResult:
        """Parse a single EVTX file to structured events (EvtxECmd). Read-only on evidence."""
        outdir = self.scratch or Path(".")
        argv = [*self.runner.tool_paths.argv("evtxecmd"), "-f", "{EV}",
                "--json", str(outdir), "--jsonf", "evtxecmd.json"]
        cap = (outdir / "evtxecmd.json")
        return self._run(tool="evtx_to_json", argv=argv, parser=parsers.parse_evtxecmd_json,
                         evidence=evidence, agent=agent, capture_file=cap)

    def evtx_dump_xml(self, evidence: str, agent: str = "evtx_analyst") -> ToolResult:
        """Pure-Python EVTX->XML dump (python-evtx) fallback. Read-only."""
        argv = [*self.runner.tool_paths.argv("evtx_dump"), "{EV}"]
        return self._run(tool="evtx_dump_xml", argv=argv, parser=parsers.parse_evtx_xml,
                         evidence=evidence, agent=agent)

    # ================================================================== #
    # NETWORK (tshark)
    # ================================================================== #
    def pcap_conn_summary(self, evidence: str, agent: str = "network_analyst") -> ToolResult:
        """TCP/IP connection summary from a PCAP (tshark -T fields). Read-only."""
        cols = ["frame.time_epoch", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "_ws.col.Protocol"]
        argv = [*self.runner.tool_paths.argv("tshark"), "-r", "{EV}", "-T", "fields",
                *sum((["-e", c] for c in cols), []), "-E", "header=y"]
        return self._run(tool="pcap_conn_summary", argv=argv,
                         parser=lambda r: parsers.parse_tshark_tsv(r, cols),
                         evidence=evidence, agent=agent)

    def pcap_dns(self, evidence: str, agent: str = "network_analyst") -> ToolResult:
        """DNS queries from a PCAP (tshark). Read-only."""
        cols = ["frame.time_epoch", "ip.src", "dns.qry.name"]
        argv = [*self.runner.tool_paths.argv("tshark"), "-r", "{EV}", "-Y", "dns.flags.response==0",
                "-T", "fields", *sum((["-e", c] for c in cols), []), "-E", "header=y"]
        return self._run(tool="pcap_dns", argv=argv,
                         parser=lambda r: parsers.parse_tshark_tsv(r, cols),
                         evidence=evidence, agent=agent)

    def pcap_http(self, evidence: str, agent: str = "network_analyst") -> ToolResult:
        """HTTP requests from a PCAP (tshark). Read-only."""
        cols = ["ip.dst", "http.host", "http.request.method", "http.request.full_uri"]
        argv = [*self.runner.tool_paths.argv("tshark"), "-r", "{EV}", "-Y", "http.request",
                "-T", "fields", *sum((["-e", c] for c in cols), []), "-E", "header=y"]
        return self._run(tool="pcap_http", argv=argv,
                         parser=lambda r: parsers.parse_tshark_tsv(r, cols),
                         evidence=evidence, agent=agent)

    # ================================================================== #
    # META (no subprocess; operate on the vault / captured output)
    # ================================================================== #
    def evidence_manifest(self) -> dict:
        """List evidence files with SHA-256 and size (the integrity baseline)."""
        recs = self.vault.manifest()
        for r in recs:
            self._hashes[r.path] = r.sha256_before
        return {
            "count": len(recs),
            "evidence": [
                {"path": r.path, "sha256": r.sha256_before, "bytes": r.bytes,
                 "type": self.vault.classify(r.path).value}
                for r in recs
            ],
        }

    def hash_verify(self, evidence: str, expected_sha256: str) -> dict:
        """Recompute the SHA-256 of an evidence file and compare to expected."""
        label, resolved = self._resolve(evidence)
        actual = self._sha(label, resolved)
        return {"evidence": label, "expected": expected_sha256, "actual": actual,
                "match": actual == expected_sha256}

    def ioc_extract(self, tool_exec_id: str, agent: str = "system") -> dict:
        """Extract IOCs from the captured raw output of a prior tool execution.

        The IOCs are grounded: each one's provenance points back to
        ``tool_exec_id`` and the verifier can confirm the value is present there.
        """
        raw = self.runner.rawstore.get_raw(tool_exec_id)
        if raw is None:
            return {"count": 0, "iocs": [], "note": f"no captured output for {tool_exec_id}"}
        prov = [Provenance(tool_exec_id=tool_exec_id, tool="ioc_extract", raw_locator="", note="source output")]
        iocs: list[IOC] = extract_iocs(raw, context=f"from {tool_exec_id}", provenance=prov)
        # set each IOC's locator to its own value so the verifier checks it
        for ioc in iocs:
            for p in ioc.provenance:
                p.raw_locator = ioc.value
        return {"count": len(iocs), "iocs": [i.model_dump() for i in iocs]}

    def attack_map(self, *, artifact_key: Optional[str] = None,
                   event_id: Optional[int] = None) -> dict:
        """Map an artifact key or Windows event ID to MITRE ATT&CK technique(s)."""
        from glassbox.attack import for_artifact, for_event_id

        mappings = []
        if artifact_key:
            mappings += for_artifact(artifact_key)
        if event_id is not None:
            mappings += for_event_id(int(event_id))
        return {"count": len(mappings), "mappings": [m.model_dump() for m in mappings]}

    # ------------------------------------------------------------------ #
    def list_tools(self) -> list[str]:
        return [
            # Memory (Volatility 3)
            "mem_pslist", "mem_pstree", "mem_psscan", "mem_netscan", "mem_malfind",
            "mem_cmdline", "mem_svcscan", "mem_dlllist",
            # YARA
            "yara_scan",
            # Disk (Sleuth Kit)
            "disk_partition_table", "disk_list_files", "disk_mft_timeline",
            # Registry (RegRipper)
            "registry_analyze",
            # EVTX
            "evtx_hunt", "evtx_to_json", "evtx_dump_xml",
            # Network (tshark)
            "pcap_conn_summary", "pcap_dns", "pcap_http",
            # Meta
            "evidence_manifest", "hash_verify", "ioc_extract", "attack_map",
        ]
