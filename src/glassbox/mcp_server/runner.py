"""Safe, read-only tool runner.

Every underlying SIFT CLI is invoked here, and *only* here. Guarantees:

* **No shell.** Commands are argv lists passed to ``subprocess.run`` without
  ``shell=True``; there is no string interpolation an injected evidence string
  could exploit.
* **Read-only argv.** The toolkit only ever constructs read flags (``fls``,
  ``icat``, ``vol ... windows.pslist``, ``tshark -r`` …). No wrapper writes to
  the evidence path.
* **Full capture + provenance.** Raw output is content-addressed into the
  RawStore; a :class:`~glassbox.models.ToolExecution` is recorded; and a compact
  event is appended to the hash-chained audit log. The raw bytes are never
  altered, so the hallucination verifier can trust them.
* **Graceful degradation.** A missing binary → ``UNAVAILABLE``; a non-zero exit
  → ``ERROR``; a timeout → ``TIMEOUT``. The orchestrator routes around these
  instead of crashing.
* **Replay mode.** Point the runner at a fixtures directory and it serves canned
  raw output through the identical parse/store/audit path — so the offline demo
  and the unit tests exercise real code without needing SIFT installed.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional, Sequence

from glassbox.audit.chain import AuditChain
from glassbox.audit.rawstore import RawStore
from glassbox.models import ToolExecution, ToolStatus
from glassbox.util import sha256_bytes

# A parser turns raw text into a compact structured summary for the LLM.
Parser = Callable[[str], dict]


class ToolPaths:
    """Resolved invocation prefixes for SIFT tools (verified defaults).

    Override any of these via the case config or environment. ``vol`` and
    ``evtxecmd`` are multi-token because they launch through an interpreter.
    """

    def __init__(self, overrides: Optional[dict[str, list[str]]] = None):
        self.paths: dict[str, list[str]] = {
            # memory
            "vol": ["vol"],  # or ["python3", "/opt/volatility3-2.20.0/vol.py"]
            # disk (Sleuth Kit natives)
            "mmls": ["mmls"], "fls": ["fls"], "icat": ["icat"], "mactime": ["mactime"],
            # evtx
            "hayabusa": ["hayabusa"],
            "evtxecmd": ["dotnet", "/opt/zimmermantools/EvtxECmd.dll"],
            "evtx_dump": ["evtx_dump.py"],
            # network
            "tshark": ["tshark"],
            # registry / misc
            "regripper": ["rip.pl"],
        }
        if overrides:
            self.paths.update(overrides)

    def argv(self, tool: str) -> list[str]:
        return list(self.paths.get(tool, [tool]))

    def available(self, tool: str) -> bool:
        prefix = self.argv(tool)
        head = prefix[0]
        if shutil.which(head) is not None:
            return True
        # interpreter-launched tools: also require the script/dll to exist
        if len(prefix) > 1 and Path(prefix[-1]).exists() and shutil.which(head) is not None:
            return True
        return Path(head).exists()


class ToolRunner:
    def __init__(
        self,
        rawstore: RawStore,
        audit: AuditChain,
        tool_paths: Optional[ToolPaths] = None,
        *,
        timeout: int = 600,
        replay_dir: Optional[str | Path] = None,
    ):
        self.rawstore = rawstore
        self.audit = audit
        self.tool_paths = tool_paths or ToolPaths()
        self.timeout = timeout
        self.replay_dir = Path(replay_dir) if replay_dir else None
        self._counter = 0

    def _next_id(self, tool: str) -> str:
        self._counter += 1
        return f"TE{self._counter:04d}-{tool}"

    def _replay(self, replay_key: str) -> Optional[str]:
        if self.replay_dir is None or not replay_key:
            return None
        for ext in (".txt", ".json", ".out"):
            cand = self.replay_dir / f"{replay_key}{ext}"
            if cand.exists():
                return cand.read_text(encoding="utf-8", errors="replace")
        return None

    def run(
        self,
        *,
        tool: str,
        argv: Sequence[str],
        parser: Optional[Parser] = None,
        evidence_path: Optional[str] = None,
        evidence_sha256: Optional[str] = None,
        agent: str = "system",
        replay_key: Optional[str] = None,
        capture_file: Optional[str | Path] = None,
    ) -> ToolExecution:
        """Execute one read-only tool and record everything about it."""
        exec_id = self._next_id(tool)
        cmd_str = " ".join(str(a) for a in argv)
        started = time.time()
        status = ToolStatus.OK
        exit_code: Optional[int] = None
        stderr_excerpt = ""
        raw = ""

        replayed = self._replay(replay_key) if replay_key else None
        if replayed is not None:
            raw = replayed
            cmd_str = f"[replay:{replay_key}] {cmd_str}"
        else:
            base_tool = argv[0] if argv else tool
            # Resolve availability by the logical tool name when known.
            if not self.tool_paths.available(tool) and shutil.which(str(base_tool)) is None and not Path(str(base_tool)).exists():
                status = ToolStatus.UNAVAILABLE
                stderr_excerpt = f"binary for '{tool}' not found on PATH/SIFT paths"
            else:
                try:
                    proc = subprocess.run(
                        list(map(str, argv)),
                        capture_output=True,
                        text=True,
                        timeout=self.timeout,
                        shell=False,  # never a shell
                    )
                    exit_code = proc.returncode
                    stderr_excerpt = (proc.stderr or "")[:2000]
                    if capture_file is not None and Path(capture_file).exists():
                        raw = Path(capture_file).read_text(encoding="utf-8", errors="replace")
                    else:
                        raw = proc.stdout or ""
                    if exit_code != 0:
                        status = ToolStatus.ERROR if not raw else ToolStatus.DEGRADED
                except subprocess.TimeoutExpired:
                    status = ToolStatus.TIMEOUT
                    stderr_excerpt = f"timeout after {self.timeout}s"
                except OSError as exc:
                    status = ToolStatus.ERROR
                    stderr_excerpt = f"{type(exc).__name__}: {exc}"

        parsed: dict = {}
        if raw and parser is not None:
            try:
                parsed = parser(raw)
            except Exception as exc:  # parser robustness: never crash a run
                status = ToolStatus.DEGRADED if status == ToolStatus.OK else status
                parsed = {"parse_error": f"{type(exc).__name__}: {exc}"}

        self.rawstore.put(exec_id, raw, parsed)
        ended = time.time()
        duration_ms = int((ended - started) * 1000)
        stdout_sha = sha256_bytes(raw.encode("utf-8")) if raw else None

        te = ToolExecution(
            tool_exec_id=exec_id,
            tool=tool,
            command=cmd_str,
            evidence_path=evidence_path,
            evidence_sha256=evidence_sha256,
            ended_at=None,
            duration_ms=duration_ms,
            exit_code=exit_code,
            status=status,
            stdout_sha256=stdout_sha,
            raw_output_ref=exec_id,
            parsed_summary=parsed,
            stderr_excerpt=stderr_excerpt,
            agent=agent,
        )
        # Compact, traceable audit record (never the full raw dump).
        self.audit.append(
            "tool_execution",
            tool_exec_id=exec_id,
            tool=tool,
            command=cmd_str,
            agent=agent,
            evidence_sha256=evidence_sha256,
            status=status.value,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_sha256=stdout_sha,
            n_records=parsed.get("count") if isinstance(parsed, dict) else None,
            raw_output_ref=exec_id,
        )
        return te
