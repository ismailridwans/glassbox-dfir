"""CaseContext — wires together the vault, audit chain, raw store, runner,
toolkit, and integrity guard for one case. Used identically by the MCP server,
the CLI, and the LangGraph orchestrator so behavior never diverges between
transports."""

from __future__ import annotations

from glassbox.audit.chain import AuditChain
from glassbox.audit.rawstore import RawStore
from glassbox.config import GlassboxConfig
from glassbox.evidence.integrity import IntegrityGuard
from glassbox.evidence.vault import EvidenceVault
from glassbox.learning.lessons import LessonsLog
from glassbox.mcp_server.runner import ToolPaths, ToolRunner
from glassbox.mcp_server.toolkit import ReadOnlyToolKit


class CaseContext:
    def __init__(self, config: GlassboxConfig, *, replay: bool | None = None):
        self.config = config
        config.ensure_dirs()
        replay = bool(config.replay_dir) if replay is None else replay
        self.replay = replay

        self.audit = AuditChain(config.audit_path)
        self.rawstore = RawStore(config.raw_dir)
        self.vault = EvidenceVault(config.evidence_dir)
        self.runner = ToolRunner(
            self.rawstore,
            self.audit,
            ToolPaths(config.tool_path_overrides),
            replay_dir=config.replay_dir,
        )
        self.toolkit = ReadOnlyToolKit(
            self.vault, self.runner, scratch_dir=config.scratch_dir, replay=replay
        )
        self.integrity = IntegrityGuard(self.vault, self.audit)
        self.lessons = LessonsLog(config.case_dir / "lessons.jsonl")
        self.audit.append(
            "case_open",
            case_id=config.case_id,
            evidence_dir=str(config.evidence_dir),
            replay=replay,
            max_iterations=config.max_iterations,
            glassbox_tools=self.toolkit.list_tools(),
        )

    def known_exec_ids(self) -> list[str]:
        return [te.tool_exec_id for te in self.toolkit.executions]
