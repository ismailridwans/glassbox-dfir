"""Case configuration.

A *case* is a directory with this layout::

    <case>/
      evidence/        # READ-ONLY source data (disk/mem/evtx/pcap). Never written.
      raw/             # captured verbatim tool output (RawStore)
      scratch/         # tool work area (e.g. Hayabusa output) — never evidence
      reports/         # generated triage reports
      case.audit.jsonl # hash-chained audit trail

Config can be supplied via YAML (``glassbox.yaml`` in the case dir) and/or
environment variables (``GLASSBOX_CASE``, ``GLASSBOX_EVIDENCE``,
``GLASSBOX_MAX_ITERS``, ``GLASSBOX_REPLAY_DIR``, ``GLASSBOX_VOL`` ...).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class GlassboxConfig:
    case_id: str
    case_dir: Path
    evidence_dir: Path
    raw_dir: Path
    scratch_dir: Path
    reports_dir: Path
    audit_path: Path
    max_iterations: int = 3
    recursion_limit: int = 50
    replay_dir: Optional[Path] = None
    tool_path_overrides: dict[str, list[str]] = field(default_factory=dict)
    llm_backend: str = "heuristic"   # "heuristic" (offline) | "anthropic"
    llm_model: str = "claude-opus-4-8"

    @classmethod
    def for_case(
        cls,
        case_dir: str | Path,
        *,
        case_id: Optional[str] = None,
        evidence_dir: Optional[str | Path] = None,
        replay_dir: Optional[str | Path] = None,
        max_iterations: Optional[int] = None,
    ) -> "GlassboxConfig":
        case_dir = Path(case_dir).resolve()
        cfg = cls(
            case_id=case_id or case_dir.name,
            case_dir=case_dir,
            evidence_dir=Path(evidence_dir).resolve() if evidence_dir else case_dir / "evidence",
            raw_dir=case_dir / "raw",
            scratch_dir=case_dir / "scratch",
            reports_dir=case_dir / "reports",
            audit_path=case_dir / "case.audit.jsonl",
            replay_dir=Path(replay_dir).resolve() if replay_dir else None,
        )
        # YAML overrides
        yaml_path = case_dir / "glassbox.yaml"
        if yaml is not None and yaml_path.exists():
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            cfg._apply(data)
        # env overrides (highest priority)
        cfg._apply_env()
        if max_iterations is not None:
            cfg.max_iterations = max_iterations
        return cfg

    def _apply(self, data: dict) -> None:
        if "max_iterations" in data:
            self.max_iterations = int(data["max_iterations"])
        if "recursion_limit" in data:
            self.recursion_limit = int(data["recursion_limit"])
        if "evidence_dir" in data:
            self.evidence_dir = Path(data["evidence_dir"]).resolve()
        if "llm_backend" in data:
            self.llm_backend = str(data["llm_backend"])
        if "llm_model" in data:
            self.llm_model = str(data["llm_model"])
        for key, val in (data.get("tool_paths") or {}).items():
            self.tool_path_overrides[key] = list(val) if isinstance(val, (list, tuple)) else [str(val)]

    def _apply_env(self) -> None:
        if os.getenv("GLASSBOX_MAX_ITERS"):
            self.max_iterations = int(os.environ["GLASSBOX_MAX_ITERS"])
        if os.getenv("GLASSBOX_REPLAY_DIR"):
            self.replay_dir = Path(os.environ["GLASSBOX_REPLAY_DIR"]).resolve()
        if os.getenv("GLASSBOX_EVIDENCE"):
            self.evidence_dir = Path(os.environ["GLASSBOX_EVIDENCE"]).resolve()
        if os.getenv("GLASSBOX_LLM_BACKEND"):
            self.llm_backend = os.environ["GLASSBOX_LLM_BACKEND"]
        # individual tool path overrides, e.g. GLASSBOX_VOL="python3 /opt/volatility3-2.20.0/vol.py"
        for tool in ("vol", "mmls", "fls", "icat", "hayabusa", "evtxecmd", "evtx_dump", "tshark"):
            envk = f"GLASSBOX_{tool.upper()}"
            if os.getenv(envk):
                self.tool_path_overrides[tool] = os.environ[envk].split()

    def ensure_dirs(self) -> None:
        for d in (self.raw_dir, self.scratch_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
