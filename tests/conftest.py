"""Shared pytest fixtures for the GLASSBOX test suite."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from glassbox.audit.chain import AuditChain
from glassbox.audit.rawstore import RawStore
from glassbox.config import GlassboxConfig
from glassbox.context import CaseContext
from glassbox.evidence.vault import EvidenceVault
from glassbox.mcp_server.runner import ToolRunner
from glassbox.mcp_server.toolkit import ReadOnlyToolKit

DEMO_CASE = Path(__file__).parent.parent / "demo_case"


@pytest.fixture
def tmp_case(tmp_path) -> Path:
    """A writable case directory with the demo fixtures."""
    dst = tmp_path / "demo-cridex-evtx"
    shutil.copytree(DEMO_CASE, dst)
    return dst


@pytest.fixture
def replay_ctx(tmp_case) -> CaseContext:
    """A fully-wired CaseContext using demo replay fixtures."""
    cfg = GlassboxConfig.for_case(
        tmp_case,
        evidence_dir=tmp_case / "evidence",
        replay_dir=tmp_case / "fixtures",
        max_iterations=3,
    )
    return CaseContext(cfg, replay=True)


@pytest.fixture
def empty_vault(tmp_path) -> EvidenceVault:
    ev = tmp_path / "evidence"
    ev.mkdir()
    return EvidenceVault(ev)


@pytest.fixture
def vault_with_files(tmp_path) -> EvidenceVault:
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "mem.vmem").write_bytes(b"FAKE_MEMORY" * 100)
    (ev / "disk.img").write_bytes(b"FAKE_DISK" * 100)
    (ev / "Security.evtx").write_bytes(b"FAKE_EVTX" * 50)
    return EvidenceVault(ev)


@pytest.fixture
def store_and_audit(tmp_path):
    store = RawStore(tmp_path / "raw")
    audit = AuditChain(tmp_path / "audit.jsonl")
    return store, audit


@pytest.fixture
def toolkit(tmp_path) -> ReadOnlyToolKit:
    ev = tmp_path / "evidence"
    ev.mkdir()
    vault = EvidenceVault(ev)
    audit = AuditChain(tmp_path / "audit.jsonl")
    store = RawStore(tmp_path / "raw")
    runner = ToolRunner(store, audit)
    return ReadOnlyToolKit(vault, runner, scratch_dir=tmp_path / "scratch")
