"""Evidence vault: path-traversal rejection and read-only posture."""

import os
import pytest
from glassbox.evidence.vault import EvidenceVault, VaultError


@pytest.fixture
def vault(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "mem.vmem").write_bytes(b"FAKE_MEMORY_IMAGE" * 100)
    (ev / "disk.img").write_bytes(b"FAKE_DISK_IMAGE" * 100)
    return EvidenceVault(ev)


def test_resolve_valid_file(vault):
    p = vault.resolve("mem.vmem")
    assert p.exists()


def test_path_traversal_blocked(vault):
    with pytest.raises(VaultError, match="path traversal"):
        vault.resolve("../../etc/passwd")


def test_absolute_outside_vault_blocked(vault, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    with pytest.raises(VaultError, match="path traversal"):
        vault.resolve(str(outside))


def test_nonexistent_file_raises(vault):
    with pytest.raises(VaultError):
        vault.resolve("nonexistent.vmem")


def test_classify_memory(vault):
    from glassbox.models import EvidenceType
    assert vault.classify("mem.vmem") == EvidenceType.MEMORY


def test_classify_disk(vault):
    from glassbox.models import EvidenceType
    assert vault.classify("disk.img") == EvidenceType.DISK


def test_manifest_hashes_consistent(vault):
    recs = vault.manifest()
    assert len(recs) == 2
    # re-running gives the same hashes (content-addressed)
    recs2 = vault.manifest()
    for r1, r2 in zip(sorted(recs, key=lambda r: r.path),
                       sorted(recs2, key=lambda r: r.path)):
        assert r1.sha256_before == r2.sha256_before


def test_integrity_guard_no_spoliation(vault):
    from glassbox.evidence.integrity import IntegrityGuard
    guard = IntegrityGuard(vault)
    guard.snapshot()
    recs = guard.verify()
    assert all(r.unchanged for r in recs)
    assert not guard.spoliation_detected()
