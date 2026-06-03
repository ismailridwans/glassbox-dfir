"""Anti-spoliation integrity guard.

Two functions the accuracy report depends on:

* :class:`IntegrityGuard` snapshots SHA-256 of every evidence file *before* a
  run and re-verifies *after*. Identical hashes are positive proof that the
  triage did not modify the original data (zero spoliation).
* :func:`write_probe` deliberately *attempts* to modify an evidence file to
  demonstrate the control actually holds — answering the hackathon's
  "Did you test for spoliation?" requirement with evidence, not assertion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from glassbox.evidence.vault import EvidenceVault
from glassbox.models import IntegrityRecord
from glassbox.util import sha256_file


class IntegrityGuard:
    """Before/after hash custody for a set of evidence files."""

    def __init__(self, vault: EvidenceVault, audit=None):
        self.vault = vault
        self.audit = audit
        self.baseline: list[IntegrityRecord] = []

    def snapshot(self) -> list[IntegrityRecord]:
        self.baseline = self.vault.manifest()
        if self.audit is not None:
            self.audit.append(
                "integrity_baseline",
                files=[{"path": r.path, "sha256": r.sha256_before, "bytes": r.bytes} for r in self.baseline],
            )
        return self.baseline

    def verify(self) -> list[IntegrityRecord]:
        """Recompute hashes and compare against the baseline."""
        out: list[IntegrityRecord] = []
        for rec in self.baseline:
            after = sha256_file(rec.path) if Path(rec.path).exists() else None
            rec.sha256_after = after
            rec.unchanged = (after == rec.sha256_before)
            out.append(rec)
        if self.audit is not None:
            self.audit.append(
                "integrity_verify",
                results=[
                    {"path": r.path, "unchanged": r.unchanged,
                     "before": r.sha256_before, "after": r.sha256_after}
                    for r in out
                ],
                spoliation_detected=self.spoliation_detected(),
            )
        return out

    def spoliation_detected(self) -> bool:
        return any(r.unchanged is False for r in self.baseline)


def write_probe(vault: EvidenceVault, audit=None) -> dict:
    """Actively try to modify each evidence file; confirm every attempt is
    rejected. Returns a structured result for the accuracy report.

    A passing probe means: for every evidence file, opening it for append/write
    raised an OS error (PermissionError / OSError) — i.e., the read-only posture
    held. If *any* write succeeds, ``spoliation_possible`` is True and the run
    should be treated as untrustworthy.
    """
    results = []
    spoliation_possible = False
    for p in vault.list_evidence():
        before = sha256_file(p)
        blocked = True
        detail = "write rejected by OS (read-only)"
        try:
            with open(p, "ab") as fh:
                fh.write(b"")  # zero-length append still requires write access
                fh.flush()
            # If we got here the FS allowed opening for write. Confirm content
            # is still byte-identical (we wrote nothing), but flag the capability.
            blocked = False
            detail = "WARNING: file opened for write (FS did not block); no bytes written"
            spoliation_possible = True
        except (PermissionError, OSError) as exc:
            detail = f"write rejected: {type(exc).__name__}: {exc}"
        after = sha256_file(p)
        results.append(
            {
                "path": str(p),
                "write_blocked": blocked,
                "sha256_before": before,
                "sha256_after": after,
                "unchanged": before == after,
                "detail": detail,
            }
        )
    summary = {
        "probe": "evidence_write_attempt",
        "files_tested": len(results),
        "all_writes_blocked": all(r["write_blocked"] for r in results) if results else True,
        "all_unchanged": all(r["unchanged"] for r in results) if results else True,
        "spoliation_possible": spoliation_possible,
        "results": results,
    }
    if audit is not None:
        audit.append("spoliation_probe", **summary)
    return summary
