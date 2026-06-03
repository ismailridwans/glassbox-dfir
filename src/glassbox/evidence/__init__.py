"""Read-only evidence vault and anti-spoliation integrity guard."""

from glassbox.evidence.integrity import IntegrityGuard, write_probe
from glassbox.evidence.vault import EvidenceVault, VaultError

__all__ = ["EvidenceVault", "VaultError", "IntegrityGuard", "write_probe"]
