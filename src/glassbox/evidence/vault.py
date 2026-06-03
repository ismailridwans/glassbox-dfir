"""The read-only evidence vault.

The vault is the *first* architectural guardrail: a directory of evidence that
the agent may read but cannot reach to write. Three enforcement layers, in
order of strength:

1. **OS read-only mount** (recommended for real cases): mount the image
   directory ``-o ro`` / use ``ewfmount`` (read-only by design) / a write
   blocker. GLASSBOX never relies on this alone but documents it.
2. **Filesystem permissions**: :meth:`EvidenceVault.harden` strips write bits
   (POSIX ``0o555``/``0o444``; Windows read-only attribute) so even the user
   running GLASSBOX cannot casually clobber evidence.
3. **No write primitive in the tool surface**: the MCP server exposes only
   typed read functions. There is literally no ``write_file`` / ``execute_shell``
   tool for the model to call. (Enforced in ``glassbox.mcp_server``.)

The vault also rejects path traversal: every path an agent references is
resolved and confirmed to live inside the vault root, so ``../../etc/passwd``
or ``C:\\Windows`` can never be opened through it.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from glassbox.models import EvidenceType, IntegrityRecord
from glassbox.util import sha256_file

# Extension -> evidence type. ``.raw``/``.dmp`` are ambiguous (disk vs memory);
# resolved by name hint, else left UNKNOWN for the case manifest to override.
_EXT_TYPE = {
    ".e01": EvidenceType.DISK, ".ex01": EvidenceType.DISK, ".dd": EvidenceType.DISK,
    ".img": EvidenceType.DISK, ".001": EvidenceType.DISK, ".vhd": EvidenceType.DISK,
    ".vhdx": EvidenceType.DISK,
    ".vmem": EvidenceType.MEMORY, ".mem": EvidenceType.MEMORY, ".lime": EvidenceType.MEMORY,
    ".vmss": EvidenceType.MEMORY, ".vmsn": EvidenceType.MEMORY, ".dump": EvidenceType.MEMORY,
    ".evtx": EvidenceType.EVTX,
    ".pcap": EvidenceType.PCAP, ".pcapng": EvidenceType.PCAP, ".cap": EvidenceType.PCAP,
    # Registry hives (by name pattern — also handled in classify())
    ".dat": EvidenceType.REGISTRY, ".hiv": EvidenceType.REGISTRY, ".reg": EvidenceType.REGISTRY,
}


class VaultError(Exception):
    """Raised on path traversal or access outside the vault root."""


class EvidenceVault:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise VaultError(f"evidence vault root does not exist: {self.root}")
        if not self.root.is_dir():
            raise VaultError(f"evidence vault root is not a directory: {self.root}")

    # ------------------------------------------------------------------ #
    # Path safety
    # ------------------------------------------------------------------ #
    def resolve(self, path: str | Path) -> Path:
        """Resolve ``path`` and confirm it is inside the vault. Accepts a bare
        filename, a relative path, or an absolute path that must still be a
        descendant of the vault root."""
        p = Path(path)
        candidate = (p if p.is_absolute() else (self.root / p)).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise VaultError(
                f"path traversal blocked: {path!r} resolves outside the vault ({candidate})"
            ) from exc
        if not candidate.exists():
            raise VaultError(f"evidence not found in vault: {candidate}")
        return candidate

    def open_ro(self, path: str | Path):
        """Open an evidence file strictly read-only (binary)."""
        return open(self.resolve(path), "rb")

    # ------------------------------------------------------------------ #
    # Inventory
    # ------------------------------------------------------------------ #
    # Files to skip — placeholders, readmes, stubs that are not real evidence.
    _SKIP = {".gitkeep", ".gitignore", "readme.md", "readme.txt"}
    _SKIP_SUFFIX = {".md", ".txt", ".py", ".yaml", ".yml", ".json", ".xml"}

    def list_evidence(self) -> list[Path]:
        out: list[Path] = []
        for p in self.root.rglob("*"):
            if not p.is_file():
                continue
            if p.name.lower() in self._SKIP:
                continue
            # For known-text extensions: skip stubs and unrecognised types
            if p.suffix.lower() in self._SKIP_SUFFIX:
                try:
                    head = p.read_bytes()[:512]
                    if b"GLASSBOX_REPLAY_STUB" in head:
                        continue
                except OSError:
                    pass
                if self.classify(p) == EvidenceType.UNKNOWN:
                    continue
            # Registry hives (.dat/.hiv/.reg) — let stub files through.
            # In replay mode, the stub IS the evidence placeholder; the fixture file provides the data.
            # In live mode, real hives don't contain GLASSBOX_REPLAY_STUB so they always pass.
            out.append(p)
        return sorted(out)

    @staticmethod
    def classify(path: str | Path) -> EvidenceType:
        p = Path(path)
        ext = p.suffix.lower()
        t = _EXT_TYPE.get(ext)
        if t:
            # Narrow .dat — only registry hive names are REGISTRY, others stay UNKNOWN
            if t == EvidenceType.REGISTRY and ext == ".dat":
                name = p.name.upper()
                _REGISTRY_HIVES = {"NTUSER.DAT", "USRCLASS.DAT", "SAM", "SECURITY", "SOFTWARE",
                                   "SYSTEM", "COMPONENTS", "BCD", "DEFAULT"}
                if name not in _REGISTRY_HIVES:
                    return EvidenceType.UNKNOWN
            return t
        if ext in (".raw", ".dmp", ".bin"):
            name = p.name.lower()
            if any(h in name for h in ("mem", "ram", "dump")):
                return EvidenceType.MEMORY
            if any(h in name for h in ("disk", "img", "hdd")):
                return EvidenceType.DISK
        return EvidenceType.UNKNOWN

    def manifest(self) -> list[IntegrityRecord]:
        """SHA-256 + size for every evidence file (the baseline for the
        integrity guard and the dataset documentation)."""
        records: list[IntegrityRecord] = []
        for p in self.list_evidence():
            records.append(
                IntegrityRecord(
                    path=str(p),
                    sha256_before=sha256_file(p),
                    bytes=p.stat().st_size,
                )
            )
        return records

    # ------------------------------------------------------------------ #
    # Hardening (defense in depth — layer 2)
    # ------------------------------------------------------------------ #
    def harden(self) -> dict[str, str]:
        """Strip write permissions from the vault (best-effort, cross-platform).

        Returns a per-path status map. This is *defense in depth*; the primary
        guarantee is that no write tool exists. On a real case, also mount the
        source read-only / use a hardware write blocker.
        """
        status: dict[str, str] = {}
        for p in [self.root, *self.list_evidence()]:
            try:
                if os.name == "nt":
                    os.chmod(p, stat.S_IREAD)  # toggles the Windows read-only attr for files
                    status[str(p)] = "read-only attribute set"
                else:
                    mode = 0o555 if p.is_dir() else 0o444
                    os.chmod(p, mode)
                    status[str(p)] = f"mode {oct(mode)}"
            except OSError as exc:  # pragma: no cover - platform dependent
                status[str(p)] = f"could not harden: {exc}"
        return status
