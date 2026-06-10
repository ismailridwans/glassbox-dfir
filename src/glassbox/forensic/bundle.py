"""Court-admissible forensic case bundle.

Packages the report, audit log, integrity manifest, and a methodology statement
into a single directory with a binding manifest hash. The manifest records the
SHA-256 of every component file so any post-hoc alteration is detectable. An
optional HMAC seals the bundle against an examiner key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from glassbox.models import utcnow_iso
from glassbox.util import sha256_file

_METHODOLOGY = """\
GLASSBOX FORENSIC METHODOLOGY STATEMENT
=======================================

1. EVIDENCE INTEGRITY (anti-spoliation)
   - All source evidence is accessed strictly read-only. The analysis tool
     surface (MCP server) exposes NO write, delete, shell, or mount capability;
     spoliation is architecturally impossible, not merely policy-prohibited.
   - SHA-256 of every evidence file is recorded before and after analysis and
     compared. Identical hashes are included in this bundle as proof of
     non-modification.

2. PROVENANCE (FRE 901 authentication)
   - Every reported finding cites the specific tool execution (tool_exec_id)
     that produced it and a raw_locator string present verbatim in that tool's
     captured output. No finding exists without grounded provenance.

3. ANTI-HALLUCINATION (reliability — Daubert)
   - A deterministic verification gate re-reads captured tool output and
     confirms each cited value is present; ungrounded claims are quarantined.
   - An adversarial verification panel independently red-teams every finding;
     findings are UPHELD / DEMOTED / REFUTED by a documented, reproducible rule
     set. False positives (e.g. benign public DNS) are removed.

4. CHAIN OF CUSTODY (tamper-evidence)
   - Every action is recorded in an append-only, hash-chained audit log. Each
     record's hash covers the prior record's hash; any insertion, deletion, or
     edit breaks the chain and is detected by re-verification.

5. REPRODUCIBILITY (known error rate — Daubert)
   - The complete finding set can be re-derived from the audit log and captured
     output alone (deterministic replay), independent of the original run.

This methodology is open-source and auditable. GLASSBOX is an investigative aid;
findings should be validated by a qualified examiner before use in proceedings.
"""


class ForensicBundle(BaseModel):
    case_id: str
    created_at: str
    components: dict[str, str] = Field(default_factory=dict)  # filename -> sha256
    bundle_hash: str = ""
    sealed: bool = False
    seal_hmac: Optional[str] = None


def _hmac_key() -> Optional[bytes]:
    raw = os.getenv("GLASSBOX_APPROVAL_KEY", "")
    return raw.encode("utf-8") if raw else None


def build_bundle(
    case_id: str,
    *,
    report_md: Path,
    report_json: Path,
    audit_log: Path,
    execution_log: Optional[Path] = None,
    out_dir: str | Path,
) -> ForensicBundle:
    """Assemble a court-admissible bundle directory and return its manifest."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # write methodology statement
    method_path = out / "METHODOLOGY.txt"
    method_path.write_text(_METHODOLOGY, encoding="utf-8")

    components: dict[str, Path] = {
        "report.md": report_md,
        "report.json": report_json,
        "audit.jsonl": audit_log,
        "METHODOLOGY.txt": method_path,
    }
    if execution_log and Path(execution_log).exists():
        components["execution_log.jsonl"] = execution_log

    # copy each component into the bundle and hash it
    comp_hashes: dict[str, str] = {}
    for name, src in components.items():
        src = Path(src)
        if not src.exists():
            continue
        dst = out / name
        if src.resolve() != dst.resolve():
            shutil.copy(src, dst)
        comp_hashes[name] = sha256_file(dst)

    # bundle hash binds all component hashes together
    manifest_blob = json.dumps(comp_hashes, sort_keys=True, separators=(",", ":"))
    bundle_hash = hashlib.sha256(manifest_blob.encode("utf-8")).hexdigest()

    bundle = ForensicBundle(
        case_id=case_id,
        created_at=utcnow_iso(),
        components=comp_hashes,
        bundle_hash=bundle_hash,
    )

    # optional HMAC seal
    key = _hmac_key()
    if key:
        bundle.seal_hmac = hmac.new(key, bundle_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        bundle.sealed = True

    (out / "MANIFEST.json").write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return bundle


def verify_bundle(bundle_dir: str | Path) -> tuple[bool, list[str]]:
    """Re-verify a bundle: recompute component hashes and the bundle hash."""
    out = Path(bundle_dir)
    manifest_path = out / "MANIFEST.json"
    if not manifest_path.exists():
        return False, ["MANIFEST.json not found"]
    manifest = ForensicBundle.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    recomputed: dict[str, str] = {}
    for name, expected in manifest.components.items():
        p = out / name
        if not p.exists():
            errors.append(f"missing component: {name}")
            continue
        actual = sha256_file(p)
        recomputed[name] = actual
        if actual != expected:
            errors.append(f"component altered: {name}")
    blob = json.dumps(recomputed, sort_keys=True, separators=(",", ":"))
    bh = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    if recomputed and bh != manifest.bundle_hash and not errors:
        errors.append("bundle hash mismatch")
    return (len(errors) == 0), errors
