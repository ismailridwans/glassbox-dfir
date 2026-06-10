"""Architectural guardrail self-test.

The hackathon's criterion #4 asks: *"Are guardrails architectural or
prompt-based? Judges evaluate where security boundaries are enforced and whether
they were tested for bypass."*

This module actively tests every architectural boundary and returns a pass/fail
report. It does not trust documentation — it *exercises* the controls:

  1. NO_WRITE_TOOL   — the MCP tool surface exposes no write/shell/delete tool.
  2. PATH_TRAVERSAL  — the vault rejects ../ and absolute paths outside the root.
  3. EVIDENCE_RO     — a direct write attempt on evidence is blocked / detected.
  4. AUDIT_TAMPER    — altering an audit record is detected by chain re-verify.
  5. HALLUCINATION   — a fabricated claim is quarantined by the gate.
  6. HMAC_APPROVAL   — a tampered approval token is rejected.

Run via:  glassbox guardrail-selftest
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pydantic import BaseModel, Field


class GuardrailCheck(BaseModel):
    name: str
    passed: bool
    detail: str


class GuardrailReport(BaseModel):
    checks: list[GuardrailCheck] = Field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def summary(self) -> dict:
        return {
            "all_passed": self.all_passed,
            "passed": sum(1 for c in self.checks if c.passed),
            "total": len(self.checks),
            "checks": [c.model_dump() for c in self.checks],
        }


def run_guardrail_selftest() -> GuardrailReport:
    rep = GuardrailReport()

    # 1) NO write/shell tool in the MCP surface
    try:
        from glassbox.audit.chain import AuditChain
        from glassbox.audit.rawstore import RawStore
        from glassbox.evidence.vault import EvidenceVault
        from glassbox.mcp_server.runner import ToolRunner
        from glassbox.mcp_server.toolkit import ReadOnlyToolKit

        t = Path(tempfile.mkdtemp())
        (t / "evidence").mkdir()
        (t / "evidence" / "mem.vmem").write_bytes(b"x" * 64)
        v = EvidenceVault(t / "evidence")
        r = ToolRunner(RawStore(t / "raw"), AuditChain(t / "a.jsonl"))
        kit = ReadOnlyToolKit(v, r)
        tools = set(kit.list_tools())
        forbidden = {"execute_shell", "write_file", "delete", "Bash", "rm",
                     "mount", "dd", "shell", "exec", "icat_to_evidence"}
        found = tools & forbidden
        rep.checks.append(GuardrailCheck(
            name="NO_WRITE_TOOL", passed=(not found),
            detail=(f"{len(tools)} read-only tools registered; forbidden tools present: "
                    f"{sorted(found) or 'none'}")))
    except Exception as exc:
        rep.checks.append(GuardrailCheck(name="NO_WRITE_TOOL", passed=False, detail=f"error: {exc}"))

    # 2) Path traversal rejection
    try:
        from glassbox.evidence.vault import EvidenceVault, VaultError
        t = Path(tempfile.mkdtemp())
        (t / "evidence").mkdir()
        (t / "evidence" / "ok.vmem").write_bytes(b"x" * 16)
        v = EvidenceVault(t / "evidence")
        blocked = False
        try:
            v.resolve("../../etc/passwd")
        except VaultError:
            blocked = True
        rep.checks.append(GuardrailCheck(
            name="PATH_TRAVERSAL", passed=blocked,
            detail="../../etc/passwd " + ("rejected by vault.resolve()" if blocked else "WAS NOT blocked")))
    except Exception as exc:
        rep.checks.append(GuardrailCheck(name="PATH_TRAVERSAL", passed=False, detail=f"error: {exc}"))

    # 3) Evidence read-only write-probe
    try:
        from glassbox.evidence.integrity import write_probe
        from glassbox.evidence.vault import EvidenceVault
        t = Path(tempfile.mkdtemp())
        (t / "evidence").mkdir()
        ev = (t / "evidence" / "disk.img")
        ev.write_bytes(b"EVIDENCE" * 32)
        v = EvidenceVault(t / "evidence")
        v.harden()  # strip write bits (defense in depth)
        probe = write_probe(v)
        # pass if no spoliation occurred (files unchanged) regardless of FS enforcement
        rep.checks.append(GuardrailCheck(
            name="EVIDENCE_RO", passed=probe["all_unchanged"],
            detail=(f"write-probe: {probe['files_tested']} file(s); all_unchanged="
                    f"{probe['all_unchanged']}, writes_blocked={probe['all_writes_blocked']}")))
    except Exception as exc:
        rep.checks.append(GuardrailCheck(name="EVIDENCE_RO", passed=False, detail=f"error: {exc}"))

    # 4) Audit tamper detection
    try:
        import json
        from glassbox.audit.chain import AuditChain
        t = Path(tempfile.mkdtemp())
        chain = AuditChain(t / "audit.jsonl")
        for i in range(3):
            chain.append("test", i=i)
        lines = (t / "audit.jsonl").read_text("utf-8").splitlines()
        rec = json.loads(lines[1]); rec["event"]["i"] = 999
        lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        (t / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, errs = AuditChain.verify(t / "audit.jsonl")
        rep.checks.append(GuardrailCheck(
            name="AUDIT_TAMPER", passed=(not ok),
            detail=("tampered record detected by chain re-verify" if not ok
                    else "TAMPER NOT DETECTED")))
    except Exception as exc:
        rep.checks.append(GuardrailCheck(name="AUDIT_TAMPER", passed=False, detail=f"error: {exc}"))

    # 5) Hallucination gate
    try:
        from glassbox.audit.chain import AuditChain
        from glassbox.audit.rawstore import RawStore
        from glassbox.models import Confidence, EvidenceType, Finding, Provenance, Severity
        from glassbox.util import stable_id
        from glassbox.verify import verify_findings
        t = Path(tempfile.mkdtemp())
        store = RawStore(t / "raw"); audit = AuditChain(t / "a.jsonl")
        store.put("TE1", "benign output only", None)
        f = Finding(finding_id=stable_id("F", "x"), title="fabricated",
                    evidence_type=EvidenceType.MEMORY, severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED, source_agent="t",
                    provenance=[Provenance(tool_exec_id="TE1", tool="t", raw_locator="PHANTOM")],
                    cited_values=["PHANTOM"])
        result = verify_findings([f], store, ["TE1"], audit=audit)
        rep.checks.append(GuardrailCheck(
            name="HALLUCINATION", passed=(len(result.quarantined) == 1),
            detail=("fabricated claim quarantined" if result.quarantined
                    else "fabrication NOT caught")))
    except Exception as exc:
        rep.checks.append(GuardrailCheck(name="HALLUCINATION", passed=False, detail=f"error: {exc}"))

    # 6) HMAC approval token tamper
    try:
        from glassbox.approve import ApprovalGate
        gate = ApprovalGate("case-x")
        token = gate.generate_token("F-1", verdict="APPROVE")
        tampered = token.to_string()[:-2] + "00"
        valid, _ = gate.validate_token(tampered)
        rep.checks.append(GuardrailCheck(
            name="HMAC_APPROVAL", passed=(not valid),
            detail=("tampered approval token rejected" if not valid
                    else "tampered token WAS accepted")))
    except Exception as exc:
        rep.checks.append(GuardrailCheck(name="HMAC_APPROVAL", passed=False, detail=f"error: {exc}"))

    return rep
