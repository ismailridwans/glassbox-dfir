"""Triage session manager for the web backend.

Wraps a :class:`~glassbox.context.CaseContext` and drives the LangGraph triage,
exposing a generator that yields structured live-execution events for the
Server-Sent-Events stream. After a run it caches the report dict and derived
artifacts (Navigator layer, speed report, audit records) for the REST endpoints.
"""

from __future__ import annotations

import itertools
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator, Optional


def _node_event(node: str, delta: dict) -> dict:
    """Turn a LangGraph node delta into a compact UI event."""
    label = {
        "intake": "Intake", "plan": "Plan", "collect": "Collect",
        "correlate": "Correlate", "map_attack": "ATT&CK Map",
        "verify": "Verify (hallucination gate)", "adversarial_verify": "Red-Team Panel",
        "critique": "Self-Critique", "report": "Report",
    }.get(node, node)
    data: dict[str, Any] = {}
    detail = ""
    if node == "intake":
        n = len(delta.get("evidence", []))
        detail = f"{n} evidence item(s) hashed; integrity baseline set"
        data = {"evidence": n}
    elif node == "plan":
        plan = delta.get("plan", [])
        it = delta.get("iteration", "?")
        detail = f"iteration {it}: {len(plan)} step(s) — {', '.join(s['tool'] for s in plan[:5])}"
        data = {"iteration": it, "steps": [s["tool"] for s in plan]}
    elif node == "collect":
        n = len(delta.get("findings", []))
        detail = f"specialists ran; {n} cumulative finding(s)"
        data = {"findings": n}
    elif node == "correlate":
        d = len(delta.get("discrepancies", []))
        detail = f"{d} cross-source discrepancy(ies)"
        data = {"discrepancies": d}
    elif node == "map_attack":
        a = len(delta.get("attack", []))
        detail = f"{a} ATT&CK technique(s) mapped"
        data = {"techniques": a}
    elif node == "verify":
        v = delta.get("verification", {})
        detail = (f"{v.get('confirmed', 0)} confirmed, {v.get('inferred', 0)} inferred, "
                  f"{v.get('hallucinated', 0)} hallucinated→quarantined")
        data = v
    elif node == "adversarial_verify":
        a = delta.get("adversarial", {})
        detail = (f"{a.get('upheld', 0)} upheld, {a.get('demoted', 0)} demoted, "
                  f"{a.get('refuted', 0)} refuted (false positives)")
        data = a
    elif node == "critique":
        gaps = delta.get("gaps", [])
        done = delta.get("done")
        detail = ("no actionable gaps — concluding" if (done or not gaps)
                  else f"gap found → self-correcting ({', '.join(g['tool'] for g in gaps[:4])})")
        data = {"gaps": [g["tool"] for g in gaps], "done": bool(done)}
    elif node == "report":
        detail = "triage complete"
        data = {"complete": True}
    return {"type": "node", "node": node, "label": label, "detail": detail, "data": data}


class TriageSession:
    """Holds one case and runs/streams triage for the web backend."""

    def __init__(self, *, case_dir: Optional[str] = None, evidence_dir: Optional[str] = None,
                 demo: bool = True, max_iterations: int = 3):
        from glassbox.config import GlassboxConfig
        from glassbox.context import CaseContext

        self.demo = demo
        self.max_iterations = max_iterations
        self._tmp: Optional[str] = None

        if demo or case_dir is None:
            # Persistent working copy of the bundled demo case (cleaned on server exit).
            demo_root = Path(__file__).resolve().parent.parent.parent.parent / "demo_case"
            if not demo_root.exists():
                demo_root = Path("demo_case")
            self._tmp = tempfile.mkdtemp(prefix="glassbox_web_")
            work = Path(self._tmp) / "demo-cridex-evtx"
            shutil.copytree(demo_root, work)
            cfg = GlassboxConfig.for_case(work, evidence_dir=work / "evidence",
                                          replay_dir=work / "fixtures",
                                          max_iterations=max_iterations)
            self.ctx = CaseContext(cfg, replay=True)
            self._demo_overclaim = True
        else:
            cfg = GlassboxConfig.for_case(case_dir, evidence_dir=evidence_dir,
                                          max_iterations=max_iterations)
            self.ctx = CaseContext(cfg, replay=bool(cfg.replay_dir))
            self._demo_overclaim = False

        self.case_id = self.ctx.config.case_id
        self.report: Optional[dict] = None
        self.last_a2a: list[dict] = []
        self.running = False
        self.last_duration_ms = 0

    # ------------------------------------------------------------------ #
    def evidence_manifest(self) -> dict:
        try:
            return self.ctx.toolkit.evidence_manifest()
        except Exception as exc:  # pragma: no cover
            return {"count": 0, "evidence": [], "error": str(exc)}

    def stream_run(self) -> Iterator[dict]:
        """Generator of SSE events: start → node* → done."""
        from glassbox.orchestrator.graph import build_graph
        from glassbox.orchestrator.llm import get_llm

        # Fresh context per run so re-runs start clean.
        self._reset_context()
        self.running = True
        llm = get_llm(self.ctx.config.llm_backend, self.ctx.config.llm_model)
        seq = itertools.count().__next__
        graph = build_graph(self.ctx, llm, seq)
        init = {"case_id": self.case_id, "max_iterations": self.max_iterations,
                "demo_overclaim": self._demo_overclaim}
        config = {"configurable": {"thread_id": self.case_id},
                  "recursion_limit": self.ctx.config.recursion_limit}

        man = self.evidence_manifest()
        yield {"type": "start", "case_id": self.case_id,
               "evidence": man.get("evidence", []),
               "tools": self.ctx.toolkit.list_tools()}

        t0 = time.perf_counter()
        rep_obj = None
        try:
            for step in graph.stream(init, config, stream_mode="updates"):
                for node, delta in step.items():
                    ev = _node_event(node, delta)
                    ev["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
                    if node == "report" and isinstance(delta, dict) and delta.get("report") is not None:
                        rep_obj = delta["report"]
                    yield ev
        except Exception as exc:  # pragma: no cover
            yield {"type": "error", "error": f"{type(exc).__name__}: {exc}"}
            self.running = False
            return

        self.last_duration_ms = int((time.perf_counter() - t0) * 1000)
        if rep_obj is not None:
            rep_obj.duration_ms = self.last_duration_ms
            self.report = json.loads(rep_obj.model_dump_json())
            from glassbox.report.render import write_report
            paths = write_report(rep_obj, self.ctx.config.reports_dir)
            self.last_a2a = self._read_a2a(paths.get("execution_log"))
        self.running = False
        yield {"type": "done", "duration_ms": self.last_duration_ms,
               "report": self.report or {}}

    def run_blocking(self) -> dict:
        """Run to completion (used for the auto-run on server start)."""
        for _ in self.stream_run():
            pass
        return self.report or {}

    # ------------------------------------------------------------------ #
    def _reset_context(self) -> None:
        from glassbox.config import GlassboxConfig
        from glassbox.context import CaseContext
        cfg = self.ctx.config
        # rebuild a fresh CaseContext on the same dirs (clears prior executions/audit tip)
        if cfg.audit_path.exists():
            cfg.audit_path.unlink()
        fresh = GlassboxConfig.for_case(cfg.case_dir, evidence_dir=cfg.evidence_dir,
                                        replay_dir=cfg.replay_dir,
                                        max_iterations=self.max_iterations)
        self.ctx = CaseContext(fresh, replay=bool(fresh.replay_dir) or not self.demo and False or self.demo)

    @staticmethod
    def _read_a2a(path) -> list[dict]:
        if not path or not Path(path).exists():
            return []
        out = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out

    # ------------------------------------------------------------------ #
    # Derived artifacts for REST endpoints
    # ------------------------------------------------------------------ #
    def navigator_layer(self) -> dict:
        from glassbox.attack.navigator import to_navigator_layer
        return to_navigator_layer(self.report or {})

    def diamond_model(self) -> dict:
        from glassbox.attack.navigator import to_diamond_model
        return to_diamond_model(self.report or {})

    def speed(self) -> dict:
        from glassbox.perf import speed_report
        return speed_report(self.ctx.toolkit.executions, self.last_duration_ms,
                            iterations=(self.report or {}).get("iterations_used", 1))

    def audit_records(self, limit: int = 2000) -> dict:
        path = self.ctx.config.audit_path
        records = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines()[:limit]:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        from glassbox.audit.chain import AuditChain
        ok, errors = AuditChain.verify(path) if path.exists() else (False, ["no log"])
        return {"valid": ok, "errors": errors, "count": len(records), "records": records}

    def guardrail_selftest(self) -> dict:
        from glassbox.guardrail import run_guardrail_selftest
        return run_guardrail_selftest().summary()

    def replay_verify(self) -> dict:
        from glassbox.forensic import replay_verify
        reports = self.ctx.config.reports_dir
        rj = next(iter(reports.glob("*.report.json")), None)
        if rj is None:
            return {"reproducible": False, "note": "no report yet — run triage first"}
        return replay_verify(self.ctx.config.audit_path, self.ctx.config.raw_dir, rj).summary()

    def a2a(self) -> list[dict]:
        return self.last_a2a

    def cleanup(self) -> None:
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
