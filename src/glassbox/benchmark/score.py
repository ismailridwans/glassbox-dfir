"""Benchmark scoring: agent findings vs. documented ground truth.

Ground-truth format (``ground_truth.json`` in gt_dir):
  {
    "techniques": ["T1543.003", "T1003.001", ...],
    "iocs": ["41.168.5.140", "reader_sl.exe", ...],
    "confirmed_artifacts": ["lsass", "reader_sl.exe", ...],
    "source": "cridex.vmem – Volatility labs"
  }

Predictions come from the agent's report JSON (``*.report.json`` in pred_dir).
Scores reported match the hackathon accuracy report requirements:
  precision, recall, F1, false_positive_rate, missed_artifacts,
  hallucinated_claims, confirmed_findings, inferred_findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _techniques_from_report(rep: dict) -> set[str]:
    out: set[str] = set()
    for f in rep.get("findings", []):
        for m in f.get("attack", []):
            tid = m.get("technique_id", "")
            if tid:
                out.add(tid.upper())
    for m in rep.get("attack_coverage", []):
        tid = m.get("technique_id", "")
        if tid:
            out.add(tid.upper())
    return out


def _iocs_from_report(rep: dict) -> set[str]:
    out: set[str] = set()
    for ioc in rep.get("iocs", []):
        out.add(str(ioc.get("value", "")).lower())
    return out


def _precision_recall_f1(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) else 0.0)
    return {"precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3)}


def score_case(gt: dict, rep: dict) -> dict:
    gt_techs  = {t.upper() for t in gt.get("techniques", [])}
    gt_iocs   = {i.lower() for i in gt.get("iocs", [])}
    gt_arts   = {a.lower() for a in gt.get("confirmed_artifacts", [])}

    pred_techs = _techniques_from_report(rep)
    pred_iocs  = _iocs_from_report(rep)

    # technique scoring
    tp_t = len(gt_techs & pred_techs)
    fp_t = len(pred_techs - gt_techs)
    fn_t = len(gt_techs - pred_techs)
    tech_scores = _precision_recall_f1(tp_t, fp_t, fn_t)

    # IOC scoring
    tp_i = sum(1 for g in gt_iocs if any(g in p or p in g for p in pred_iocs))
    fp_i = len(pred_iocs - gt_iocs)
    fn_i = len(gt_iocs) - tp_i
    ioc_scores = _precision_recall_f1(tp_i, max(fp_i, 0), max(fn_i, 0))

    # hallucination + integrity
    n_quarantined = len(rep.get("quarantined", []))
    n_findings    = len(rep.get("findings", []))
    hallucination_rate = (n_quarantined / (n_findings + n_quarantined)
                          if (n_findings + n_quarantined) else 0.0)

    n_confirmed = sum(1 for f in rep.get("findings", [])
                      if f.get("confidence") == "CONFIRMED")
    n_inferred  = sum(1 for f in rep.get("findings", [])
                      if f.get("confidence") == "INFERRED")

    # missed artifacts: ground-truth artifacts not cited in any finding description
    all_finding_text = " ".join(
        (f.get("title", "") + " " + f.get("description", "")).lower()
        for f in rep.get("findings", [])
    )
    missed = [a for a in gt_arts if a not in all_finding_text]

    return {
        "source": gt.get("source", "unknown"),
        "technique_scoring": {**tech_scores, "tp": tp_t, "fp": fp_t, "fn": fn_t,
                               "gt_count": len(gt_techs), "pred_count": len(pred_techs),
                               "missed": sorted(gt_techs - pred_techs)},
        "ioc_scoring": {**ioc_scores, "tp": tp_i, "fp": fp_i, "fn": fn_i,
                        "gt_count": len(gt_iocs), "pred_count": len(pred_iocs)},
        "hallucination_rate": round(hallucination_rate, 3),
        "quarantined": n_quarantined,
        "confirmed_findings": n_confirmed,
        "inferred_findings": n_inferred,
        "total_reportable": n_findings,
        "missed_artifacts": missed,
        "false_positive_rate": round(fp_t / len(pred_techs), 3) if pred_techs else 0.0,
        "integrity": rep.get("integrity", []),
        "audit_chain_valid": rep.get("audit_chain_valid", None),
    }


def run_benchmark(
    ground_truth_dir: str,
    predictions_dir: str,
    report_path: Optional[str] = "benchmark_report.json",
) -> dict:
    gt_dir   = Path(ground_truth_dir)
    pred_dir = Path(predictions_dir)
    results  = []

    gt_file = gt_dir / "ground_truth.json"
    if not gt_file.exists():
        return {"error": f"ground_truth.json not found in {gt_dir}"}

    gt = _load_json(gt_file)

    # find all report JSONs in predictions dir
    rep_files = sorted(pred_dir.glob("*.report.json"))
    if not rep_files:
        return {"error": f"No *.report.json files found in {pred_dir}"}

    for rf in rep_files:
        rep = _load_json(rf)
        results.append({"report_file": rf.name, **score_case(gt, rep)})

    # aggregate across all reports
    if results:
        avg_t_prec = sum(r["technique_scoring"]["precision"] for r in results) / len(results)
        avg_t_rec  = sum(r["technique_scoring"]["recall"]    for r in results) / len(results)
        avg_hallu  = sum(r["hallucination_rate"]             for r in results) / len(results)
    else:
        avg_t_prec = avg_t_rec = avg_hallu = 0.0

    summary = {
        "cases_scored": len(results),
        "avg_technique_precision": round(avg_t_prec, 3),
        "avg_technique_recall":    round(avg_t_rec, 3),
        "avg_hallucination_rate":  round(avg_hallu, 3),
        "results": results,
    }
    if report_path:
        Path(report_path).write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
    return summary
