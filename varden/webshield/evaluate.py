from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .corpus import CorpusCase, build_output_inputs, build_registration_inputs, load_corpus
from .engine import scan_output, scan_registration
from .sanitize import sanitize_tool

# Any band above "low" (see risk.py bands) is treated as flagged for security
# attention: "guarded" already means "not clearly benign, worth a look" by
# the band's own definition, so it is the correct operating point for
# measuring whether the scanner meaningfully surfaced a case, as opposed to
# the (higher) "suspicious"/"high" bands that drive stronger policy actions
# such as warn/block. See docs/web-shield-evaluation.md for the rationale.
POSITIVE_SCORE_THRESHOLD = 20


@dataclass
class CaseResult:
    case: CorpusCase
    predicted_label: str
    score: int
    band: str
    latency_ms: float
    matched_categories: set[str] = field(default_factory=set)
    correct: bool = False


def _classify_registration(case: CorpusCase) -> CaseResult:
    tool, context = build_registration_inputs(case)
    start = time.perf_counter()
    result = scan_registration(tool, context)
    sanitized = sanitize_tool(tool)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    predicted_positive = result.risk.score >= POSITIVE_SCORE_THRESHOLD or sanitized.blocked
    predicted_label = "malicious" if predicted_positive else "benign"
    categories = {f.category for f in result.findings}
    return CaseResult(
        case=case,
        predicted_label=predicted_label,
        score=result.risk.score,
        band=result.risk.band,
        latency_ms=elapsed_ms,
        matched_categories=categories,
        correct=predicted_label == case.label,
    )


def _classify_output(case: CorpusCase) -> CaseResult:
    inputs = build_output_inputs(case)
    start = time.perf_counter()
    findings, risk = scan_output(
        inputs["text"],
        owner_origin=inputs["owner_origin"],
        contains_user_generated_content=inputs["contains_user_generated_content"],
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    predicted_positive = risk.score >= POSITIVE_SCORE_THRESHOLD
    predicted_label = "malicious" if predicted_positive else "benign"
    categories = {f.category for f in findings}
    return CaseResult(
        case=case,
        predicted_label=predicted_label,
        score=risk.score,
        band=risk.band,
        latency_ms=elapsed_ms,
        matched_categories=categories,
        correct=predicted_label == case.label,
    )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100.0 * (len(ordered) - 1))))
    return ordered[idx]


def run_evaluation(version: str = "v1") -> dict[str, Any]:
    corpus_version, cases = load_corpus(version)
    results: list[CaseResult] = []
    for case in cases:
        if case.scan_target == "output":
            results.append(_classify_output(case))
        else:
            results.append(_classify_registration(case))

    tp = sum(1 for r in results if r.case.label == "malicious" and r.predicted_label == "malicious")
    fp = sum(1 for r in results if r.case.label == "benign" and r.predicted_label == "malicious")
    tn = sum(1 for r in results if r.case.label == "benign" and r.predicted_label == "benign")
    fn = sum(1 for r in results if r.case.label == "malicious" and r.predicted_label == "benign")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    per_category: dict[str, dict[str, int]] = {}
    for r in results:
        bucket = per_category.setdefault(r.case.attack_category, {"total": 0, "correct": 0})
        bucket["total"] += 1
        bucket["correct"] += 1 if r.correct else 0

    false_positives = [
        {"id": r.case.id, "score": r.score, "band": r.band, "notes": r.case.notes}
        for r in results if r.case.label == "benign" and r.predicted_label == "malicious"
    ]
    misses = [
        {"id": r.case.id, "score": r.score, "band": r.band, "notes": r.case.notes, "expected_categories": r.case.raw.get("expect_categories", [])}
        for r in results if r.case.label == "malicious" and r.predicted_label == "benign"
    ]

    latencies = [r.latency_ms for r in results]

    return {
        "corpus_version": corpus_version,
        "positive_score_threshold": POSITIVE_SCORE_THRESHOLD,
        "total_cases": len(results),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "per_category": per_category,
        "top_false_positives": false_positives,
        "top_misses": misses,
        "latency_ms": {
            "p50": round(_percentile(latencies, 50), 3),
            "p95": round(_percentile(latencies, 95), 3),
            "p99": round(_percentile(latencies, 99), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "acceptance_targets": {
            "malicious_recall_min": 0.90,
            "benign_precision_min": 0.90,
            "p95_latency_ms_max": 25.0,
        },
        "acceptance_result": {
            "recall_met": recall >= 0.90,
            "precision_met": precision >= 0.90,
            "latency_met": _percentile(latencies, 95) < 25.0,
        },
        "cases": [
            {
                "id": r.case.id,
                "label": r.case.label,
                "predicted": r.predicted_label,
                "score": r.score,
                "band": r.band,
                "correct": r.correct,
                "attack_category": r.case.attack_category,
                "latency_ms": round(r.latency_ms, 3),
            }
            for r in results
        ],
    }
