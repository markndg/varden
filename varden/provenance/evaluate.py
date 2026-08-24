"""Evaluation corpus for provenance / authority-flow protection."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..models import Action
from ..policy import PolicyEngine
from ..policy_packs import load_policy_pack
from .engine import enrich

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"


def _load_cases() -> list[dict[str, Any]]:
    path = CORPUS_DIR / "cases_v1.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("cases") or [])


def run_evaluation(*, json_out: bool = False, db_path: str | None = None) -> dict[str, Any]:
    cases = _load_cases()
    pack = load_policy_pack("provenance-authority-defense")
    template = (pack or {}).get("template") or {"block": [], "warn": [], "monitor": [], "allow": [], "require_approval": []}
    # Ephemeral policy engine for evaluation — avoid touching operator DB policy.
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = PolicyEngine(tmp.name, template)

    latencies: list[float] = []
    tp = fp = tn = fn = 0
    details: list[dict[str, Any]] = []

    for case in cases:
        action_raw = case.get("action") or {}
        action = Action(
            type=str(action_raw.get("type") or "tool_call"),
            tool=action_raw.get("tool"),
            method=action_raw.get("method"),
            url=action_raw.get("url"),
            domain=action_raw.get("domain"),
            args=dict(action_raw.get("args") or {}),
            metadata=dict(action_raw.get("metadata") or {}),
            classifiers=dict(action_raw.get("classifiers") or {}),
            agent_name=action_raw.get("agent_name") or "eval",
            trace_id=str(case.get("id") or action_raw.get("trace_id") or "eval"),
        )
        start = time.perf_counter()
        enriched = enrich(action)
        decision = engine.evaluate(enriched)
        elapsed = (time.perf_counter() - start) * 1000.0
        latencies.append(elapsed)

        expected = str(case.get("expected") or "allow")
        actual = decision.action
        # Collapse require_approval into "block-like" for attack detection metrics
        # when the corpus labels attacks as block; benign may be allow/monitor/warn.
        is_attack = bool(case.get("attack"))
        blocked_like = actual in {"block", "require_approval"}
        if is_attack and blocked_like:
            tp += 1
            outcome = "tp"
        elif is_attack and not blocked_like:
            fn += 1
            outcome = "fn"
        elif (not is_attack) and blocked_like and expected == "allow":
            fp += 1
            outcome = "fp"
        else:
            tn += 1
            outcome = "tn"

        details.append({
            "id": case.get("id"),
            "expected": expected,
            "actual": actual,
            "attack": is_attack,
            "outcome": outcome,
            "latency_ms": round(elapsed, 3),
            "findings": (enriched.metadata or {}).get("findings") or [],
        })

    latencies_sorted = sorted(latencies)
    def pct(p: float) -> float:
        if not latencies_sorted:
            return 0.0
        idx = min(len(latencies_sorted) - 1, max(0, int(round((p / 100.0) * (len(latencies_sorted) - 1)))))
        return latencies_sorted[idx]

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    benign_allow = tn / (tn + fp) if (tn + fp) else 1.0

    result = {
        "ok": fn == 0 and precision >= 0.8,
        "cases": len(cases),
        "attack_detection_rate": round(recall, 4),
        "benign_allow_rate": round(benign_allow, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "authority_violation_recall": round(recall, 4),
        "precision": round(precision, 4),
        "median_latency_ms": round(pct(50), 3),
        "p95_latency_ms": round(pct(95), 3),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "details": details,
    }

    if not json_out:
        print("Provenance / authority-flow evaluation")
        print(f"  cases: {result['cases']}")
        print(f"  attack detection rate (recall): {result['attack_detection_rate']}")
        print(f"  benign allow rate: {result['benign_allow_rate']}")
        print(f"  false positive rate: {result['false_positive_rate']}")
        print(f"  false negative rate: {result['false_negative_rate']}")
        print(f"  precision: {result['precision']}")
        print(f"  median latency ms: {result['median_latency_ms']}")
        print(f"  p95 latency ms: {result['p95_latency_ms']}")
        if result["fn"]:
            print("  false negatives:")
            for row in details:
                if row["outcome"] == "fn":
                    print(f"    - {row['id']}: expected block-like, got {row['actual']}")
    return result
