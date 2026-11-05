"""Latency measurements for the monitoring-integrity hot path.

Numbers are observed, not targets. The test fails only if the benchmark
cannot run or the cache does not avoid a second graph build.
"""

from __future__ import annotations

import json
import os
import statistics
import time
import tracemalloc

from varden.monitoring_integrity.analysis import analyse, get_analysis_cache, invalidate_analysis
from varden.monitoring_integrity.assets import AssetRegistry
from varden.monitoring_integrity.decide import Decider
from varden.monitoring_integrity.approvals import ApprovalStore


def _percentile(samples, fraction):
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def _registry(tmp_path):
    registry = AssetRegistry()
    assets = []
    for index in range(50):
        path = tmp_path / f"asset-{index}.json"
        path.write_text("{}", encoding="utf-8")
        assets.append(
            {
                "id": f"asset-{index}",
                "type": "application",
                "protected": True,
                "owner": "operator",
                "path": str(path),
                "permitted_operations": ["read"],
            }
        )
    assets.append(
        {
            "id": "monitor.config",
            "type": "enforcement_config",
            "protected": True,
            "owner": "operator",
            "path": str(tmp_path / "monitoring.json"),
            "permitted_operations": ["read"],
        }
    )
    (tmp_path / "monitoring.json").write_text('{"audit": {"enabled": true}}', encoding="utf-8")
    registry.load_section(
        {
            "enabled": True,
            "mode": "guarded",
            "assets": assets,
            "grants": [
                {"id": "read_config", "operations": ["read"], "assets": ["monitor.config"], "surface": "filesystem", "sequence": 1, "authority_neutral": True},
                {"id": "reload", "operations": ["exec"], "assets": ["monitor.config"], "surface": "subprocess", "sequence": 2, "activation": True},
            ],
        },
        section_hash="bench",
    )
    return registry


def test_benchmark_reports_observed_latency(tmp_path):
    registry = _registry(tmp_path)
    decider = Decider(registry, ApprovalStore())
    unrelated = tmp_path / "notes.txt"
    unrelated.write_text("x", encoding="utf-8")
    action = {
        "type": "filesystem",
        "tool": "open",
        "args": {"path": str(unrelated), "mode": "w"},
        "metadata": {"runtime": {"surface": "filesystem"}},
        "agent_name": "agent",
    }
    protected = dict(action)
    protected["args"] = {"path": str(tmp_path / "monitoring.json"), "mode": "w"}

    def sample(fn, count=200):
        for _ in range(20):
            fn()
        values = []
        for _ in range(count):
            start = time.perf_counter()
            fn()
            values.append((time.perf_counter() - start) * 1000.0)
        return values

    baseline = sample(lambda: os.stat(unrelated))
    classify = sample(lambda: registry.match_path(str(unrelated)))
    invariant = sample(lambda: decider.evaluate(protected, before_execution=True))
    graph_cold = analyse(registry, use_cache=False)
    cache = get_analysis_cache()
    analyse(registry)
    hits = cache.hits
    graph_warm_started = time.perf_counter()
    graph_warm = analyse(registry)
    graph_warm_ms = (time.perf_counter() - graph_warm_started) * 1000.0
    tracemalloc.start()
    analyse(registry, use_cache=False)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    invalidate_started = time.perf_counter()
    invalidate_analysis()
    invalidate_ms = (time.perf_counter() - invalidate_started) * 1000.0
    median_ms = statistics.median(invariant)
    report = {
        "baseline_stat_ms": _summary(baseline),
        "classification_ms": _summary(classify),
        "invariant_evaluation_ms": _summary(invariant),
        "invariant_throughput_per_s": (1000.0 / median_ms) if median_ms else None,
        "graph_cold_nodes": graph_cold["graph_nodes"],
        "graph_cold_edges": graph_cold["graph_edges"],
        "graph_warm_ms": graph_warm_ms,
        "graph_rebuild_peak_bytes": peak,
        "invalidation_ms": invalidate_ms,
        "cache_hit": cache.hits == hits + 1,
        "analysis_incomplete": graph_warm["analysis_incomplete"],
        "safe_conclusion": graph_warm["safe_conclusion"],
    }
    print("MIP_BENCH " + json.dumps(report))
    assert report["cache_hit"] is True
    assert report["baseline_stat_ms"]["p99"] >= report["baseline_stat_ms"]["median"]
    assert invariant_result_prevents(decider, protected)


def invariant_result_prevents(decider, action):
    decision = decider.evaluate(action, before_execution=True)
    return decision is not None and decision.prevents


def _summary(values):
    return {
        "median": statistics.median(values),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "count": len(values),
    }
