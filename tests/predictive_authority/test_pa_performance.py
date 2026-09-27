"""Performance tests — generous bounds, not brittle absolute timings."""

from __future__ import annotations

import time

from varden.models import Action, Decision
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine, apply_predictive_authority
from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.reachability import bounded_reachability
from varden.predictive_authority.registry import reset_authority_registry

from tests.predictive_authority.helpers import allow_decision, fresh_engine, run_step


def test_disabled_overhead_is_negligible():
    action = Action(type="http_request", method="GET", url="https://example.com", trace_id="perf", tenant_id="t")
    decision = allow_decision()
    cfg = PredictiveAuthorityConfig(enabled=False, mode="off")
    start = time.perf_counter()
    for _ in range(200):
        apply_predictive_authority(action, decision, config=cfg)
    elapsed = time.perf_counter() - start
    # 200 no-ops should be well under 1s on CI.
    assert elapsed < 1.0


def test_observe_mode_graph_transition_bound():
    engine = fresh_engine(mode="observe", max_depth=3)
    start = time.perf_counter()
    for i in range(50):
        run_step(
            engine,
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": [f"src/file_{i}.py", "r"]},
                trace_id="perf-obs",
                tenant_id="t",
            ),
        )
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0


def test_bounded_reachability_worst_case_depth():
    g = CapabilityGraph()
    n = 40
    for i in range(n):
        g.add_node(GraphNode(node_id=f"n{i}", node_type="capability", label=f"n{i}"))
    for i in range(n - 1):
        for j in range(i + 1, min(i + 4, n)):
            g.add_edge(
                GraphEdge(src=f"n{i}", dst=f"n{j}", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED)
            )
    start = time.perf_counter()
    for depth in (1, 2, 3, 4, 5):
        bounded_reachability(g, ["n0"], max_depth=depth, target=f"n{n-1}")
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0


def test_demo_runs_quickly():
    from varden.predictive_authority.demo import run_predictive_demo

    start = time.perf_counter()
    rc = run_predictive_demo(json_out=True)
    assert rc == 0
    assert time.perf_counter() - start < 3.0
