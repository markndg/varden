"""Final review closure: AQ–AX declassification, depth semantics, truncation, smoke perf.

Finding identifiers used here:
  secret_exfiltration          ↔ pattern untrusted_to_sensitive_to_external
  provenance_specific_hazard   ↔ pattern untrusted_to_credential_to_privileged
                                 (and/or matched predicate provenance_specific_hazard)
"""

from __future__ import annotations

import statistics
import time

from varden.models import Action
from varden.predictive_authority.authority_delta import AuthorityDelta
from varden.predictive_authority.graph import (
    CapabilityGraph,
    EdgeEvidence,
    EdgeKind,
    GraphEdge,
    GraphNode,
)
from varden.predictive_authority.hazardous import detect_hazardous_paths
from varden.predictive_authority.lifecycle import add_sanitisation_boundary
from varden.predictive_authority.policy import recommend
from varden.predictive_authority.reachability import (
    DEFAULT_MAX_VISITS,
    authority_hop_cost,
    bounded_reachability,
)
from varden.predictive_authority.registry import get_authority_registry

from tests.predictive_authority.helpers import fresh_engine, run_step, untrusted_meta
from tests.predictive_authority.horizon_harness import (
    build_authority_chain_graph,
    run_action_trajectory,
    slow_authority_actions,
)


SECRET_EXFIL = "untrusted_to_sensitive_to_external"
PROVENANCE_PRIV = "untrusted_to_credential_to_privileged"


def _patterns(findings) -> set[str]:
    return {f.pattern for f in findings}


def _declass_base(*, privileged_sink: bool) -> CapabilityGraph:
    """UNTRUSTED → SECRET → trusted declass{SECRET} → derived → sink."""
    g = CapabilityGraph(max_nodes=10_000, max_edges=40_000)
    g.add_node(
        GraphNode(
            node_id="untrusted:src",
            node_type="untrusted_content",
            label="untrusted",
            metadata={"trust_level": "untrusted"},
        )
    )
    g.add_node(
        GraphNode(
            node_id="res:secret",
            node_type="resource",
            label="secret-value",
            metadata={"sensitivity": "secret"},
        )
    )
    g.add_edge(
        GraphEdge(src="untrusted:src", dst="res:secret", kind=EdgeKind.FLOWS_TO, evidence=EdgeEvidence.OBSERVED)
    )
    derived = "res:derived.nonsecret"
    g.add_node(
        GraphNode(
            node_id=derived,
            node_type="resource",
            label="derived-nonsecret",
            metadata={"sensitivity": "public", "declassified": True},
        )
    )
    add_sanitisation_boundary(
        g,
        from_node="res:secret",
        boundary_id="declass:secret-only",
        to_node=derived,
        trusted=True,
        cleared_properties=["SECRET"],
        remaining_properties=["UNTRUSTED_PROVENANCE"],
        source="varden_sanitiser",
    )
    # Retained provenance on the derived value (do NOT delete provenance).
    g.add_edge(
        GraphEdge(src="untrusted:src", dst=derived, kind=EdgeKind.FLOWS_TO, evidence=EdgeEvidence.INFERRED)
    )
    if privileged_sink:
        g.add_node(
            GraphNode(
                node_id="cap:credential.aws",
                node_type="credential",
                label="credential.aws",
                metadata={"credential": True},
            )
        )
        g.add_node(GraphNode(node_id="cap:aws.ec2.modify", node_type="capability", label="aws.ec2.modify"))
        # Declassified result participates in a provenance-sensitive privileged trajectory.
        g.add_edge(
            GraphEdge(src=derived, dst="cap:credential.aws", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED)
        )
        g.add_edge(
            GraphEdge(
                src="cap:credential.aws",
                dst="cap:aws.ec2.modify",
                kind=EdgeKind.GRANTS,
                evidence=EdgeEvidence.OBSERVED,
            )
        )
        g.add_edge(
            GraphEdge(
                src="untrusted:src",
                dst="cap:credential.aws",
                kind=EdgeKind.FLOWS_TO,
                evidence=EdgeEvidence.INFERRED,
            )
        )
    else:
        g.add_node(
            GraphNode(
                node_id="sink:allowed.telemetry",
                node_type="sink",
                label="allowed-telemetry",
                metadata={"external_sink": True, "sink": True, "benign": True},
            )
        )
        g.add_edge(
            GraphEdge(
                src=derived,
                dst="sink:allowed.telemetry",
                kind=EdgeKind.REACHES,
                evidence=EdgeEvidence.OBSERVED,
            )
        )
    return g


def test_aq_legitimate_declassification_to_benign_sink():
    """AQ: clearing SECRET must not leave secret-exfiltration or unrelated provenance blocks."""
    g = _declass_base(privileged_sink=False)
    boundary = g.get_node("declass:secret-only")
    assert boundary is not None
    assert "SECRET" in (boundary.metadata or {}).get("cleared_properties", [])
    assert "UNTRUSTED_PROVENANCE" in (boundary.metadata or {}).get("remaining_properties", [])
    assert boundary.metadata.get("trusted_mechanism") == "varden_sanitiser"
    assert boundary.metadata.get("input_node") == "res:secret"
    assert boundary.metadata.get("output_node") == "res:derived.nonsecret"
    assert boundary.metadata.get("trusted_because")

    # Provenance retained.
    assert any(e.src == "untrusted:src" and e.dst == "res:derived.nonsecret" for e in g.edges())
    assert any(e.src == "untrusted:src" and e.dst == "res:secret" for e in g.edges())

    findings = detect_hazardous_paths(g, max_depth=3)
    pats = _patterns(findings)
    assert SECRET_EXFIL not in pats
    assert PROVENANCE_PRIV not in pats

    delta = AuthorityDelta(authority_expands=False)
    rec = recommend(delta=delta, findings=findings, policy={})
    assert "secret_exfiltration" not in (rec.matched_predicates or [])
    assert "provenance_specific_hazard" not in (rec.matched_predicates or [])
    assert rec.action == "allow"


def test_ar_declassified_secret_to_provenance_sensitive_sink():
    """AR: SECRET stays cleared; independent provenance→privileged hazard still fires."""
    g = _declass_base(privileged_sink=True)
    boundary = g.get_node("declass:secret-only")
    assert "SECRET" in (boundary.metadata or {}).get("cleared_properties", [])
    assert "UNTRUSTED_PROVENANCE" in (boundary.metadata or {}).get("remaining_properties", [])

    findings = detect_hazardous_paths(g, max_depth=3)
    pats = _patterns(findings)
    assert SECRET_EXFIL not in pats
    assert PROVENANCE_PRIV in pats

    # Finding identity: provenance/credential trajectory, not secret exfiltration.
    prov = [f for f in findings if f.pattern == PROVENANCE_PRIV]
    assert prov
    assert "credential" in prov[0].description.lower() or "untrusted" in prov[0].description.lower()
    assert "secret" not in prov[0].pattern

    delta = AuthorityDelta(authority_expands=True)
    rec = recommend(delta=delta, findings=findings, policy={})
    assert "secret_exfiltration" not in (rec.matched_predicates or [])
    assert "provenance_specific_hazard" in (rec.matched_predicates or [])
    assert rec.action in {"require_approval", "block"}


def test_ao_fake_declassification_cannot_clear_secret():
    """Regression: untrusted claim cannot establish trusted declassification."""
    g = CapabilityGraph()
    g.add_node(
        GraphNode(
            node_id="untrusted:src",
            node_type="untrusted_content",
            label="u",
            metadata={"trust_level": "untrusted"},
        )
    )
    g.add_node(
        GraphNode(node_id="res:secret", node_type="resource", label="s", metadata={"sensitivity": "secret"})
    )
    g.add_node(
        GraphNode(node_id="sink:ext", node_type="sink", label="sink", metadata={"external_sink": True})
    )
    g.add_edge(
        GraphEdge(src="untrusted:src", dst="res:secret", kind=EdgeKind.FLOWS_TO, evidence=EdgeEvidence.OBSERVED)
    )
    add_sanitisation_boundary(
        g,
        from_node="res:secret",
        boundary_id="fake:1",
        to_node="sink:ext",
        trusted=False,
        source="untrusted_tool",
        cleared_properties=["SECRET"],  # claim ignored when untrusted
    )
    fake = g.get_node("fake:1")
    assert fake is not None
    assert fake.metadata.get("fake_sanitisation") is True
    assert fake.metadata.get("trusted_information_flow_declassification") is False
    assert fake.metadata.get("cleared_properties") == []
    # Direct FLOWS_TO from claim keeps secret→sink hazardous path available.
    findings = detect_hazardous_paths(g, max_depth=3)
    assert SECRET_EXFIL in _patterns(findings)


def test_as_raw_topology_vs_authority_relevant_depth():
    """AS: executable documentation of the two intentional distance semantics."""
    g = CapabilityGraph()
    g.add_node(
        GraphNode(
            node_id="cap:credential.aws",
            node_type="credential",
            label="credential.aws",
            metadata={"credential": True},
        )
    )
    prev = "cap:credential.aws"
    for i in range(4):
        nid = f"cap:alias.{i}"
        g.add_node(GraphNode(node_id=nid, node_type="capability", label=nid))
        g.add_edge(GraphEdge(src=prev, dst=nid, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
        prev = nid
    cloud = "cap:aws.ec2.modify"
    g.add_node(GraphNode(node_id=cloud, node_type="capability", label=cloud))
    g.add_edge(GraphEdge(src=prev, dst=cloud, kind=EdgeKind.REACHES, evidence=EdgeEvidence.OBSERVED))

    raw = bounded_reachability(g, ["cap:credential.aws"], max_depth=3, target=cloud)
    assert raw.reachable is False

    haz = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=3,
        target=cloud,
        hop_cost=lambda e, d: authority_hop_cost(e, d, g),
    )
    assert haz.reachable is True
    assert any(f.pattern == "credential_to_cloud_mutation" for f in detect_hazardous_paths(g, max_depth=3))


def test_at_long_zero_cost_alias_chain_bounded():
    """AT: 100-hop alias padding still finds hazard; visits remain bounded."""
    g = CapabilityGraph(max_nodes=50_000, max_edges=200_000)
    g.add_node(
        GraphNode(
            node_id="cap:credential.aws",
            node_type="credential",
            label="c",
            metadata={"credential": True},
        )
    )
    prev = "cap:credential.aws"
    for i in range(100):
        nid = f"cap:alias.{i}"
        g.add_node(GraphNode(node_id=nid, node_type="capability", label=nid))
        g.add_edge(
            GraphEdge(
                src=prev,
                dst=nid,
                kind=EdgeKind.ENABLES,
                evidence=EdgeEvidence.OBSERVED,
                metadata={"authority_neutral": True},
            )
        )
        prev = nid
    cloud = "cap:aws.ec2.modify"
    g.add_node(GraphNode(node_id=cloud, node_type="capability", label=cloud))
    g.add_edge(GraphEdge(src=prev, dst=cloud, kind=EdgeKind.REACHES, evidence=EdgeEvidence.OBSERVED))

    t0 = time.perf_counter()
    result = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=3,
        target=cloud,
        hop_cost=lambda e, d: authority_hop_cost(e, d, g),
        max_visits=DEFAULT_MAX_VISITS,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert result.reachable is True
    assert result.visited_nodes <= DEFAULT_MAX_VISITS + 10
    assert elapsed_ms < 1500.0
    # Alias chain preserved on the concrete path when shown.
    assert result.shortest() is not None
    assert any(n.startswith("cap:alias.") for n in result.shortest().nodes)


def test_au_zero_cost_alias_cycle_terminates():
    """AU: alias cycle must not nonterminate; hazard still found if present."""
    g = CapabilityGraph()
    for nid, meta in (
        ("cap:credential.aws", {"credential": True}),
        ("cap:alias.a", {}),
        ("cap:alias.b", {}),
        ("cap:alias.c", {}),
        ("cap:aws.ec2.modify", {}),
    ):
        ntype = "credential" if "credential" in nid else "capability"
        g.add_node(GraphNode(node_id=nid, node_type=ntype, label=nid, metadata=meta))
    g.add_edge(GraphEdge(src="cap:credential.aws", dst="cap:alias.a", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    g.add_edge(GraphEdge(src="cap:alias.a", dst="cap:alias.b", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    g.add_edge(GraphEdge(src="cap:alias.b", dst="cap:alias.c", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    g.add_edge(GraphEdge(src="cap:alias.c", dst="cap:alias.a", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    g.add_edge(GraphEdge(src="cap:alias.b", dst="cap:aws.ec2.modify", kind=EdgeKind.REACHES, evidence=EdgeEvidence.OBSERVED))

    t0 = time.perf_counter()
    a = detect_hazardous_paths(g, max_depth=3)
    b = detect_hazardous_paths(g, max_depth=3)
    assert time.perf_counter() - t0 < 1.0
    assert a == b or _patterns(a) == _patterns(b)
    assert "credential_to_cloud_mutation" in _patterns(a)


def test_av_positive_hazard_survives_truncation():
    """AV: proven hazard remains valid when analysis later hits a resource bound."""
    g = build_authority_chain_graph(intermediates=2, with_credential_at=1, alias_after_credential=0)
    core_nodes = g.node_count()
    g2 = CapabilityGraph(max_nodes=core_nodes + 2, max_edges=g.edge_count() + 50)
    for n in g.nodes():
        g2.add_node(
            GraphNode(
                node_id=n.node_id,
                node_type=n.node_type,
                label=n.label,
                confirmed=n.confirmed,
                metadata=dict(n.metadata or {}),
            )
        )
    for e in g.edges():
        g2.add_edge(
            GraphEdge(src=e.src, dst=e.dst, kind=e.kind, evidence=e.evidence, label=e.label, metadata=dict(e.metadata or {}))
        )
    findings_before = detect_hazardous_paths(g2, max_depth=3)
    assert findings_before
    for i in range(20):
        g2.add_node(GraphNode(node_id=f"cap:pad.{i}", node_type="capability", label=str(i)))
    assert g2.truncated is True
    findings_after = detect_hazardous_paths(g2, max_depth=3)
    assert findings_after, "hazard must remain after truncation"
    assert any("credential" in f.pattern for f in findings_after)

    engine = fresh_engine(mode="enforce", max_depth=3, max_nodes=12, max_edges=40)
    tid = "av-trunc-pos"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="adv",
        ),
    )
    for i in range(30):
        final, result = run_step(
            engine,
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": [f"/tmp/pad-{i}.txt", "r"]},
                metadata=untrusted_meta(),
                trace_id=tid,
                tenant_id="adv",
            ),
        )
        if result.analysis_status == "truncated":
            meta = result.to_metadata()
            assert meta.get("safe_conclusion") is False
            state = get_authority_registry().get("adv:av-trunc-pos")
            assert state is not None
            assert state.graph.truncated is True
            live = detect_hazardous_paths(state.graph, max_depth=3)
            assert live  # positive finding under truncation
            assert final.action in {"require_approval", "block", "approval_required"}
            return
    state = get_authority_registry().get("adv:av-trunc-pos")
    assert state and state.graph.truncated


def test_aw_negative_truncation_never_safe():
    """AW: no hazard found before bound → TRUNCATED/incomplete, never SAFE."""
    engine = fresh_engine(mode="enforce", max_depth=3, max_nodes=6, max_edges=12)
    tid = "aw-trunc-neg"
    saw_trunc = False
    for i in range(25):
        final, result = run_step(
            engine,
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": [f"/tmp/benign-{i}.txt", "r"]},
                metadata=untrusted_meta(),
                trace_id=tid,
                tenant_id="adv",
            ),
        )
        if result.analysis_status == "truncated":
            saw_trunc = True
            meta = result.to_metadata()
            assert meta.get("safe_conclusion") is False
            assert final.action in {"require_approval", "block", "approval_required"}
            break
    assert saw_trunc


def _noise_hazard_benchmark(noise: int, *, repeats: int = 5) -> dict:
    """Benchmark helper: report graph size vs visited size honestly."""
    from varden.predictive_authority.config import PredictiveAuthorityConfig

    cfg = PredictiveAuthorityConfig()
    g = build_authority_chain_graph(intermediates=2, with_credential_at=1)
    # Keep production-like limits on a separate analysis graph view: the noise
    # graph itself may be larger than max_nodes so we report total vs visited.
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
    samples: list[float] = []
    last = None
    for _ in range(repeats):
        t0 = time.perf_counter()
        # Measure the credential→cloud hazardous query with visit accounting.
        last = bounded_reachability(
            g,
            ["cap:credential.aws"],
            max_depth=3,
            predicate=lambda n: "aws.ec2.modify" in n,
            hop_cost=lambda e, d: authority_hop_cost(e, d, g),
            max_visits=DEFAULT_MAX_VISITS,
        )
        samples.append((time.perf_counter() - t0) * 1000.0)
    findings = detect_hazardous_paths(g, max_depth=3)
    status = "TRUNCATED" if (last and last.truncated) or g.truncated else "COMPLETE"
    if last and last.analysis_incomplete and not last.truncated and not g.truncated:
        status = "INCOMPLETE"
    samples.sort()
    return {
        "total_graph_nodes": g.node_count(),
        "total_graph_edges": g.edge_count(),
        "visited_nodes": last.visited_nodes if last else 0,
        "visited_edges": last.visited_edges if last else 0,
        "configured_max_nodes": cfg.max_nodes,
        "configured_max_edges": cfg.max_edges,
        "configured_max_visits": DEFAULT_MAX_VISITS,
        "hazard_found": bool(findings) and bool(last and last.reachable),
        "analysis_status": status,
        "median_ms": statistics.median(samples),
        "p95_ms": samples[max(0, int(len(samples) * 0.95) - 1)],
    }


def test_ax_loose_performance_regression_smoke():
    """AX: order-of-magnitude CI guards — not precision benchmarks.

    Thresholds are intentionally generous (catch seconds-scale regressions, not
    laptop-vs-CI 2× noise). Real medians are recorded by benchmarks / docs.
    """
    # 1k-node hazardous analysis
    row_1k = _noise_hazard_benchmark(1000, repeats=3)
    assert row_1k["hazard_found"] is True
    assert row_1k["median_ms"] < 500.0, row_1k

    # 10k-node workload (may be COMPLETE or TRUNCATED depending on visits; report both)
    row_10k = _noise_hazard_benchmark(10_000, repeats=3)
    assert row_10k["hazard_found"] is True
    assert row_10k["total_graph_nodes"] >= 10_000
    assert row_10k["visited_nodes"] <= DEFAULT_MAX_VISITS + 64
    assert row_10k["median_ms"] < 1500.0, row_10k
    # Honest reporting: do not require exhaustive analysis of all 10k nodes.
    assert row_10k["visited_nodes"] <= row_10k["total_graph_nodes"]

    # 32-step accumulation
    engine = fresh_engine(mode="enforce", max_depth=3)
    actions = slow_authority_actions("ax-32", 32)
    t0 = time.perf_counter()
    report = run_action_trajectory(engine, actions, scenario="AX", sink_index=31)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert report.intercepted_before_sink is True
    assert elapsed_ms < 3000.0, elapsed_ms


def test_large_graph_benchmark_reports_visited_and_status():
    """Precise large-graph reporting (benchmark semantics, not CI certification)."""
    rows = []
    for noise in (100, 1000, 10_000):
        rows.append(_noise_hazard_benchmark(noise, repeats=5))
    for row in rows:
        for key in (
            "total_graph_nodes",
            "total_graph_edges",
            "visited_nodes",
            "visited_edges",
            "configured_max_nodes",
            "configured_max_edges",
            "configured_max_visits",
            "hazard_found",
            "analysis_status",
            "median_ms",
            "p95_ms",
        ):
            assert key in row
        assert row["analysis_status"] in {"COMPLETE", "TRUNCATED", "INCOMPLETE", "FAILED"}
        assert row["hazard_found"] is True
        # Never imply the whole graph was exhaustively walked when visits << nodes.
        if row["total_graph_nodes"] > row["configured_max_visits"]:
            assert row["visited_nodes"] <= row["configured_max_visits"] + 64
