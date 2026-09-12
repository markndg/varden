"""Property / invariant tests for Predictive Authority."""

from __future__ import annotations

from varden.models import Action, Decision
from varden.predictive_authority.authority_delta import compute_authority_delta
from varden.predictive_authority.capability import Capability, CapabilityKind
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import apply_predictive_authority
from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.policy import PredictiveRecommendation, decision_rank, strengthen_decision
from varden.predictive_authority.reachability import bounded_reachability
from varden.predictive_authority.registry import reset_authority_registry
from varden.predictive_authority.state import AuthorityState

from tests.predictive_authority.helpers import allow_decision, fresh_engine, run_step, untrusted_meta


def test_invariant_enforce_never_weakens():
    for existing in ("block", "require_approval", "warn", "monitor", "allow"):
        for rec in ("block", "require_approval", "warn", "monitor", "allow"):
            out = strengthen_decision(
                Decision(action=existing, reason="e", effective_action=existing),
                PredictiveRecommendation(action=rec, reason="r", matched_predicates=[], authority_expands=False, structural_units=0),
            )
            assert decision_rank(out.action) >= decision_rank(existing)


def test_invariant_off_mode_current_behavior():
    reset_authority_registry()
    action = Action(type="tool_call", tool="x", trace_id="inv-off", tenant_id="t")
    d = Decision(action="monitor", reason="m", effective_action="monitor")
    final, _ = apply_predictive_authority(action, d, config=PredictiveAuthorityConfig(enabled=False, mode="off"))
    assert final.action == "monitor"


def test_invariant_reachability_deterministic():
    g = CapabilityGraph()
    for n in ("a", "b", "c"):
        g.add_node(GraphNode(node_id=n, node_type="capability", label=n))
    g.add_edge(GraphEdge(src="a", dst="b", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    g.add_edge(GraphEdge(src="b", dst="c", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    r1 = bounded_reachability(g, ["a"], max_depth=3, target="c")
    r2 = bounded_reachability(g, ["a"], max_depth=3, target="c")
    assert r1.to_dict() == r2.to_dict()


def test_invariant_potential_never_silently_confirmed():
    engine = fresh_engine(mode="observe")
    _f, result = run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]}, trace_id="inv-p", tenant_id="t"),
    )
    for cap in result.delta.added_capabilities:
        if cap.evidence.value == "potential":
            assert cap.kind == CapabilityKind.POTENTIAL


def test_invariant_identical_inputs_identical_delta():
    engine = fresh_engine(mode="observe")
    action = Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id="inv-d1", tenant_id="t")
    _f1, r1 = run_step(engine, action)
    reset_authority_registry()
    engine2 = fresh_engine(mode="observe")
    action2 = Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id="inv-d2", tenant_id="t")
    _f2, r2 = run_step(engine2, action2)
    assert r1.delta.to_dict()["added_capabilities"] == r2.delta.to_dict()["added_capabilities"]


def test_invariant_removing_edge_cannot_increase_reachability():
    g = CapabilityGraph()
    for n in ("a", "b", "c"):
        g.add_node(GraphNode(node_id=n, node_type="capability", label=n))
    e1 = GraphEdge(src="a", dst="b", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED)
    e2 = GraphEdge(src="b", dst="c", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED)
    g.add_edge(e1)
    g.add_edge(e2)
    before = bounded_reachability(g, ["a"], max_depth=3, target="c")
    g.remove_edge(e2.edge_id)
    after = bounded_reachability(g, ["a"], max_depth=3, target="c")
    assert after.reachable <= before.reachable


def test_invariant_adding_edge_cannot_reduce_reachability():
    g = CapabilityGraph()
    for n in ("a", "b", "c"):
        g.add_node(GraphNode(node_id=n, node_type="capability", label=n))
    g.add_edge(GraphEdge(src="a", dst="b", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    before = bounded_reachability(g, ["a"], max_depth=3, target="c")
    g.add_edge(GraphEdge(src="b", dst="c", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    after = bounded_reachability(g, ["a"], max_depth=3, target="c")
    assert after.reachable >= before.reachable


def test_invariant_no_raw_secrets_in_audit_metadata():
    engine = fresh_engine(mode="observe")
    secret = "super-secret-password-value-xyz"
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": [f"password={secret}", "r"]},
        metadata=untrusted_meta(),
        trace_id="inv-sec",
        tenant_id="t",
    )
    run_step(engine, action)
    assert secret not in str(action.metadata)
