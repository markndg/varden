"""Security self-review coverage for Predictive Authority."""

from __future__ import annotations

from varden.models import Action
from varden.predictive_authority.capability import canonicalize_capability_name
from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.policy import PredictiveRecommendation, strengthen_decision
from varden.models import Decision
from tests.predictive_authority.helpers import fresh_engine, run_step, untrusted_meta


def test_review_attacker_controlled_capability_names_cannot_inject_separators():
    name = canonicalize_capability_name("aws\n.s3;drop|table")
    assert "\n" not in name
    assert ";" not in name or name == canonicalize_capability_name(name)


def test_review_stale_cache_not_used_across_depth_change():
    from varden.predictive_authority.reachability import bounded_reachability

    g = CapabilityGraph()
    for n in ("a", "b", "c", "d"):
        g.add_node(GraphNode(node_id=n, node_type="capability", label=n))
    for a, b in (("a", "b"), ("b", "c"), ("c", "d")):
        g.add_edge(GraphEdge(src=a, dst=b, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    assert bounded_reachability(g, ["a"], max_depth=2, target="d").reachable is False
    assert bounded_reachability(g, ["a"], max_depth=3, target="d").reachable is True


def test_review_failure_cannot_bypass_existing_block():
    engine = fresh_engine(mode="enforce")

    def boom(*_a, **_k):
        raise RuntimeError("fail")

    import varden.predictive_authority.engine as eng

    original = eng.extract_facts
    eng.extract_facts = boom  # type: ignore[assignment]
    try:
        final, result = engine.evaluate(
            Action(type="http_request", method="POST", url="https://x", trace_id="rev", tenant_id="t"),
            Decision(action="block", reason="policy", effective_action="block"),
        )
        assert final.action == "block"
        assert result.error
    finally:
        eng.extract_facts = original


def test_review_potential_not_collapsed_in_recommendation_metadata():
    engine = fresh_engine(mode="observe")
    _f, result = run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id="rev-p",
            tenant_id="t",
        ),
    )
    meta = (result.to_metadata().get("delta") or {})
    kinds = {c["kind"] for c in meta.get("added_capabilities") or []}
    assert "potential" in kinds
