"""Adversarial tests for Predictive Authority."""

from __future__ import annotations

from varden.models import Action, Decision
from varden.predictive_authority.capability import canonicalize_capability_name
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine, apply_predictive_authority
from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.policy import strengthen_decision
from varden.predictive_authority.registry import reset_authority_registry
from varden.predictive_authority.resource import sanitize_identifier

from tests.predictive_authority.helpers import allow_decision, fresh_engine, run_step, untrusted_meta


def test_graph_node_id_poisoning_normalized():
    assert "../" not in canonicalize_capability_name("../../etc/passwd")
    assert "\0" not in canonicalize_capability_name("aws\0s3")


def test_secret_values_never_in_metadata():
    engine = fresh_engine(mode="observe")
    secret = "AKIAEXAMPLESECRETVALUE999"
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": [f"AWS_SECRET_ACCESS_KEY={secret}", "r"]},
        trace_id="adv-secret",
        tenant_id="t",
    )
    _final, result = run_step(engine, action)
    blob = str(action.metadata)
    assert secret not in blob
    if result.explanation:
        assert secret not in result.explanation.render()


def test_cyclic_graph_does_not_hang():
    g = CapabilityGraph()
    for n in ("a", "b"):
        g.add_node(GraphNode(node_id=n, node_type="capability", label=n))
    g.add_edge(GraphEdge(src="a", dst="b", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    g.add_edge(GraphEdge(src="b", dst="a", kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    from varden.predictive_authority.reachability import bounded_reachability

    r = bounded_reachability(g, ["a"], max_depth=10, target="b")
    assert r.reachable is True


def test_graph_bounds_truncate_dos():
    g = CapabilityGraph(max_nodes=5, max_edges=5)
    for i in range(20):
        g.add_node(GraphNode(node_id=f"n{i}", node_type="capability", label=str(i)))
    assert g.truncated is True
    assert g.node_count() <= 5


def test_enforce_cannot_weaken_block_to_allow():
    from varden.predictive_authority.policy import PredictiveRecommendation

    existing = Decision(action="block", reason="policy", effective_action="block")
    rec = PredictiveRecommendation(action="allow", reason="noop", matched_predicates=[], authority_expands=False, structural_units=0)
    out = strengthen_decision(existing, rec)
    assert out.action == "block"


def test_off_mode_is_noop_on_action():
    reset_authority_registry()
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata=untrusted_meta(),
        trace_id="off",
        tenant_id="t",
    )
    existing = allow_decision()
    final, result = apply_predictive_authority(
        action,
        existing,
        config=PredictiveAuthorityConfig(enabled=False, mode="off"),
    )
    assert final.action == "allow"
    assert result.recommendation is None
    assert "predictive_authority" not in (action.metadata or {}) or not (action.metadata.get("predictive_authority") or {}).get("delta")


def test_unicode_identifier_sanitized():
    text = sanitize_identifier("cred\u202eentials")
    assert isinstance(text, str)
    assert len(text) > 0


def test_concurrent_session_updates_do_not_corrupt():
    import threading

    engine = fresh_engine(mode="observe", max_depth=3)
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            for j in range(8):
                run_step(
                    engine,
                    Action(
                        type="filesystem_read",
                        tool="open",
                        args={"args": [f"file_{i}_{j}.txt", "r"]},
                        trace_id="concurrent",
                        tenant_id="t",
                    ),
                )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
