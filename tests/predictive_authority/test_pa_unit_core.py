"""Unit tests for Predictive Authority core types."""

from __future__ import annotations

from varden.predictive_authority.capability import (
    Capability,
    CapabilityKind,
    canonicalize_capability_name,
    merge_capability_sets,
    potential_grants_for_credential,
)
from varden.predictive_authority.config import parse_predictive_config
from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.policy import decision_rank, strongest_decision
from varden.predictive_authority.reachability import bounded_reachability
from varden.predictive_authority.resource import sanitize_identifier
from varden.predictive_authority.reversibility import classify_action_reversibility


def test_config_defaults_off():
    cfg = parse_predictive_config(None)
    assert cfg.enabled is False
    assert cfg.mode == "off"
    assert not cfg.is_active()


def test_config_env_observe():
    cfg = parse_predictive_config(None, env={"VARDEN_PA_MODE": "observe"})
    assert cfg.enabled is True
    assert cfg.mode == "observe"


def test_capability_canonicalization_rejects_path_poison():
    assert canonicalize_capability_name("aws/s3\\write") == "aws.s3.write"


def test_potential_grants_are_potential_not_confirmed():
    grants = potential_grants_for_credential("credential.aws")
    assert grants
    assert all(g.kind == CapabilityKind.POTENTIAL for g in grants)
    assert all(g.evidence.value == "potential" for g in grants)


def test_merge_confirmed_wins_over_potential():
    pot = Capability(name="aws.s3.read", kind=CapabilityKind.POTENTIAL)
    conf = Capability(name="aws.s3.read", kind=CapabilityKind.CONFIRMED, sensitivity=55)
    merged = merge_capability_sets([pot], [conf])
    assert merged["aws.s3.read"].kind == CapabilityKind.CONFIRMED


def test_sanitize_identifier_redacts_secret_assignment():
    text = sanitize_identifier("AWS_SECRET_ACCESS_KEY=AKIAEXAMPLESECRETVALUE")
    assert "AKIA" not in text
    assert "<redacted>" in text


def test_decision_strengthen_never_weakens():
    assert strongest_decision("block", "allow") == "block"
    assert strongest_decision("allow", "require_approval") == "require_approval"
    assert decision_rank("block") > decision_rank("require_approval")


def test_reachability_respects_max_depth_and_cycles():
    g = CapabilityGraph()
    for name in ("a", "b", "c", "d", "e"):
        g.add_node(GraphNode(node_id=name, node_type="capability", label=name))
    for src, dst in (("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("e", "b")):
        g.add_edge(GraphEdge(src=src, dst=dst, kind=EdgeKind.ENABLES, evidence=EdgeEvidence.OBSERVED))
    r3 = bounded_reachability(g, ["a"], max_depth=3, target="e")
    assert r3.reachable is False
    r4 = bounded_reachability(g, ["a"], max_depth=4, target="e")
    assert r4.reachable is True
    assert r4.shortest() is not None
    assert r4.shortest().length == 4


def test_http_post_is_irreversible():
    assert classify_action_reversibility("http_request", method="POST").value == "irreversible"
    assert classify_action_reversibility("http_request", method="GET").value == "reversible"
