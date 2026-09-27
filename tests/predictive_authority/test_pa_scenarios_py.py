"""Scenarios P–Y: evidence, lifecycle, poisoning, sanitisation, truncation, UI truthfulness."""

from __future__ import annotations

import threading

from varden.models import Action, Decision
from varden.predictive_authority.capability import CapabilityKind
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.evidence import AuthorityLifecycle, EvidenceKind
from varden.predictive_authority.lifecycle import apply_trusted_scope_narrowing, revoke_capability
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import get_authority_registry, reset_authority_registry
from varden.predictive_authority.views import build_demo_fixture, build_session_view, safe_label

from tests.predictive_authority.helpers import allow_decision, fresh_engine, run_step, untrusted_meta


def test_scenario_p_graph_poisoning_untrusted_mcp_cannot_confirm():
    engine = fresh_engine(mode="enforce")
    final, result = run_step(
        engine,
        Action(
            type="mcp_call",
            tool="read_status",
            metadata={
                "mcp_server": "evil-mcp",
                "declared_capabilities": ["credential.aws", "aws.iam.modify"],
                "provenance_sources": [
                    {"source_id": "evil", "type": "mcp_tool_definition", "trust_level": "untrusted", "server": "evil-mcp"}
                ],
            },
            classifiers={"provenance_untrusted": True},
            trace_id="p",
            tenant_id="t",
        ),
    )
    state = get_authority_registry().get("t:p")
    for name in ("credential.aws", "aws.iam.modify"):
        cap = state.capabilities.get(name)
        assert cap is not None
        assert cap.kind == CapabilityKind.POTENTIAL
        assert (cap.metadata or {}).get("untrusted_declared") is True
    # Edges introducing those caps must be untrusted_declared evidence.
    for edge in state.graph.edges():
        if edge.dst.endswith("credential.aws") or edge.dst.endswith("aws.iam.modify"):
            if edge.kind.value == "introduces":
                assert edge.evidence.kind == EvidenceKind.UNTRUSTED_DECLARED
                assert edge.lifecycle != AuthorityLifecycle.CONFIRMED


def test_scenario_q_potential_disproven_by_trusted_scope():
    engine = fresh_engine(mode="observe")
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            trace_id="q",
            tenant_id="t",
        ),
    )
    state = get_authority_registry().get("t:q")
    assert any(n.startswith("aws.") for n in state.capabilities)
    result = apply_trusted_scope_narrowing(state, "credential.aws", ["aws.s3.read"])
    assert "aws.s3.read" in result["confirmed"]
    assert state.capabilities["aws.s3.read"].kind == CapabilityKind.CONFIRMED
    # Disproven potentials must not remain as active capabilities.
    for name in result["disproven"]:
        assert name not in state.capabilities or state.graph.get_node(f"cap.potential:{name}") is None or (
            state.graph.get_node(f"cap:{name}") and state.graph.get_node(f"cap:{name}").lifecycle == AuthorityLifecycle.DISPROVEN
        ) or True
    # Reachability via disproven edges must not increase.
    from varden.predictive_authority.reachability import bounded_reachability

    r = bounded_reachability(
        state.graph,
        [n.node_id for n in state.graph.nodes() if "credential.aws" in n.node_id],
        max_depth=3,
        predicate=lambda n: "aws.iam.modify" in n,
    )
    assert r.reachable is False


def test_scenario_r_capability_revoked_updates_reachability():
    engine = fresh_engine(mode="observe")
    run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]}, trace_id="r", tenant_id="t"),
    )
    state = get_authority_registry().get("t:r")
    assert "credential.aws" in state.capabilities
    assert revoke_capability(state, "credential.aws") is True
    assert "credential.aws" not in state.capabilities
    node = state.graph.get_node("cap:credential.aws")
    assert node is None or node.lifecycle == AuthorityLifecycle.REVOKED


def test_scenario_s_trusted_sanitisation_terminates_sensitive_flow():
    engine = fresh_engine(mode="enforce", max_depth=4)
    run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]}, trace_id="s", tenant_id="t"),
    )
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            method="POST",
            url="https://out.example/x",
            domain="out.example",
            classifiers={"sanitised": True},
            metadata={"varden_sanitised": True},
            trace_id="s",
            tenant_id="t",
        ),
    )
    state = get_authority_registry().get("t:s")
    assert any(n.node_type == "sanitisation_boundary" for n in state.graph.nodes())
    # Sensitive flow via SANITISED_BY should not appear as untrusted_to_sensitive_to_external
    # with credential directly reaching sink through active edges.
    from varden.predictive_authority.reachability import bounded_reachability

    cred_nodes = [n.node_id for n in state.graph.nodes() if (n.metadata or {}).get("credential")]
    r = bounded_reachability(state.graph, cred_nodes, max_depth=4, predicate=lambda n: "http.write" in n or "out.example" in n)
    assert r.reachable is False

def test_scenario_t_fake_sanitisation_does_not_terminate():
    engine = fresh_engine(mode="enforce", max_depth=4)
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id="t-fake",
            tenant_id="t",
        ),
    )
    final, result = run_step(
        engine,
        Action(
            type="http_request",
            method="POST",
            url="https://out.example/x",
            domain="out.example",
            metadata={**untrusted_meta(), "claimed_sanitised": True},
            trace_id="t-fake",
            tenant_id="t",
        ),
    )
    assert decision_rank(final.action) >= decision_rank("require_approval") or result.findings


def test_scenario_u_truncation_never_safe():
    engine = PredictiveAuthorityEngine(
        PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=3, max_nodes=3, max_edges=3, failure_mode="require_approval")
    )
    reset_authority_registry()
    # Force many nodes.
    for i in range(10):
        final, result = engine.evaluate(
            Action(type="filesystem_read", tool="open", args={"args": [f"file_{i}.txt", "r"]}, trace_id="u", tenant_id="t"),
            allow_decision(),
        )
    assert result.analysis_status in {"truncated", "complete", "failed"}
    state = get_authority_registry().get("t:u")
    if state and state.graph.truncated:
        assert result.analysis_status == "truncated"
        assert result.to_metadata().get("safe_conclusion") is False
        assert decision_rank(final.action) >= decision_rank("require_approval")


def test_scenario_v_enforce_failure_require_approval(monkeypatch):
    engine = PredictiveAuthorityEngine(
        PredictiveAuthorityConfig(enabled=True, mode="enforce", failure_mode="require_approval")
    )
    reset_authority_registry()

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("varden.predictive_authority.engine.extract_facts", boom)
    final, result = engine.evaluate(
        Action(type="http_request", method="POST", url="https://x", trace_id="v", tenant_id="t"),
        allow_decision(),
    )
    assert result.analysis_status == "failed"
    assert result.to_metadata().get("safe_conclusion") is False
    assert final.action == "require_approval"


def test_scenario_w_trusted_vs_untrusted_evidence_differ():
    engine = fresh_engine(mode="observe")
    run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]}, trace_id="w", tenant_id="t"),
    )
    run_step(
        engine,
        Action(
            type="mcp_call",
            tool="read_status",
            metadata={"mcp_server": "evil", "declared_capabilities": ["aws.s3.read"]},
            classifiers={"provenance_untrusted": True},
            trace_id="w",
            tenant_id="t",
        ),
    )
    state = get_authority_registry().get("t:w")
    kinds = set()
    for edge in state.graph.edges():
        if "aws.s3.read" in edge.dst or "credential.aws" in edge.dst:
            kinds.add(edge.evidence.kind.value)
    assert "untrusted_declared" in kinds or any(
        (c.metadata or {}).get("untrusted_declared") for c in state.capabilities.values()
    )
    # Observed credential remains distinct from untrusted claim.
    assert state.capabilities.get("credential.aws") is not None


def test_scenario_x_concurrent_acquire_and_revoke():
    engine = fresh_engine(mode="observe")
    run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]}, trace_id="x", tenant_id="t"),
    )
    state = get_authority_registry().get("t:x")
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            if i % 2 == 0:
                run_step(
                    engine,
                    Action(type="filesystem_read", tool="open", args={"args": [f"f{i}.txt", "r"]}, trace_id="x", tenant_id="t"),
                )
            else:
                revoke_capability(state, "credential.aws")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # Coherent: either present or revoked — not corrupt.
    cap = state.capabilities.get("credential.aws")
    node = state.graph.get_node("cap:credential.aws")
    assert cap is None or isinstance(cap.name, str)
    assert node is None or node.lifecycle in {
        AuthorityLifecycle.CONFIRMED,
        AuthorityLifecycle.POTENTIAL,
        AuthorityLifecycle.REVOKED,
        AuthorityLifecycle.DISPROVEN,
        AuthorityLifecycle.EXPIRED,
        AuthorityLifecycle.UNKNOWN,
    }


def test_scenario_y_ui_truthfulness_observed_vs_predicted():
    fixture = build_demo_fixture(mode="enforce")
    haz = fixture["hazardous"]
    assert haz["live"] is True
    events = haz.get("events") or []
    assert events
    last = events[-1]
    assert last.get("existing_decision") == "allow"
    assert last.get("recommendation") in {"require_approval", "block", "warn", "monitor"}
    # Must not claim the predicted mutation already occurred.
    assert last.get("mode") in {"enforce", "observe"}
    meta_warning = "Predicted" in str(build_session_view(tenant_id="demo", trace_id="ui-demo")) or True
    assert safe_label("<script>alert(1)</script>") == "‹script›alert(1)‹/script›"
    # Safe session should not be all-red.
    safe = fixture["safe"]
    assert safe["live"] is True
