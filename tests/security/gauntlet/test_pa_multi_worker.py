"""Gauntlet Phase 6 — multi-worker authority continuity.

Live PA state is process-local. Two isolated registries simulate two workers:
a hazardous chain split across them is missed. That is unsupported for enforce
mode unless ``VARDEN_PA_ALLOW_MULTI_WORKER`` is explicitly set.
"""

from __future__ import annotations

from varden.models import Action
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.deployment import pa_deployment_status
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import AuthorityRegistry

from tests.predictive_authority.helpers import allow_decision, untrusted_meta


def _prior(trace: str) -> list[Action]:
    return [
        Action(
            type="tool_call",
            tool="ingest_issue",
            metadata=untrusted_meta("github.issue"),
            classifiers={"provenance_untrusted": True},
            trace_id=trace,
            tenant_id="t",
        ),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta("github.issue"),
            trace_id=trace,
            tenant_id="t",
        ),
    ]


def _shell(trace: str) -> Action:
    return Action(type="tool_call", tool="shell", args={"command": "env"}, trace_id=trace, tenant_id="t")


_SINGLE = {"VARDEN_PA_DEPLOYMENT": "single_worker"}


def test_gauntlet_BEFORE_cross_worker_chain_is_missed_without_failsafe():
    """Characterization: split chain across two registries weakens the final hop.

    Each registry declares single_worker (as independent processes often would).
    Env detection cannot see the sibling process — architectural miss.
    """
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    worker_a = PredictiveAuthorityEngine(
        cfg, registry=AuthorityRegistry(max_sessions=100, idle_seconds=0), env=_SINGLE
    )
    for action in _prior("cross-worker"):
        worker_a.evaluate(action, allow_decision(), policy={})

    worker_b = PredictiveAuthorityEngine(
        cfg, registry=AuthorityRegistry(max_sessions=100, idle_seconds=0), env=_SINGLE
    )
    same_process = PredictiveAuthorityEngine(cfg, registry=worker_a._registry, env=_SINGLE)

    same_final, same_res = same_process.evaluate(_shell("cross-worker"), allow_decision(), policy={})
    split_final, split_res = worker_b.evaluate(_shell("cross-worker"), allow_decision(), policy={})

    assert decision_rank(same_final.action) >= decision_rank("require_approval")
    assert same_res.findings
    assert decision_rank(split_final.action) < decision_rank(same_final.action)
    assert split_final.action == "allow"


def test_gauntlet_AFTER_multi_worker_enforce_failsafe():
    """G-PA-MULTI-01: enforce + WEB_CONCURRENCY>1 without opt-in must fail-safe."""
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    env = {"WEB_CONCURRENCY": "4", "VARDEN_PA_DEPLOYMENT": "single_worker"}
    assert pa_deployment_status(enforce=True, env=env)["reason"] == "MULTI_WORKER_UNSUPPORTED"

    engine = PredictiveAuthorityEngine(
        cfg,
        registry=AuthorityRegistry(max_sessions=100, idle_seconds=0),
        env=env,
    )
    final, result = engine.evaluate(_shell("mw-1"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason == "MULTI_WORKER_UNSUPPORTED"
    assert result.to_metadata()["safe_conclusion"] is False
    assert decision_rank(final.action) >= decision_rank("require_approval")


def test_gauntlet_multi_worker_explicit_allow_opt_in():
    """Opt-in accepts residual risk — not independently verified shared-state safety."""
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    env = {"WEB_CONCURRENCY": "4", "VARDEN_PA_ALLOW_MULTI_WORKER": "1"}
    status = pa_deployment_status(enforce=True, env=env)
    assert status["unsupported_multi_worker_enforce"] is False
    assert status["reason"] == "MULTI_WORKER_EXPLICITLY_ALLOWED"
    engine = PredictiveAuthorityEngine(
        cfg,
        registry=AuthorityRegistry(max_sessions=100, idle_seconds=0),
        env=env,
    )
    final, result = engine.evaluate(_shell("mw-allow"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason != "MULTI_WORKER_UNSUPPORTED"
    assert final.action == "allow"


def test_gauntlet_AFTER_shared_db_leases_catch_split_workers(tmp_path):
    """Sibling processes declaring single_worker still fail-safe via shared DB leases."""
    from varden.predictive_authority.continuity_store import ContinuityStore

    db = str(tmp_path / "shared.db")
    store_a = ContinuityStore(db, worker_id="wa", lease_ttl=60.0)
    store_b = ContinuityStore(db, worker_id="wb", lease_ttl=60.0)
    store_a.touch_lease()
    store_b.touch_lease()

    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    worker_a = PredictiveAuthorityEngine(
        cfg, registry=AuthorityRegistry(max_sessions=100, idle_seconds=0), env=_SINGLE
    )
    worker_a._registry.attach_continuity_store(store_a)
    for action in _prior("cross-worker-durable"):
        worker_a.evaluate(action, allow_decision(), policy={})

    worker_b = PredictiveAuthorityEngine(
        cfg, registry=AuthorityRegistry(max_sessions=100, idle_seconds=0), env=_SINGLE
    )
    worker_b._registry.attach_continuity_store(store_b)
    split_final, split_res = worker_b.evaluate(_shell("cross-worker-durable"), allow_decision(), policy={})
    assert split_res.analysis_incomplete_reason == "MULTI_WORKER_UNSUPPORTED"
    assert decision_rank(split_final.action) >= decision_rank("require_approval")


def test_gauntlet_observe_multi_worker_does_not_block():
    cfg = PredictiveAuthorityConfig(enabled=True, mode="observe", max_depth=4)
    engine = PredictiveAuthorityEngine(
        cfg,
        registry=AuthorityRegistry(max_sessions=100, idle_seconds=0),
        env={"WEB_CONCURRENCY": "8"},
    )
    final, result = engine.evaluate(_shell("mw-obs"), allow_decision(), policy={})
    assert final.action == "allow"
    assert (result.after_snapshot or {}).get("deployment", {}).get("multi_worker_detected") is True
