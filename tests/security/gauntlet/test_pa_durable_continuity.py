"""Durable PA continuity — restart, tombstone, multi-worker lease fail-safes."""

from __future__ import annotations

import time
from pathlib import Path

from varden.models import Action
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.continuity_store import ContinuityStore
from varden.predictive_authority.deployment import pa_deployment_status
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import AuthorityRegistry
from varden.predictive_authority.state import AuthorityTransitionRecord

from tests.predictive_authority.helpers import allow_decision, untrusted_meta

_SINGLE = {"VARDEN_PA_DEPLOYMENT": "single_worker"}


def _shell(trace: str) -> Action:
    return Action(type="tool_call", tool="shell", args={"command": "env"}, trace_id=trace, tenant_id="t")


def _cred(trace: str) -> Action:
    return Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata=untrusted_meta("github.issue"),
        classifiers={"provenance_untrusted": True},
        trace_id=trace,
        tenant_id="t",
    )


def test_gauntlet_AFTER_restart_reintroduced_session_failsafe(tmp_path: Path):
    """G-PA-RESTART-01: durable had_authority → continuity_broken after new process_id."""
    db = str(tmp_path / "c.db")
    store_a = ContinuityStore(db, worker_id="worker-a", lease_ttl=60.0)
    reg_a = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    reg_a.attach_continuity_store(store_a)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    eng_a = PredictiveAuthorityEngine(cfg, registry=reg_a, env=_SINGLE)
    eng_a.evaluate(_cred("restart-vic"), allow_decision(), policy={})
    # Simulate process death: expire worker-a lease so B is not seen as multi-worker.
    with __import__("varden.db", fromlist=["connect"]).connect(db) as conn:
        conn.execute("UPDATE pa_worker_leases SET last_seen = 0 WHERE worker_id = ?", ("worker-a",))
        conn.commit()
    store_b = ContinuityStore(db, worker_id="worker-b", lease_ttl=60.0)
    assert store_b.process_id != store_a.process_id
    reg_b = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    reg_b.attach_continuity_store(store_b)
    eng_b = PredictiveAuthorityEngine(cfg, registry=reg_b, env=_SINGLE)
    final, result = eng_b.evaluate(_shell("restart-vic"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason == "SESSION_CONTINUITY_BROKEN"
    assert decision_rank(final.action) >= decision_rank("require_approval")
    assert result.to_metadata()["safe_conclusion"] is False


def test_gauntlet_AFTER_durable_tombstone_survives_memory_forget(tmp_path: Path):
    """In-memory tombstone forget still fail-safes via durable tombstone row."""
    db = str(tmp_path / "t.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    reg.attach_continuity_store(store)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    store.record_tombstone("t:vic", "lru")
    # No in-memory tombstone — only durable row.
    assert "t:vic" not in reg._authority_tombstones
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    final, result = eng.evaluate(_shell("vic"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason == "SESSION_CONTINUITY_BROKEN"
    assert decision_rank(final.action) >= decision_rank("require_approval")


def test_gauntlet_AFTER_lease_detects_sibling_single_worker_processes(tmp_path: Path):
    """G-PA-MULTI-01: two leases on shared DB fail-safe without WEB_CONCURRENCY."""
    db = str(tmp_path / "w.db")
    store_a = ContinuityStore(db, worker_id="a", lease_ttl=60.0)
    store_b = ContinuityStore(db, worker_id="b", lease_ttl=60.0)
    store_a.touch_lease()
    store_b.touch_lease()
    assert store_a.active_worker_count() >= 2

    reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    reg.attach_continuity_store(store_a)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    # Declared single_worker AND no WEB_CONCURRENCY — lease still detects siblings
    status = pa_deployment_status(
        enforce=True,
        env=_SINGLE,
        active_workers=reg.active_worker_count(),
    )
    assert status["reason"] == "MULTI_WORKER_UNSUPPORTED"
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    final, result = eng.evaluate(_shell("lease-1"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason == "MULTI_WORKER_UNSUPPORTED"
    assert decision_rank(final.action) >= decision_rank("require_approval")


def test_gauntlet_benign_new_session_after_restart_still_allows(tmp_path: Path):
    """Fresh session keys with no durable history remain allow under enforce."""
    db = str(tmp_path / "b.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    reg.attach_continuity_store(store)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    final, result = eng.evaluate(_shell("brand-new"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason not in {
        "SESSION_CONTINUITY_BROKEN",
        "MULTI_WORKER_UNSUPPORTED",
        "TOMBSTONE_HISTORY_INCOMPLETE",
    }
    assert final.action == "allow"


def test_gauntlet_preserve_existing_cannot_weaken_continuity_failsafe(tmp_path: Path):
    """integrity incomplete reasons ignore failure_mode=preserve_existing."""
    db = str(tmp_path / "pe.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    reg.attach_continuity_store(store)
    store.record_tombstone("t:vic", "lru")
    cfg = PredictiveAuthorityConfig(
        enabled=True, mode="enforce", max_depth=4, failure_mode="preserve_existing"
    )
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    final, result = eng.evaluate(_shell("vic"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason == "SESSION_CONTINUITY_BROKEN"
    assert decision_rank(final.action) >= decision_rank("require_approval")


def test_gauntlet_provenance_only_state_is_tombstoned_on_eviction():
    """Provenance-only accumulated state must not be silently forgotten."""
    reg = AuthorityRegistry(max_sessions=2, idle_seconds=0)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    st = reg.get_or_create("t:prov", cfg)
    st.provenance_refs.append("src-untrusted-1")
    # Flood with other accumulated-authority sessions so LRU drops t:prov
    # (empty peers are preferred for eviction and would leave t:prov alive).
    for i in range(8):
        peer = reg.get_or_create(f"t:peer-{i}", cfg)
        peer.history.append(
            AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="n",
                added_capabilities=["x"],
                added_resources=[],
                added_sinks=[],
            )
        )
    assert reg.get("t:prov") is None
    # Either the key is still tombstoned, or tombstone-table pressure degraded
    # the process — both are fail-safe (not silent allow).
    assert "t:prov" in reg._authority_tombstones or reg.continuity_degraded()
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    final, result = eng.evaluate(_shell("prov"), allow_decision(), policy={})
    assert result.analysis_incomplete_reason in {
        "SESSION_CONTINUITY_BROKEN",
        "TOMBSTONE_HISTORY_INCOMPLETE",
    }
    assert decision_rank(final.action) >= decision_rank("require_approval")
