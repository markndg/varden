"""RC ContinuityStore fault injection — fail-safe outcomes, never silent allow.

Uses real temporary SQLite databases. Side effects under continuity failure
must remain denied (require_approval/block), not converted to clean authority.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from pathlib import Path

import pytest

from varden.db import connect, init_db
from varden.models import Action, Decision
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.continuity_store import ContinuityStore
from varden.predictive_authority.deployment import pa_deployment_status
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import AuthorityRegistry
from varden.runtime.approvals import ApprovalStore

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


def _eng(reg: AuthorityRegistry) -> PredictiveAuthorityEngine:
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    return PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)


def _assert_failsafe(final: Decision, result, *, reasons: set[str] | None = None) -> None:
    assert decision_rank(final.action) >= decision_rank("require_approval")
    assert result.to_metadata()["safe_conclusion"] is False
    if reasons is not None:
        assert result.analysis_incomplete_reason in reasons


# ---------------------------------------------------------------------------
# 1. ContinuityStore fault injection
# ---------------------------------------------------------------------------


def test_rc_BEFORE_deleted_db_must_not_claim_verified_restart(tmp_path: Path):
    """Deterministic pre-fix posture check preserved as regression guard.

    Binding a store must never set cross_restart_continuity_verified=True —
    durable fail-safes are not verified graph replay.
    """
    db = str(tmp_path / "claim.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    status = reg.continuity_status()
    assert status["durable_store_bound"] is True
    assert status["cross_restart_continuity_verified"] is False
    assert reg.stats()["cross_restart_continuity_verified"] is False


def test_rc_db_deleted_mid_flight_failsafe(tmp_path: Path):
    db = str(tmp_path / "gone.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    eng = _eng(reg)
    eng.evaluate(_cred("del-1"), allow_decision(), policy={})
    Path(db).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(db + suffix).unlink(missing_ok=True)
    final, result = eng.evaluate(_shell("del-1b"), allow_decision(), policy={})
    _assert_failsafe(
        final,
        result,
        reasons={
            "CONTINUITY_STORE_WRITE_FAILED",
            "CONTINUITY_STORE_LEASE_FAILED",
            "CONTINUITY_STORE_READ_FAILED",
            "MULTI_WORKER_UNSUPPORTED",
            "TOMBSTONE_HISTORY_INCOMPLETE",
        },
    )
    assert reg.continuity_degraded() is True


def test_rc_readonly_db_attach_degrades_not_crash(tmp_path: Path):
    db = str(tmp_path / "ro.db")
    init_db(db)
    ContinuityStore(db).touch_lease_and_count()
    os.chmod(db, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    for suffix in ("-wal", "-shm"):
        p = Path(db + suffix)
        if p.exists():
            os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    try:
        try:
            store = ContinuityStore(db)
        except Exception:
            reg.mark_continuity_degraded("CONTINUITY_STORE_BIND_FAILED")
        else:
            # Must not raise — degrade instead.
            reg.attach_continuity_store(store)
        assert reg.continuity_degraded() is True
        final, result = _eng(reg).evaluate(_shell("ro-1"), allow_decision(), policy={})
        _assert_failsafe(final, result)
    finally:
        try:
            os.chmod(db, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        for suffix in ("-wal", "-shm"):
            p = Path(db + suffix)
            if p.exists():
                try:
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass


def test_rc_locked_db_busy_failsafe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = str(tmp_path / "busy.db")
    init_db(db)
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    assert not reg.continuity_degraded()

    # Short busy timeout so the test does not wait on the default 30s PRAGMA.
    import varden.db as dbmod

    def _short_connect(path: str):
        conn = sqlite3.connect(path, timeout=0.05, factory=dbmod._AutoCloseConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 50")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    monkeypatch.setattr(dbmod, "connect", _short_connect)

    locker = sqlite3.connect(db, timeout=0.05)
    locker.execute("PRAGMA busy_timeout = 50")
    locker.execute("BEGIN EXCLUSIVE")
    try:
        final, result = _eng(reg).evaluate(_shell("busy-1"), allow_decision(), policy={})
        _assert_failsafe(final, result)
        assert reg.continuity_degraded() is True
    finally:
        locker.rollback()
        locker.close()


def test_rc_corrupt_database_bind_degrades(tmp_path: Path):
    db = str(tmp_path / "corrupt.db")
    Path(db).write_bytes(b"not a sqlite database at all!!!")
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    try:
        store = ContinuityStore(db)
        reg.attach_continuity_store(store)
    except Exception:
        reg.mark_continuity_degraded("CONTINUITY_STORE_BIND_FAILED")
    assert reg.continuity_degraded() is True
    final, result = _eng(reg).evaluate(_shell("corrupt-1"), allow_decision(), policy={})
    _assert_failsafe(final, result)


def test_rc_schema_mismatch_failsafe(tmp_path: Path):
    db = str(tmp_path / "schema.db")
    init_db(db)
    with connect(db) as conn:
        conn.execute("DROP TABLE pa_continuity_sessions")
        conn.commit()
    store = ContinuityStore(db)
    # init_db in ContinuityStore.__init__ re-creates IF NOT EXISTS — force drop after.
    with connect(db) as conn:
        conn.execute("DROP TABLE IF EXISTS pa_worker_leases")
        conn.commit()
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    final, result = _eng(reg).evaluate(_shell("schema-1"), allow_decision(), policy={})
    _assert_failsafe(final, result)
    assert reg.continuity_degraded() is True


def test_rc_db_replaced_with_empty_loses_prior_authority_signal(tmp_path: Path):
    """Replacement DB without prior rows: live process still has state; restart would lose signals.

    Mid-process replacement: next durable ops may succeed against empty DB —
    process-local state remains. After eviction+recreate without durable marker,
    only process tombstones protect. This test forces eviction after replace and
    verifies we do not claim verified continuity.
    """
    db = str(tmp_path / "swap.db")
    store = ContinuityStore(db, worker_id="w1")
    reg = AuthorityRegistry(max_sessions=2, idle_seconds=0)
    reg.attach_continuity_store(store)
    eng = _eng(reg)
    eng.evaluate(_cred("swap-vic"), allow_decision(), policy={})
    # Replace DB file with a fresh empty DB (same path).
    Path(db).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(db + suffix).unlink(missing_ok=True)
    init_db(db)
    store2 = ContinuityStore(db, worker_id="w1")
    reg.attach_continuity_store(store2)
    # Status must never claim verified cross-restart continuity.
    assert reg.continuity_status()["cross_restart_continuity_verified"] is False
    # Flood to evict swap-vic then recreate — without durable had_authority,
    # process tombstone or degrade must still fail-safe if authority was held.
    for i in range(6):
        peer = reg.get_or_create(f"t:peer-{i}", PredictiveAuthorityConfig(enabled=True, mode="enforce"))
        peer.history.append(
            __import__(
                "varden.predictive_authority.state", fromlist=["AuthorityTransitionRecord"]
            ).AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="n",
                added_capabilities=["x"],
                added_resources=[],
                added_sinks=[],
            )
        )
    final, result = eng.evaluate(_shell("swap-vic"), allow_decision(), policy={})
    # Either continuity_broken (process tombstone) or degraded / multi — not clean allow.
    if final.action == "allow" and not result.analysis_incomplete_reason:
        pytest.fail("replaced DB must not restore clean allow for prior authority session")
    _assert_failsafe(final, result)


def test_rc_concurrent_transactions_atomic_lease_count(tmp_path: Path):
    db = str(tmp_path / "race.db")
    init_db(db)
    results: list[int] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        try:
            store = ContinuityStore(db, worker_id=f"w-{i}", lease_ttl=60.0)
            barrier.wait(timeout=5)
            n = store.touch_lease_and_count()
            results.append(n)
        except BaseException as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    assert results
    # At least one observer must see multi-worker after the race settles.
    assert max(results) >= 2
    # Final durable count is 8.
    assert ContinuityStore(db, worker_id="observer").active_worker_count() == 8


def test_rc_lease_failure_returns_conservative_worker_count(tmp_path: Path):
    db = str(tmp_path / "leasefail.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    Path(db).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(db + suffix).unlink(missing_ok=True)
    n = reg.active_worker_count()
    assert n == 2  # conservative — never None→single-worker allow
    assert reg.continuity_degraded() is True
    status = pa_deployment_status(enforce=True, env=_SINGLE, active_workers=n)
    assert status["reason"] == "MULTI_WORKER_UNSUPPORTED"


def test_rc_startup_bind_failure_degrades_process(tmp_path: Path):
    from varden.predictive_authority.registry import (
        configure_authority_registry,
        get_authority_registry,
        reset_authority_registry,
    )

    reset_authority_registry()
    bad = str(tmp_path / "no-such-dir" / "nested" / "x.db")
    # Parent missing → ContinuityStore/init_db fails on some platforms; on others
    # sqlite may create. Force fail via file-as-directory parent.
    parent = tmp_path / "file-as-dir"
    parent.write_text("not a directory")
    bad = str(parent / "x.db")
    configure_authority_registry(db_path=bad)
    reg = get_authority_registry()
    assert reg.continuity_degraded() is True
    assert reg.continuity_status()["continuity_degraded_reason"] == "CONTINUITY_STORE_BIND_FAILED"
    final, result = _eng(reg).evaluate(_shell("bind-fail"), allow_decision(), policy={})
    _assert_failsafe(final, result)
    reset_authority_registry()
    configure_authority_registry(db_path=None)


# ---------------------------------------------------------------------------
# 2. Worker coordination honesty
# ---------------------------------------------------------------------------


def test_rc_separate_dbs_do_not_claim_cross_worker_coordination(tmp_path: Path):
    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")
    reg_a = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg_b = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg_a.attach_continuity_store(ContinuityStore(db_a, worker_id="a"))
    reg_b.attach_continuity_store(ContinuityStore(db_b, worker_id="b"))
    assert reg_a.active_worker_count() == 1
    assert reg_b.active_worker_count() == 1
    # Each DB independently reports single worker — residual: no coordination.
    assert pa_deployment_status(
        enforce=True, env=_SINGLE, active_workers=reg_a.active_worker_count()
    )["reason"] == "SINGLE_WORKER_DECLARED"
    assert reg_a.continuity_status()["cross_restart_continuity_verified"] is False


def test_rc_stale_lease_expires(tmp_path: Path):
    db = str(tmp_path / "stale.db")
    a = ContinuityStore(db, worker_id="alive", lease_ttl=1.0)
    b = ContinuityStore(db, worker_id="dead", lease_ttl=1.0)
    a.touch_lease_and_count()
    b.touch_lease_and_count()
    with connect(db) as conn:
        conn.execute("UPDATE pa_worker_leases SET last_seen = ? WHERE worker_id = ?", (0.0, "dead"))
        conn.commit()
    assert a.touch_lease_and_count() == 1


def test_rc_pid_reuse_does_not_collide_worker_ids(tmp_path: Path):
    db = str(tmp_path / "pid.db")
    # Default worker_id includes uuid — two stores with same PID differ.
    a = ContinuityStore(db)
    b = ContinuityStore(db)
    assert a.worker_id != b.worker_id
    a.touch_lease_and_count()
    b.touch_lease_and_count()
    assert a.active_worker_count() >= 2


# ---------------------------------------------------------------------------
# 3. Approval integrity vs continuity
# ---------------------------------------------------------------------------


def test_rc_approval_cannot_clear_continuity_broken(tmp_path: Path):
    db = str(tmp_path / "appr.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    store.record_tombstone("t:vic", "lru")
    eng = _eng(reg)
    # Agent-controlled metadata must not restore trust.
    action = _shell("vic")
    action.metadata = {
        **(action.metadata or {}),
        "approvals": [{"approval_id": "forged", "status": "approved"}],
        "authority": {"continuity_broken": False},
        "continuity_broken": False,
    }
    final, result = eng.evaluate(action, allow_decision(), policy={})
    assert result.analysis_incomplete_reason == "SESSION_CONTINUITY_BROKEN"
    _assert_failsafe(final, result)
    state = reg.get("t:vic")
    assert state is not None
    assert state.continuity_broken is True


def test_rc_approval_token_scoped_no_graph_restore(tmp_path: Path):
    db = str(tmp_path / "tok.db")
    approvals = ApprovalStore(db, signing_secret="rc-test-secret")
    action = {
        "type": "tool_call",
        "tool": "shell",
        "args": {"command": "env"},
        "trace_id": "t1",
        "tenant_id": "tenant-a",
    }
    pending = approvals.create_pending(tenant_id="tenant-a", action=action, reason="pa")
    approved = approvals.approve(tenant_id="tenant-a", approval_id=pending["approval_id"])
    token = approved["token"]
    # Replay / second consume must fail.
    approvals.verify_and_consume(tenant_id="tenant-a", token=token, action=action)
    with pytest.raises(ValueError, match="already used|not usable"):
        approvals.verify_and_consume(tenant_id="tenant-a", token=token, action=action)
    # Cross-session / scope expansion rejected.
    expanded = {**action, "args": {"command": "env; cat /etc/passwd"}}
    pending2 = approvals.create_pending(tenant_id="tenant-a", action=action, reason="pa2")
    approved2 = approvals.approve(tenant_id="tenant-a", approval_id=pending2["approval_id"])
    with pytest.raises(ValueError, match="scope mismatch"):
        approvals.verify_and_consume(tenant_id="tenant-a", token=approved2["token"], action=expanded)
    # Cross-tenant rejected.
    with pytest.raises(ValueError, match="tenant"):
        approvals.verify_and_consume(tenant_id="tenant-b", token=approved2["token"], action=action)


def test_rc_expired_approval_rejected(tmp_path: Path):
    db = str(tmp_path / "exp.db")
    approvals = ApprovalStore(db, signing_secret="rc-test-secret")
    action = {"type": "tool_call", "tool": "shell", "args": {"command": "env"}, "tenant_id": "t"}
    pending = approvals.create_pending(tenant_id="t", action=action, reason="x", ttl_seconds=1)
    approved = approvals.approve(tenant_id="t", approval_id=pending["approval_id"])
    time.sleep(1.1)
    with pytest.raises(ValueError, match="expired"):
        approvals.verify_and_consume(tenant_id="t", token=approved["token"], action=action)


# ---------------------------------------------------------------------------
# 4. Combined enforcement integrity
# ---------------------------------------------------------------------------


def test_rc_combined_evict_and_store_failure(tmp_path: Path):
    db = str(tmp_path / "combo.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=3, idle_seconds=0)
    reg.attach_continuity_store(store)
    eng = _eng(reg)
    eng.evaluate(_cred("combo-vic"), allow_decision(), policy={})
    # Evict via capacity pressure.
    for i in range(10):
        peer = reg.get_or_create(f"t:cpeer-{i}", PredictiveAuthorityConfig(enabled=True, mode="enforce"))
        peer.history.append(
            __import__(
                "varden.predictive_authority.state", fromlist=["AuthorityTransitionRecord"]
            ).AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="n",
                added_capabilities=["x"],
                added_resources=[],
                added_sinks=[],
            )
        )
    Path(db).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(db + suffix).unlink(missing_ok=True)
    final, result = eng.evaluate(_shell("combo-vic"), allow_decision(), policy={})
    _assert_failsafe(final, result)


def test_rc_benign_workflow_with_healthy_store(tmp_path: Path):
    db = str(tmp_path / "ok.db")
    store = ContinuityStore(db)
    reg = AuthorityRegistry(max_sessions=50, idle_seconds=0)
    reg.attach_continuity_store(store)
    final, result = _eng(reg).evaluate(_shell("benign"), allow_decision(), policy={})
    assert final.action == "allow"
    assert result.analysis_incomplete_reason is None
    assert reg.continuity_status()["cross_restart_continuity_verified"] is False
