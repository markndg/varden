"""Usage reconciliation must be atomic with its completion state.

Baseline defect: ``/sdk/log`` commits ``claim_usage_report`` before
``post_record``. A failure after that claim leaves the guard event claimed
and the actual usage unrecorded. Each budget rule also commits on its own,
so a later rule failure keeps the earlier charge.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.models import Action
from varden.rules.registry import load_budget_rules
from varden.rules.token_budget import DEFAULT_MODEL_COSTS, compute_cost_usd
from varden.token_budget import TokenBudgetStore


def _rules(*windows: str, limit: float = 10.0):
    return load_budget_rules(
        {
            "budget_rules": [
                {
                    "id": f"cap-{window}",
                    "type": "token_budget",
                    "limit_usd": limit,
                    "window": window,
                    "hard_cap": True,
                }
                for window in windows
            ]
        }
    )


def _action(trace: str = "trace-atomic") -> Action:
    return Action(
        type="llm_call",
        tool="openai",
        trace_id=trace,
        workflow_id="wf-atomic",
        tenant_id="default",
        args={"kwargs": {"model": "gpt-4o", "max_tokens": 1000}},
    )


def _payload() -> dict:
    return {"kwargs": {"model": "gpt-4o", "max_tokens": 1000}}


def _store(tmp_path, ttl: float = 36 * 3600) -> tuple[TokenBudgetStore, dict]:
    box = {"now": datetime(2026, 10, 17, 12, tzinfo=timezone.utc).timestamp()}
    store = TokenBudgetStore(str(tmp_path / "varden.db"), clock=lambda: box["now"], reservation_ttl=ttl)
    return store, box


def _usage(output_tokens: int) -> dict:
    return {"usage": {"input_tokens": 0, "output_tokens": output_tokens}, "model": "gpt-4o"}


def _cost(output_tokens: int) -> float:
    return compute_cost_usd(
        model="gpt-4o",
        input_tokens=0,
        output_tokens=output_tokens,
        model_costs=DEFAULT_MODEL_COSTS,
    )


def _ledger(store: TokenBudgetStore) -> tuple[list[dict], list[dict]]:
    reservations = store.list_reservations()
    budgets = store.list_active_budgets()
    return reservations, budgets


def test_failed_reconciliation_stays_retryable_and_charges_once(tmp_path, monkeypatch):
    store, _box = _store(tmp_path)
    action = _action()
    rules = _rules("session")
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    assert store.bind_guard_event(11, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    real = TokenBudgetStore._settle
    armed = {"on": True}

    def interrupt(self, *args, **kwargs):
        if armed["on"]:
            armed["on"] = False
            raise RuntimeError("accounting interrupted")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(TokenBudgetStore, "_settle", interrupt)
    with pytest.raises(RuntimeError, match="accounting interrupted"):
        store.post_record(
            action,
            input_payload=_payload(),
            output_payload=_usage(4000),
            rules=rules,
            guard_event_id=11,
            tenant_id="default",
            principal_hash="p",
        )
    reservations, budgets = _ledger(store)
    assert reservations[0]["status"] == "reserved"
    assert float(reservations[0]["charged_usd"]) == 0.0
    assert float(budgets[0]["current_usd"]) == 0.0

    monkeypatch.setattr(TokenBudgetStore, "_settle", real)
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(4000),
        rules=rules,
        guard_event_id=11,
        tenant_id="default",
        principal_hash="p",
    ) is True
    reservations, budgets = _ledger(store)
    assert reservations[0]["status"] == "reconciled"
    assert reservations[0]["reported_usd"] == pytest.approx(_cost(4000))
    assert reservations[0]["charged_usd"] == pytest.approx(_cost(4000))
    assert float(budgets[0]["current_usd"]) == pytest.approx(_cost(4000))
    assert float(budgets[0]["reserved_usd"]) == 0.0


def test_multi_rule_failure_rolls_back_every_rule(tmp_path, monkeypatch):
    store, _box = _store(tmp_path)
    action = _action("multi")
    rules = _rules("session", "daily", limit=50.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    assert len(store.list_reservations()) == 2
    store.bind_guard_event(12, tenant_id="default", principal_hash="p", reservation_ids=[row["id"] for row in store.list_reservations()])
    real = TokenBudgetStore._settle
    calls = {"n": 0}

    def fail_second(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError("second rule failed")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(TokenBudgetStore, "_settle", fail_second)
    with pytest.raises(RuntimeError, match="second rule failed"):
        store.post_record(
            action,
            input_payload=_payload(),
            output_payload=_usage(1500),
            rules=rules,
            guard_event_id=12,
            tenant_id="default",
            principal_hash="p",
        )
    reservations, budgets = _ledger(store)
    assert [row["status"] for row in reservations] == ["reserved", "reserved"]
    assert all(float(row["charged_usd"]) == 0.0 for row in reservations)
    assert all(float(row["current_usd"]) == 0.0 for row in budgets)

    monkeypatch.setattr(TokenBudgetStore, "_settle", real)
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(1500),
        rules=rules,
        guard_event_id=12,
        tenant_id="default",
        principal_hash="p",
    ) is True
    reservations, budgets = _ledger(store)
    assert [row["status"] for row in reservations] == ["reconciled", "reconciled"]
    assert all(row["charged_usd"] == pytest.approx(_cost(1500)) for row in reservations)
    assert sum(float(row["current_usd"]) for row in budgets) == pytest.approx(_cost(1500) * 2)


def test_process_restart_after_interrupted_reconciliation(tmp_path, monkeypatch):
    path = tmp_path / "varden.db"
    box = {"now": datetime(2026, 10, 17, 12, tzinfo=timezone.utc).timestamp()}
    store = TokenBudgetStore(str(path), clock=lambda: box["now"])
    action = _action("restart")
    rules = _rules("daily", limit=50.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(
        13,
        tenant_id="default",
        principal_hash="p",
        reservation_ids=[row["id"] for row in store.list_reservations()],
    )

    def boom(self, *args, **kwargs):
        raise RuntimeError("process interrupted")

    monkeypatch.setattr(TokenBudgetStore, "_settle", boom)
    with pytest.raises(RuntimeError):
        store.post_record(
            action,
            input_payload=_payload(),
            output_payload=_usage(2500),
            rules=rules,
            guard_event_id=13,
            tenant_id="default",
            principal_hash="p",
        )
    monkeypatch.undo()
    restarted = TokenBudgetStore(str(path), clock=lambda: box["now"])
    assert restarted.list_reservations()[0]["status"] == "reserved"
    assert restarted.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(2500),
        rules=rules,
        guard_event_id=13,
        tenant_id="default",
        principal_hash="p",
    ) is True
    row = restarted.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["charged_usd"] == pytest.approx(_cost(2500))
    assert float(restarted.list_active_budgets()[0]["current_usd"]) == pytest.approx(_cost(2500))


def test_concurrent_identical_reports_charge_once(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("concurrent")
    rules = _rules("session", limit=50.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(14, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    barrier = threading.Barrier(2)
    results: list[bool] = []

    def report() -> None:
        local = TokenBudgetStore(store.db_path, clock=lambda: store._now())
        barrier.wait(timeout=5)
        results.append(
            bool(
                local.post_record(
                    action,
                    input_payload=_payload(),
                    output_payload=_usage(1200),
                    rules=rules,
                    guard_event_id=14,
                    tenant_id="default",
                    principal_hash="p",
                )
            )
        )

    threads = [threading.Thread(target=report) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(results) == [False, True]
    row = store.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["charged_usd"] == pytest.approx(_cost(1200))
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(_cost(1200))


def test_duplicate_report_after_success_does_not_change_the_ledger(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("dup")
    rules = _rules("session")
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(15, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(800),
        rules=rules,
        guard_event_id=15,
        tenant_id="default",
        principal_hash="p",
    ) is True
    before = store.list_reservations()[0]
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(800),
        rules=rules,
        guard_event_id=15,
        tenant_id="default",
        principal_hash="p",
    ) is False
    after = store.list_reservations()[0]
    assert after["status"] == "reconciled"
    assert after["charged_usd"] == pytest.approx(before["charged_usd"])
    assert after["reported_usd"] == pytest.approx(before["reported_usd"])
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(before["charged_usd"])


def test_expired_reservation_then_actual_usage_applies_the_delta(tmp_path):
    store, box = _store(tmp_path, ttl=30)
    action = _action("late")
    rules = _rules("daily", limit=50.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(
        16,
        tenant_id="default",
        principal_hash="p",
        reservation_ids=[row["id"] for row in store.list_reservations()],
    )
    estimate = float(store.list_reservations()[0]["reserved_usd"])
    box["now"] += 90
    store.expire_due()
    assert store.list_reservations()[0]["status"] == "expired_charged"
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(5000),
        rules=rules,
        guard_event_id=16,
        tenant_id="default",
        principal_hash="p",
    ) is True
    actual = _cost(5000)
    row = store.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["reported_usd"] == pytest.approx(actual)
    assert row["charged_usd"] == pytest.approx(actual)
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(actual)
    assert actual > estimate


def test_actual_usage_below_and_above_the_estimate(tmp_path):
    store, _box = _store(tmp_path)
    rules = _rules("session", limit=50.0)
    low = _action("low")
    store.pre_check(low, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(17, tenant_id="default", principal_hash="p", trace_id=low.trace_id)
    estimate = float(store.list_reservations()[0]["reserved_usd"])
    assert store.post_record(
        low,
        input_payload=_payload(),
        output_payload=_usage(100),
        rules=rules,
        guard_event_id=17,
        tenant_id="default",
        principal_hash="p",
    ) is True
    low_cost = _cost(100)
    assert low_cost < estimate
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(low_cost)
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(low_cost)

    high = _action("high")
    store.pre_check(high, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(18, tenant_id="default", principal_hash="p", trace_id=high.trace_id)
    assert store.post_record(
        high,
        input_payload=_payload(),
        output_payload=_usage(8000),
        rules=rules,
        guard_event_id=18,
        tenant_id="default",
        principal_hash="p",
    ) is True
    high_cost = _cost(8000)
    assert high_cost > estimate
    charged = [row["charged_usd"] for row in store.list_reservations()]
    assert high_cost in [pytest.approx(value) for value in charged]
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(low_cost + high_cost)


def test_client_failure_status_does_not_settle_or_block_a_later_usage_report(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("client-fail")
    rules = _rules("session")
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(19, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload={},
        rules=rules,
        guard_event_id=19,
        tenant_id="default",
        principal_hash="p",
        client_status="failed",
    ) is False
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(900),
        rules=rules,
        guard_event_id=19,
        tenant_id="default",
        principal_hash="p",
        client_status="failed",
    ) is True
    assert store.list_reservations()[0]["status"] == "reconciled"
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(900))


def test_missing_and_malformed_usage_charge_the_estimate_once(tmp_path):
    store, _box = _store(tmp_path)
    rules = _rules("session", limit=50.0)
    missing = _action("missing-usage")
    store.pre_check(missing, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(20, tenant_id="default", principal_hash="p", trace_id=missing.trace_id)
    estimate = float(store.list_reservations()[0]["reserved_usd"])
    assert store.post_record(
        missing,
        input_payload=_payload(),
        output_payload={"text": "no usage"},
        rules=rules,
        guard_event_id=20,
        tenant_id="default",
        principal_hash="p",
    ) is True
    row = store.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["reported_usd"] is None
    assert row["charged_usd"] == pytest.approx(estimate)

    malformed = _action("malformed-usage")
    store.pre_check(malformed, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(21, tenant_id="default", principal_hash="p", trace_id=malformed.trace_id)
    malformed_estimate = float(store.list_reservations()[-1]["reserved_usd"])
    assert store.post_record(
        malformed,
        input_payload=_payload(),
        output_payload={"usage": {"input_tokens": "many", "output_tokens": "lots"}, "model": "gpt-4o"},
        rules=rules,
        guard_event_id=21,
        tenant_id="default",
        principal_hash="p",
    ) is True
    bad = store.list_reservations()[-1]
    assert bad["status"] == "reconciled"
    assert bad["reported_usd"] is None
    assert bad["charged_usd"] == pytest.approx(malformed_estimate)
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(estimate + malformed_estimate)


def test_sqlite_lock_is_an_explicit_failure_and_remains_retryable(tmp_path, monkeypatch):
    store, _box = _store(tmp_path)
    action = _action("locked")
    rules = _rules("session")
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(22, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    import varden.token_budget as budget_mod

    real_connect = budget_mod.connect

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(budget_mod, "connect", locked)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        store.post_record(
            action,
            input_payload=_payload(),
            output_payload=_usage(700),
            rules=rules,
            guard_event_id=22,
            tenant_id="default",
            principal_hash="p",
        )
    monkeypatch.setattr(budget_mod, "connect", real_connect)
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(700),
        rules=rules,
        guard_event_id=22,
        tenant_id="default",
        principal_hash="p",
    ) is True
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(700))


def test_sdk_log_claim_failure_does_not_stick(tmp_path, monkeypatch):
    """The HTTP path must not consume the usage claim before accounting commits."""
    policy = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "budget_rules": [
            {
                "id": "cap-session",
                "type": "token_budget",
                "limit_usd": 10.0,
                "window": "session",
                "hard_cap": True,
            }
        ],
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(__import__("json").dumps(policy), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=1000,
    )
    real = TokenBudgetStore._settle
    armed = {"on": True}

    def interrupt(self, *args, **kwargs):
        if armed["on"]:
            armed["on"] = False
            raise RuntimeError("claim then crash")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(TokenBudgetStore, "_settle", interrupt)
    with TestClient(create_app(cfg)) as client:
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        action = {
            "type": "llm_call",
            "tool": "openai",
            "trace_id": "http-trace",
            "workflow_id": "http-wf",
            "args": {"kwargs": {"model": "gpt-4o", "max_tokens": 1000}},
        }
        guarded = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": _payload()})
        assert guarded.status_code == 200
        event_id = guarded.json()["event_id"]
        body = {
            "guard_event_id": event_id,
            "action": guarded.json()["action"],
            "decision": {"action": "allow", "reason": "forged"},
            "status": "allowed",
            "output_payload": _usage(3000),
        }
        with pytest.raises(RuntimeError, match="claim then crash"):
            client.post("/sdk/log", headers=headers, json=body)
        monkeypatch.setattr(TokenBudgetStore, "_settle", real)
        logged = client.post("/sdk/log", headers=headers, json=body)
        assert logged.status_code == 200
        assert logged.json()["usage_accounted"] is True
    store = TokenBudgetStore(cfg.db_path)
    rows = [row for row in store.list_reservations() if row["guard_event_id"] == event_id]
    assert len(rows) == 1
    assert rows[0]["status"] == "reconciled"
    assert rows[0]["charged_usd"] == pytest.approx(_cost(3000))
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(_cost(3000))
