"""P0-6: budget reservations must outlive the window counter.

Baseline defect: ``_reset_row_if_due`` set ``reserved_usd = 0`` when a daily
or monthly window rolled. An agent that was allowed under a reservation and
never reported usage lost that debt at the reset.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from varden.exceptions import PolicyViolation
from varden.models import Action
from varden.rules.registry import load_budget_rules
from varden.token_budget import TokenBudgetStore


def _rules(window: str, limit: float = 1.0):
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
            ]
        }
    )


def _action(trace: str = "trace-budget") -> Action:
    return Action(
        type="llm_call",
        tool="openai",
        trace_id=trace,
        workflow_id=trace,
        tenant_id="default",
        args={"kwargs": {"model": "gpt-4o", "max_tokens": 1000}},
    )


def _payload() -> dict:
    return {"kwargs": {"model": "gpt-4o", "max_tokens": 1000}}


def _clock(start: datetime):
    box = {"now": start.timestamp()}
    return box, lambda: box["now"]


def _store(tmp_path, when: datetime, ttl: float = 3 * 24 * 3600) -> tuple[TokenBudgetStore, dict]:
    box, clock = _clock(when)
    store = TokenBudgetStore(str(tmp_path / "varden.db"), clock=clock, reservation_ttl=ttl)
    return store, box


def test_daily_reset_discards_unreported_reservation_on_the_baseline(tmp_path):
    """The live counter is allowed to open a fresh window. The debt is not."""
    store, box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    store.pre_check(_action(), _payload(), _rules("daily", 10.0), tenant_id="default", principal_hash="principal-a")
    held = store.list_reservations()
    assert held and held[0]["status"] == "reserved"
    reserved = held[0]["reserved_usd"]
    window_id = held[0]["window_id"]
    box["now"] = datetime(2026, 10, 18, 1, tzinfo=timezone.utc).timestamp()
    store.list_active_budgets()
    still = store.list_reservations()
    assert len(still) == 1
    assert still[0]["status"] == "reserved"
    assert still[0]["window_id"] == window_id
    assert still[0]["reserved_usd"] == pytest.approx(reserved)
    live = store.list_active_budgets()
    assert live[0]["window_id"] != window_id
    assert float(live[0]["reserved_usd"]) == 0.0


def test_monthly_reset_keeps_the_original_reservation(tmp_path):
    store, box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc), ttl=40 * 24 * 3600)
    store.pre_check(_action("month-trace"), _payload(), _rules("monthly", 10.0), tenant_id="default", principal_hash="p")
    original = store.list_reservations()[0]["window_id"]
    box["now"] = datetime(2026, 11, 2, 1, tzinfo=timezone.utc).timestamp()
    store.list_active_budgets()
    row = store.list_reservations()[0]
    assert row["status"] == "reserved"
    assert row["window_id"] == original
    assert original.startswith("monthly:2026-10")


def test_expired_reservation_is_charged_to_its_window(tmp_path):
    store, box = _store(
        tmp_path,
        datetime(2026, 10, 17, 12, tzinfo=timezone.utc),
        ttl=60,
    )
    store.pre_check(_action(), _payload(), _rules("daily", 10.0), tenant_id="default", principal_hash="p")
    reserved = store.list_reservations()[0]["reserved_usd"]
    box["now"] += 120
    store.expire_due()
    row = store.list_reservations()[0]
    assert row["status"] == "expired_charged"
    assert row["charged_usd"] == pytest.approx(reserved)
    assert store.historical_charge(row["policy_id"], row["window_id"]) == pytest.approx(0.0)
    live = store.list_active_budgets()[0]
    assert float(live["current_usd"]) == pytest.approx(reserved)


def test_late_report_adjusts_the_charged_estimate_once(tmp_path):
    store, box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc), ttl=60)
    action = _action()
    rules = _rules("daily", 50.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    event = store.bind_guard_event(1, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    assert event is True
    reserved = store.list_reservations()[0]["reserved_usd"]
    box["now"] += 120
    store.expire_due()
    usage_cost_payload = {"usage": {"input_tokens": 0, "output_tokens": 3000}, "model": "gpt-4o"}
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=usage_cost_payload,
        rules=rules,
        guard_event_id=1,
        tenant_id="default",
        principal_hash="p",
    ).usage_accounted is True
    charged = float(store.list_active_budgets()[0]["current_usd"])
    assert charged == pytest.approx(3000 * 10.0 / 1_000_000)
    assert charged != pytest.approx(reserved)
    again = store.post_record(
        action,
        input_payload=_payload(),
        output_payload=usage_cost_payload,
        rules=rules,
        guard_event_id=1,
        tenant_id="default",
        principal_hash="p",
    )
    assert again.usage_accounted is False
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(charged)


def test_duplicate_reports_do_not_double_charge(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("dup")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(7, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    usage = {"usage": {"input_tokens": 1000, "output_tokens": 1000}, "model": "gpt-4o"}
    assert store.post_record(action, input_payload=_payload(), output_payload=usage, rules=rules, guard_event_id=7, tenant_id="default", principal_hash="p")
    first = float(store.list_active_budgets()[0]["current_usd"])
    assert store.post_record(action, input_payload=_payload(), output_payload=usage, rules=rules, guard_event_id=7, tenant_id="default", principal_hash="p").usage_accounted is False
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(first)


def test_concurrent_reservations_cannot_exceed_the_hard_cap(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    rules = _rules("session", 0.015)
    barrier = threading.Barrier(2)
    results: list[str] = []

    def attempt(name: str) -> None:
        local = TokenBudgetStore(store.db_path, clock=lambda: _box_now(), reservation_ttl=3600)
        barrier.wait(timeout=5)
        try:
            local.pre_check(_action("shared-cap"), _payload(), rules, tenant_id="default", principal_hash="shared")
            results.append("ok")
        except PolicyViolation:
            results.append("blocked")

    # Both stores share the clock value captured above.
    now = store._now()

    def _box_now() -> float:
        return now

    threads = [threading.Thread(target=attempt, args=(f"t{i}",)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(results) == ["blocked", "ok"]
    assert len(store.list_reservations()) == 1


def test_restart_preserves_outstanding_reservations(tmp_path):
    path = tmp_path / "varden.db"
    when = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    box, clock = _clock(when)
    first = TokenBudgetStore(str(path), clock=clock, reservation_ttl=3600)
    first.pre_check(_action("restart"), _payload(), _rules("daily", 0.015), tenant_id="default", principal_hash="p")
    second = TokenBudgetStore(str(path), clock=clock, reservation_ttl=3600)
    with pytest.raises(PolicyViolation):
        second.pre_check(_action("restart"), _payload(), _rules("daily", 0.015), tenant_id="default", principal_hash="p")
    assert second.list_reservations()[0]["status"] == "reserved"


def test_forged_blocked_status_cannot_cancel_a_reservation(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("blocked-claim")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    before = store.list_reservations()[0]["reserved_usd"]
    store.post_record(
        action,
        input_payload=_payload(),
        output_payload={},
        rules=rules,
        tenant_id="default",
        principal_hash="p",
        client_status="blocked",
    )
    row = store.list_reservations()[0]
    assert row["status"] == "reserved"
    assert row["reserved_usd"] == pytest.approx(before)
    assert float(store.list_active_budgets()[0]["reserved_usd"]) == pytest.approx(before)


def test_forged_failure_cannot_release_budget(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("failed-claim")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.post_record(
        action,
        input_payload=_payload(),
        output_payload={"error": "connection reset"},
        rules=rules,
        tenant_id="default",
        principal_hash="p",
        client_status="failed",
    )
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0


def test_unknown_outcome_charges_the_estimate(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("unknown-outcome")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    reserved = store.list_reservations()[0]["reserved_usd"]
    store.post_record(
        action,
        input_payload=_payload(),
        output_payload={"text": "no usage block"},
        rules=rules,
        tenant_id="default",
        principal_hash="p",
        client_status="unknown",
    )
    row = store.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["charged_usd"] == pytest.approx(reserved)
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(reserved)
    assert float(store.list_active_budgets()[0]["reserved_usd"]) == 0.0


def test_reconciliation_updates_the_original_window_not_the_new_one(tmp_path):
    store, box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("historical")
    rules = _rules("daily", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(4, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    original = store.list_reservations()[0]["window_id"]
    reserved = store.list_reservations()[0]["reserved_usd"]
    box["now"] = datetime(2026, 10, 18, 3, tzinfo=timezone.utc).timestamp()
    store.list_active_budgets()
    usage = {"usage": {"input_tokens": 0, "output_tokens": 2000}, "model": "gpt-4o"}
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=usage,
        rules=rules,
        guard_event_id=4,
        tenant_id="default",
        principal_hash="p",
    )
    reported = 2000 * 10.0 / 1_000_000
    assert store.historical_charge(f"cap-daily", original) == pytest.approx(reported)
    live = store.list_active_budgets()[0]
    assert float(live["current_usd"]) == 0.0
    assert live["window_id"] != original
    assert store.list_reservations()[0]["status"] == "reconciled"
    assert reserved > 0


def test_new_window_keeps_its_own_allowance(tmp_path):
    store, box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    rules = _rules("daily", 0.015)
    store.pre_check(_action("same-workflow"), _payload(), rules, tenant_id="default", principal_hash="p")
    box["now"] = datetime(2026, 10, 18, 2, tzinfo=timezone.utc).timestamp()
    store.pre_check(_action("same-workflow"), _payload(), rules, tenant_id="default", principal_hash="p")
    live = store.list_active_budgets()[0]
    assert float(live["reserved_usd"]) == pytest.approx(store.list_reservations()[-1]["reserved_usd"])
    assert live["window_id"].endswith("2026-10-18")


def test_cleanup_does_not_erase_unresolved_liability(tmp_path):
    store, box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc), ttl=30)
    action = _action("cleanup")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.post_record(
        action,
        input_payload=_payload(),
        output_payload={"usage": {"input_tokens": 10, "output_tokens": 10}, "model": "gpt-4o"},
        rules=rules,
        tenant_id="default",
        principal_hash="p",
    )
    store.pre_check(_action("still-open"), _payload(), rules, tenant_id="default", principal_hash="p")
    box["now"] += 120 * 24 * 3600
    removed = store.cleanup_resolved()
    assert removed >= 1
    remaining = store.list_reservations()
    assert len(remaining) == 1
    assert remaining[0]["status"] == "reserved"
    assert remaining[0]["trace_id"] == "still-open"


def test_tenant_and_principal_boundaries(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("scoped")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="tenant-a", principal_hash="principal-a")
    store.bind_guard_event(9, tenant_id="tenant-a", principal_hash="principal-a", trace_id=action.trace_id)
    usage = {"usage": {"input_tokens": 100, "output_tokens": 100}, "model": "gpt-4o"}
    assert store.post_record(
        action, input_payload=_payload(), output_payload=usage, rules=rules,
        guard_event_id=9, tenant_id="tenant-b", principal_hash="principal-a",
    ).usage_accounted is False
    assert store.post_record(
        action, input_payload=_payload(), output_payload=usage, rules=rules,
        guard_event_id=9, tenant_id="tenant-a", principal_hash="principal-b",
    ).usage_accounted is False
    assert store.list_reservations()[0]["status"] == "reserved"
    assert store.post_record(
        action, input_payload=_payload(), output_payload=usage, rules=rules,
        guard_event_id=9, tenant_id="tenant-a", principal_hash="principal-a",
    ).usage_accounted is True


def test_foreign_guard_event_is_rejected(tmp_path):
    store, _box = _store(tmp_path, datetime(2026, 10, 17, 12, tzinfo=timezone.utc))
    action = _action("foreign")
    rules = _rules("session", 10.0)
    store.pre_check(action, _payload(), rules, tenant_id="default", principal_hash="p")
    store.bind_guard_event(3, tenant_id="default", principal_hash="p", trace_id=action.trace_id)
    usage = {"usage": {"input_tokens": 100, "output_tokens": 100}, "model": "gpt-4o"}
    assert store.post_record(
        action, input_payload=_payload(), output_payload=usage, rules=rules,
        guard_event_id=99, tenant_id="default", principal_hash="p",
    ).usage_accounted is False
    assert store.list_reservations()[0]["status"] == "reserved"
    with sqlite3.connect(store.db_path) as conn:
        charged = conn.execute("SELECT COALESCE(SUM(current_usd), 0) FROM token_budgets").fetchone()[0]
    assert float(charged) == 0.0
