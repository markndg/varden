"""Hard budgets must use authenticated scope, not client correlation ids.

Baseline defects:
- A session or calendar rule returns no decision when trace or workflow id
  is missing, so the call is allowed with no hold.
- The live counter is keyed by policy and those client ids. Two tenants, or
  a principal rotating a trace id, share or reset the same cap.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from varden.db import init_db
from varden.exceptions import PolicyViolation
from varden.models import Action, Decision
from varden.rules.registry import load_budget_rules
from varden.token_budget import TokenBudgetStore


def _rules(window: str, limit: float, *, hard_cap: bool = True):
    return load_budget_rules(
        {
            "budget_rules": [
                {
                    "id": f"cap-{window}",
                    "type": "token_budget",
                    "limit_usd": limit,
                    "window": window,
                    "hard_cap": hard_cap,
                }
            ]
        }
    )


def _action(trace: str | None, workflow: str | None = None, tenant: str = "default") -> Action:
    return Action(
        type="llm_call",
        tool="openai",
        trace_id=trace,
        workflow_id=workflow if workflow is not None else trace,
        tenant_id=tenant,
        args={"kwargs": {"model": "gpt-4o", "max_tokens": 1000}},
    )


def _payload() -> dict:
    return {"kwargs": {"model": "gpt-4o", "max_tokens": 1000}}


def _store(tmp_path, name: str = "varden.db") -> TokenBudgetStore:
    when = datetime(2026, 10, 17, 12, tzinfo=timezone.utc).timestamp()
    return TokenBudgetStore(str(tmp_path / name), clock=lambda: when)


def _budget_rows(store: TokenBudgetStore) -> list[dict]:
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM token_budgets ORDER BY id")]


def test_missing_correlation_ids_still_consume_the_authenticated_budget(tmp_path):
    """Omitting trace and workflow must not skip a hard cap."""
    store = _store(tmp_path)
    bare = _action(None, None)
    store.pre_check(bare, _payload(), _rules("session", 0.015), tenant_id="default", principal_hash="p")
    with pytest.raises(PolicyViolation):
        store.pre_check(bare, _payload(), _rules("session", 0.015), tenant_id="default", principal_hash="p")
    assert len(store.list_reservations()) == 1

    daily = _store(tmp_path, "daily.db")
    daily.pre_check(bare, _payload(), _rules("daily", 0.015), tenant_id="default", principal_hash="p")
    with pytest.raises(PolicyViolation):
        daily.pre_check(_action(None, None), _payload(), _rules("daily", 0.015), tenant_id="default", principal_hash="q")
    assert len(daily.list_reservations()) == 1

    monthly = _store(tmp_path, "monthly.db")
    with pytest.raises(PolicyViolation, match="scope"):
        monthly.pre_check(bare, _payload(), _rules("monthly", 10.0), tenant_id="", principal_hash="")
    with pytest.raises(PolicyViolation, match="scope"):
        monthly.pre_check(_action("has-trace", "has-wf"), _payload(), _rules("session", 10.0), tenant_id="default", principal_hash="")
    assert monthly.list_reservations() == []


def test_soft_cap_missing_scope_is_a_visible_unenforced_warning(tmp_path):
    store = _store(tmp_path)
    decision = store.pre_check(
        _action(None, None),
        _payload(),
        _rules("session", 10.0, hard_cap=False),
        tenant_id="",
        principal_hash="",
    )
    assert isinstance(decision, Decision)
    assert decision.action == "warn"
    assert decision.matched_rule.get("enforced") is False
    assert store.list_reservations() == []


def test_rotating_client_ids_does_not_reset_a_session_or_daily_cap(tmp_path):
    store = _store(tmp_path)
    rules = _rules("session", 0.015)
    store.pre_check(_action("trace-a", "wf-a"), _payload(), rules, tenant_id="default", principal_hash="p")
    with pytest.raises(PolicyViolation):
        store.pre_check(_action("trace-b", "wf-b"), _payload(), rules, tenant_id="default", principal_hash="p")
    assert len(_budget_rows(store)) == 1
    assert len(store.list_reservations()) == 1

    daily = _store(tmp_path, "daily-rotate.db")
    daily_rules = _rules("daily", 0.015)
    daily.pre_check(_action("t1", "workflow-1"), _payload(), daily_rules, tenant_id="default", principal_hash="p")
    with pytest.raises(PolicyViolation):
        daily.pre_check(_action("t2", "workflow-2"), _payload(), daily_rules, tenant_id="default", principal_hash="other")
    assert len(_budget_rows(daily)) == 1


def test_two_tenants_keep_independent_counters_for_the_same_ids(tmp_path):
    store = _store(tmp_path)
    rules = _rules("session", 0.015)
    store.pre_check(_action("shared", "shared", "tenant-a"), _payload(), rules, tenant_id="tenant-a", principal_hash="p")
    store.pre_check(_action("shared", "shared", "tenant-b"), _payload(), rules, tenant_id="tenant-b", principal_hash="p")
    rows = _budget_rows(store)
    assert len(rows) == 2
    assert {row["tenant_id"] for row in rows} == {"tenant-a", "tenant-b"}
    assert len(store.list_reservations()) == 2
    listed = store.list_active_budgets(tenant_id="tenant-a")
    assert len(listed) == 1
    assert listed[0]["tenant_id"] == "tenant-a"


def test_session_scope_is_per_principal_and_daily_scope_is_per_tenant(tmp_path):
    session = _store(tmp_path)
    rules = _rules("session", 0.015)
    session.pre_check(_action("same"), _payload(), rules, tenant_id="default", principal_hash="alice")
    session.pre_check(_action("same"), _payload(), rules, tenant_id="default", principal_hash="bob")
    assert len(session.list_reservations()) == 2
    assert len(_budget_rows(session)) == 2

    daily = _store(tmp_path, "daily-shared.db")
    daily_rules = _rules("daily", 0.015)
    daily.pre_check(_action("same"), _payload(), daily_rules, tenant_id="default", principal_hash="alice")
    with pytest.raises(PolicyViolation):
        daily.pre_check(_action("other-trace", "other-wf"), _payload(), daily_rules, tenant_id="default", principal_hash="bob")
    assert len(_budget_rows(daily)) == 1
    assert _budget_rows(daily)[0]["tenant_id"] == "default"


def test_session_restart_and_new_trace_keep_the_principal_cap(tmp_path):
    path = tmp_path / "varden.db"
    when = datetime(2026, 10, 17, 12, tzinfo=timezone.utc).timestamp()
    first = TokenBudgetStore(str(path), clock=lambda: when)
    rules = _rules("session", 0.015)
    first.pre_check(_action("before-restart"), _payload(), rules, tenant_id="default", principal_hash="p")
    second = TokenBudgetStore(str(path), clock=lambda: when)
    with pytest.raises(PolicyViolation):
        second.pre_check(_action("after-restart"), _payload(), rules, tenant_id="default", principal_hash="p")
    assert len(second.list_reservations()) == 1


def test_cross_tenant_reconcile_does_not_move_the_other_ledger(tmp_path):
    store = _store(tmp_path)
    rules = _rules("daily", 50.0)
    action = _action("shared", "shared", "tenant-a")
    store.pre_check(action, _payload(), rules, tenant_id="tenant-a", principal_hash="pa")
    store.bind_guard_event(30, tenant_id="tenant-a", principal_hash="pa", trace_id="shared")
    usage = {"usage": {"input_tokens": 0, "output_tokens": 2000}, "model": "gpt-4o"}
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=usage,
        rules=rules,
        guard_event_id=30,
        tenant_id="tenant-b",
        principal_hash="pb",
    ).usage_accounted is False
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets(tenant_id="tenant-a")[0]["current_usd"]) == 0.0
    assert store.post_record(
        action,
        input_payload=_payload(),
        output_payload=usage,
        rules=rules,
        guard_event_id=30,
        tenant_id="tenant-a",
        principal_hash="pa",
    ).usage_accounted is True
    assert store.list_active_budgets(tenant_id="tenant-b") == []
    own = store.list_active_budgets(tenant_id="tenant-a")
    assert float(own[0]["current_usd"]) > 0


def test_legacy_unscoped_budget_row_is_not_assigned_to_a_tenant(tmp_path):
    path = tmp_path / "legacy.db"
    when = datetime(2026, 10, 17, tzinfo=timezone.utc).timestamp()
    TokenBudgetStore(str(path), clock=lambda: when)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM token_budgets")
        conn.execute(
            """
            INSERT INTO token_budgets(
              policy_id, trace_id, workflow_id, window, limit_usd, current_usd, reserved_usd, window_id
            ) VALUES ('cap-session', 'shared', NULL, 'session', 10, 4.5, 0, 'session:shared')
            """
        )
    store = TokenBudgetStore(str(path), clock=lambda: when)
    store.pre_check(_action("shared"), _payload(), _rules("session", 10.0), tenant_id="tenant-a", principal_hash="p")
    rows = _budget_rows(store)
    legacy = [row for row in rows if row.get("trace_id") == "shared"]
    assert len(legacy) == 1
    assert legacy[0].get("tenant_id") in (None, "")
    assert float(legacy[0]["current_usd"]) == pytest.approx(4.5)
    assert float(legacy[0]["reserved_usd"]) == 0.0
    owned = [row for row in rows if row.get("tenant_id") == "tenant-a"]
    assert len(owned) == 1
    assert float(owned[0]["reserved_usd"]) > 0


def test_migration_14_tolerates_a_database_without_token_budgets(tmp_path):
    path = tmp_path / "ancient.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
    for version in range(1, 8):
        conn.execute("INSERT INTO schema_migrations(version) VALUES (?)", (version,))
    conn.commit()
    conn.close()
    init_db(str(path))
    with sqlite3.connect(path) as conn:
        versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
    assert 14 in versions
