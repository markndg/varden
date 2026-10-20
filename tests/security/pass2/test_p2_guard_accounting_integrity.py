"""A verified guard event is not, by itself, verified budget accounting.

Guard-time evidence says which rules reserved a hold. Reconciliation follows
that evidence. A missing reservation is an integrity failure. An explicit
unbudgeted decision stays unbudgeted if a rule appears later. An old event
with no evidence is unknown, not a successful charge.
"""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.db import init_db
from varden.models import Action
from varden.rules.registry import load_budget_rules
from varden.rules.token_budget import DEFAULT_MODEL_COSTS, compute_cost_usd
from varden.token_budget import (
    ACCOUNTING_ALREADY,
    ACCOUNTING_INTEGRITY,
    ACCOUNTING_LEGACY,
    ACCOUNTING_RECONCILED,
    ACCOUNTING_UNBUDGETED,
    ACCOUNTING_UNVERIFIED,
    TokenBudgetStore,
    budget_evidence_document,
)
from varden_sdk.sdk import VardenClient


def _rules(*windows: str, limit: float = 10.0, enabled: bool = True, output_rate: float | None = None):
    costs = None
    if output_rate is not None:
        costs = {"gpt-4o": {"input": 2.5, "output": output_rate}}
    document = {
        "budget_rules": [
            {
                "id": f"cap-{window}",
                "type": "token_budget",
                "limit_usd": limit,
                "window": window,
                "hard_cap": True,
                "enabled": enabled,
                **({"model_costs": costs} if costs else {}),
            }
            for window in windows
        ]
    }
    return load_budget_rules(document)


def _action(trace: str = "trace-evidence") -> Action:
    return Action(
        type="llm_call",
        tool="openai",
        trace_id=trace,
        workflow_id="wf-evidence",
        tenant_id="default",
        args={"kwargs": {"model": "gpt-4o", "max_tokens": 1000}},
    )


def _payload() -> dict:
    return {"kwargs": {"model": "gpt-4o", "max_tokens": 1000}}


def _usage(output_tokens: int) -> dict:
    return {"usage": {"input_tokens": 0, "output_tokens": output_tokens}, "model": "gpt-4o"}


def _cost(output_tokens: int, output_rate: float = 10.0) -> float:
    costs = copy.deepcopy(DEFAULT_MODEL_COSTS)
    costs["gpt-4o"] = {"input": 2.5, "output": output_rate}
    return compute_cost_usd(model="gpt-4o", input_tokens=0, output_tokens=output_tokens, model_costs=costs)


def _store(tmp_path, ttl: float = 36 * 3600) -> tuple[TokenBudgetStore, dict]:
    box = {"now": datetime(2026, 10, 17, 12, tzinfo=timezone.utc).timestamp()}
    store = TokenBudgetStore(str(tmp_path / "varden.db"), clock=lambda: box["now"], reservation_ttl=ttl)
    return store, box


def _hold(store: TokenBudgetStore, action: Action, rules, event_id: int, *, bind: bool = True, tenant: str = "default", principal: str = "p"):
    entries: list[dict] = []
    ids: list[int] = []
    store.pre_check(
        action,
        _payload(),
        rules,
        tenant_id=tenant,
        principal_hash=principal,
        reservation_ids=ids,
        evidence=entries,
    )
    if bind:
        store.bind_guard_event(
            event_id,
            tenant_id=tenant,
            principal_hash=principal,
            reservation_ids=ids,
        )
        bound = {row["id"] for row in store.list_reservations() if row["guard_event_id"] == event_id}
        assert bound == set(ids)
    return budget_evidence_document(entries)


def _post(store, action, rules, event_id, evidence, **kwargs):
    return store.post_record(
        action,
        input_payload=_payload(),
        output_payload=kwargs.pop("output", _usage(1000)),
        rules=rules,
        guard_event_id=event_id,
        tenant_id=kwargs.pop("tenant_id", "default"),
        principal_hash=kwargs.pop("principal_hash", "p"),
        guard_evidence=evidence,
        **kwargs,
    )


def _policy(rules: list[dict] | None = None) -> dict:
    return {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "allow_vacuous_policy": True,
        "budget_rules": rules or [],
    }


def _http(tmp_path, rules: list[dict] | None = None):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(_policy(rules)), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=1000,
    )
    return TestClient(create_app(cfg)), cfg


def _guard_and_log(client: TestClient, output_tokens: int = 1000):
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    headers = {"x-api-key": key}
    action = {
        "type": "llm_call",
        "tool": "openai",
        "trace_id": "http-evidence",
        "workflow_id": "http-wf",
        "args": {"kwargs": {"model": "gpt-4o", "max_tokens": 1000}},
    }
    guarded = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": _payload()})
    assert guarded.status_code == 200, guarded.text
    body = {
        "guard_event_id": guarded.json()["event_id"],
        "action": guarded.json()["action"],
        "status": "allowed",
        "output_payload": _usage(output_tokens),
    }
    logged = client.post("/sdk/log", headers=headers, json=body)
    return headers, guarded, logged


def test_normal_guard_reserves_and_reconciles_from_its_own_evidence(tmp_path):
    store, _box = _store(tmp_path)
    action = _action()
    rules = _rules("session")
    evidence = _hold(store, action, rules, 1)
    assert evidence["disposition"] == "evaluated"
    assert evidence["rules"][0]["disposition"] == "reserved"
    result = _post(store, action, [], 1, evidence)
    assert result.status == ACCOUNTING_RECONCILED
    assert result.usage_accounted is True
    row = store.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["charged_usd"] == pytest.approx(_cost(1000))
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(_cost(1000))


def test_http_guard_records_evidence_and_log_reports_reconciled(tmp_path):
    client, _cfg = _http(
        tmp_path,
        [{"id": "cap-session", "type": "token_budget", "limit_usd": 10.0, "window": "session", "hard_cap": True}],
    )
    with client:
        headers, guarded, logged = _guard_and_log(client)
        assert logged.status_code == 200, logged.text
        body = logged.json()
        assert body["logged"] is True
        assert body["evidence_class"] == "server_decision"
        assert body["usage_accounted"] is True
        assert body["accounting_status"] == "reconciled"
        event = client.get(f"/events/{guarded.json()['event_id']}", headers=headers).json()["event"]
        evidence = event["action"]["metadata"]["budget_evidence"]
        assert evidence["disposition"] == "evaluated"
        assert evidence["rules"][0]["reservation_id"] is not None
        assert "api_key" not in json.dumps(evidence)


def test_guard_with_no_applicable_rule_is_legitimately_unbudgeted(tmp_path):
    client, _cfg = _http(tmp_path, [])
    with client:
        headers, guarded, logged = _guard_and_log(client)
        assert logged.status_code == 200
        assert logged.json()["usage_accounted"] is False
        assert logged.json()["accounting_status"] == "legitimately_unbudgeted"
        event = client.get(f"/events/{guarded.json()['event_id']}", headers=headers).json()["event"]
        assert event["action"]["metadata"]["budget_evidence"]["disposition"] == "unbudgeted"
        assert event["decision"]["action"] == "allow"


def test_rule_added_after_an_unbudgeted_guard_is_not_retroactive(tmp_path):
    store, _box = _store(tmp_path)
    evidence = budget_evidence_document([])
    assert evidence["disposition"] == "unbudgeted"
    result = _post(store, _action(), _rules("session", limit=0.001), 3, evidence)
    assert result.status == ACCOUNTING_UNBUDGETED
    assert result.usage_accounted is False
    assert store.list_reservations() == []
    assert store.list_active_budgets() == []


def test_deleted_rule_still_reconciles_the_original_reservation(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("deleted")
    evidence = _hold(store, action, _rules("daily"), 4)
    result = _post(store, action, [], 4, evidence)
    assert result.status == ACCOUNTING_RECONCILED
    assert store.list_reservations()[0]["status"] == "reconciled"
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000))


def test_disabled_rule_still_reconciles_the_original_reservation(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("disabled")
    evidence = _hold(store, action, _rules("session"), 5)
    result = _post(store, action, _rules("session", enabled=False), 5, evidence)
    assert result.status == ACCOUNTING_RECONCILED
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000))


def test_cap_change_does_not_rewrite_the_guard_time_obligation(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("cap")
    evidence = _hold(store, action, _rules("session", limit=10.0), 6)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE token_budgets SET limit_usd = 99")
    result = _post(store, action, _rules("session", limit=0.001), 6, evidence)
    assert result.status == ACCOUNTING_RECONCILED
    assert float(store.list_active_budgets()[0]["limit_usd"]) == pytest.approx(99)
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(_cost(1000))


def test_price_change_keeps_the_guard_time_rate(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("price")
    evidence = _hold(store, action, _rules("session"), 7)
    priced = copy.deepcopy(evidence)
    priced["rules"][0]["rule_snapshot"]["model_costs"]["gpt-4o"]["output"] = 4.0
    result = _post(store, action, _rules("session", output_rate=99.0), 7, priced, output=_usage(1000))
    assert result.status == ACCOUNTING_RECONCILED
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000, output_rate=4.0))
    assert store.list_reservations()[0]["charged_usd"] != pytest.approx(_cost(1000, output_rate=99.0))


def test_expected_reservation_removed_is_an_integrity_failure(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("missing")
    evidence = _hold(store, action, _rules("session"), 8)
    reservation_id = evidence["rules"][0]["reservation_id"]
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("DELETE FROM token_budget_reservations WHERE id = ?", (reservation_id,))
    result = _post(store, action, _rules("session"), 8, evidence)
    assert result.status == ACCOUNTING_INTEGRITY
    assert result.usage_accounted is False
    findings = store.list_accounting_findings(8)
    assert len(findings) == 1
    assert findings[0]["status"] == ACCOUNTING_INTEGRITY
    detail = json.loads(findings[0]["detail_json"])
    assert detail["reservation_id"] == reservation_id
    assert "key" not in detail
    again = _post(store, action, _rules("session"), 8, evidence)
    assert again.finding_id == result.finding_id
    assert len(store.list_accounting_findings(8)) == 1
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0


def test_reservation_bound_to_another_guard_is_not_reused(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("other-event")
    evidence = _hold(store, action, _rules("session"), 9)
    result = _post(store, action, _rules("session"), 90, evidence)
    assert result.status == ACCOUNTING_INTEGRITY
    row = store.list_reservations()[0]
    assert row["guard_event_id"] == 9
    assert row["status"] == "reserved"
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0


def test_other_tenant_and_principal_do_not_settle_the_hold(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("scope")
    evidence = _hold(store, action, _rules("session"), 10, tenant="tenant-a", principal="principal-a")
    other_tenant = _post(store, action, _rules("session"), 10, evidence, tenant_id="tenant-b", principal_hash="principal-a")
    other_principal = _post(store, action, _rules("session"), 10, evidence, tenant_id="tenant-a", principal_hash="principal-b")
    assert other_tenant.status == ACCOUNTING_UNVERIFIED
    assert other_principal.status == ACCOUNTING_UNVERIFIED
    assert store.list_accounting_findings(10) == []
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets(tenant_id="tenant-a")[0]["current_usd"]) == 0.0


def test_forged_guard_event_is_unverified_and_not_accounted(tmp_path):
    client, _cfg = _http(
        tmp_path,
        [{"id": "cap-session", "type": "token_budget", "limit_usd": 10.0, "window": "session", "hard_cap": True}],
    )
    with client:
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        logged = client.post(
            "/sdk/log",
            headers=headers,
            json={
                "guard_event_id": 999999,
                "action": {"type": "llm_call", "tool": "openai", "args": {"kwargs": {"model": "gpt-4o"}}},
                "decision": {"action": "allow"},
                "status": "allowed",
                "output_payload": _usage(1000),
            },
        )
        assert logged.status_code == 200
        body = logged.json()
        assert body["evidence_class"] == "unverified_observation"
        assert body["usage_accounted"] is False
        assert body["accounting_status"] == "unverified_guard"
        detail = client.get(f"/events/{body['event_id']}", headers=headers).json()["event"]
        assert detail["decision"]["action"] == "unverified_observation"


def test_duplicate_report_does_not_charge_again(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("dup")
    rules = _rules("session")
    evidence = _hold(store, action, rules, 12)
    first = _post(store, action, rules, 12, evidence)
    second = _post(store, action, rules, 12, evidence)
    assert first.status == ACCOUNTING_RECONCILED
    assert second.status == ACCOUNTING_ALREADY
    assert second.usage_accounted is False
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000))


def test_concurrent_duplicate_reports_charge_once(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("race")
    rules = _rules("session")
    evidence = _hold(store, action, rules, 13)
    barrier = threading.Barrier(2)
    results: list[str] = []

    def report() -> None:
        barrier.wait()
        result = _post(store, action, rules, 13, evidence)
        results.append(result.status)

    threads = [threading.Thread(target=report) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [ACCOUNTING_ALREADY, ACCOUNTING_RECONCILED]
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000))


def test_reservation_created_before_the_guard_event_can_be_bound_on_reconcile(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("gap")
    evidence = _hold(store, action, _rules("session"), 14, bind=False)
    assert store.list_reservations()[0]["guard_event_id"] is None
    result = _post(store, action, [], 14, evidence)
    assert result.status == ACCOUNTING_RECONCILED
    row = store.list_reservations()[0]
    assert row["guard_event_id"] == 14
    assert row["status"] == "reconciled"
    assert row["charged_usd"] == pytest.approx(_cost(1000))


def test_crash_during_reconciliation_stays_reserved_and_retries_once(tmp_path, monkeypatch):
    store, _box = _store(tmp_path)
    action = _action("crash")
    rules = _rules("session")
    evidence = _hold(store, action, rules, 15)
    real = TokenBudgetStore._settle
    armed = {"on": True}

    def interrupt(self, *args, **kwargs):
        if armed["on"]:
            armed["on"] = False
            raise RuntimeError("reconciliation crashed")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(TokenBudgetStore, "_settle", interrupt)
    with pytest.raises(RuntimeError, match="reconciliation crashed"):
        _post(store, action, rules, 15, evidence)
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0
    monkeypatch.setattr(TokenBudgetStore, "_settle", real)
    assert _post(store, action, rules, 15, evidence).status == ACCOUNTING_RECONCILED
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000))


def test_expired_estimate_is_corrected_by_later_usage(tmp_path):
    store, box = _store(tmp_path, ttl=30)
    action = _action("late")
    rules = _rules("daily", limit=50.0)
    evidence = _hold(store, action, rules, 16)
    estimate = float(store.list_reservations()[0]["reserved_usd"])
    box["now"] += 90
    store.expire_due()
    assert store.list_reservations()[0]["status"] == "expired_charged"
    result = _post(store, action, [], 16, evidence, output=_usage(3000))
    assert result.status == ACCOUNTING_RECONCILED
    row = store.list_reservations()[0]
    assert row["status"] == "reconciled"
    assert row["charged_usd"] == pytest.approx(_cost(3000))
    assert row["charged_usd"] != pytest.approx(estimate)
    assert float(store.list_active_budgets()[0]["current_usd"]) == pytest.approx(_cost(3000))


def test_legacy_guard_without_evidence_is_not_a_successful_charge(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("legacy")
    _hold(store, action, _rules("session"), 17)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE token_budget_reservations SET evidence_json = '{}'")
    wiped = store.post_record(
        action,
        input_payload=_payload(),
        output_payload=_usage(1000),
        rules=_rules("session", output_rate=99.0),
        guard_event_id=17,
        tenant_id="default",
        principal_hash="p",
        guard_evidence=None,
    )
    assert wiped.status == ACCOUNTING_LEGACY
    assert wiped.usage_accounted is False
    assert store.list_reservations()[0]["status"] == "reserved"
    assert float(store.list_active_budgets()[0]["current_usd"]) == 0.0
    absent = store.post_record(
        _action("none"),
        input_payload=_payload(),
        output_payload=_usage(1000),
        rules=_rules("session"),
        guard_event_id=170,
        tenant_id="default",
        principal_hash="p",
    )
    assert absent.status == ACCOUNTING_LEGACY
    assert store.list_accounting_findings() == []


def test_multi_rule_missing_one_reservation_rolls_the_sibling_back(tmp_path):
    store, _box = _store(tmp_path)
    action = _action("multi")
    rules = _rules("session", "daily")
    evidence = _hold(store, action, rules, 18)
    daily_id = next(entry["reservation_id"] for entry in evidence["rules"] if entry["window"] == "daily")
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("DELETE FROM token_budget_reservations WHERE id = ?", (daily_id,))
    result = _post(store, action, rules, 18, evidence)
    assert result.status == ACCOUNTING_INTEGRITY
    remaining = store.list_reservations()
    assert len(remaining) == 1
    assert remaining[0]["status"] == "reserved"
    assert remaining[0]["window"] == "session"
    assert all(float(row["current_usd"]) == 0.0 for row in store.list_active_budgets())
    assert len(store.list_accounting_findings(18)) == 1


def test_sqlite_lock_retries_then_surfaces(tmp_path, monkeypatch):
    store, _box = _store(tmp_path)
    action = _action("lock")
    rules = _rules("session")
    evidence = _hold(store, action, rules, 19)
    import varden.token_budget as budget_mod

    real_connect = budget_mod.connect
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] < 3:
            raise sqlite3.OperationalError("database is locked")
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(budget_mod, "connect", flaky)
    assert _post(store, action, rules, 19, evidence).status == ACCOUNTING_RECONCILED
    monkeypatch.setattr(budget_mod, "connect", real_connect)
    assert store.list_reservations()[0]["charged_usd"] == pytest.approx(_cost(1000))

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    retry_dir = tmp_path / "retry"
    retry_dir.mkdir()
    fresh, _box = _store(retry_dir)
    action2 = _action("lock-hard")
    evidence2 = _hold(fresh, action2, rules, 20)
    monkeypatch.setattr(budget_mod, "connect", locked)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        _post(fresh, action2, rules, 20, evidence2)
    monkeypatch.setattr(budget_mod, "connect", real_connect)
    assert fresh.list_reservations()[0]["status"] == "reserved"
    assert float(fresh.list_active_budgets()[0]["current_usd"]) == 0.0


def test_http_missing_reservation_is_409_and_the_sdk_does_not_raise(tmp_path):
    client, cfg = _http(
        tmp_path,
        [{"id": "cap-session", "type": "token_budget", "limit_usd": 10.0, "window": "session", "hard_cap": True}],
    )
    with client:
        headers, guarded, _logged = _guard_and_log(client)
        with sqlite3.connect(cfg.db_path) as conn:
            conn.execute("DELETE FROM token_budget_reservations")
        action = guarded.json()["action"]
        action["metadata"] = {"budget_evidence": {"disposition": "unbudgeted", "rules": []}}
        logged = client.post(
            "/sdk/log",
            headers=headers,
            json={
                "guard_event_id": guarded.json()["event_id"],
                "action": action,
                "decision": {"action": "allow", "reason": "forged"},
                "status": "allowed",
                "output_payload": _usage(1000),
            },
        )
        assert logged.status_code == 409
        detail = logged.json()["detail"]
        assert detail["logged"] is True
        assert detail["usage_accounted"] is False
        assert detail["accounting_status"] == "accounting_integrity_failure"
        assert detail["retryable"] is False
        assert detail["evidence_class"] == "server_decision"
        stored = client.get(f"/events/{guarded.json()['event_id']}", headers=headers).json()["event"]
        assert stored["action"]["metadata"]["budget_evidence"]["disposition"] == "evaluated"

    sdk = VardenClient("http://varden.example", api_key="agent-key")
    sdk._client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(
        409,
        json={"detail": detail},
    )))
    returned = sdk.log_result({"guard_event_id": guarded.json()["event_id"]})
    assert returned["accounting_status"] == "accounting_integrity_failure"
    assert returned["logged"] is True


def test_migration_15_does_not_invent_evidence_for_old_events(tmp_path):
    path = tmp_path / "legacy.db"
    historical = json.dumps({"type": "llm_call", "tool": "openai", "metadata": {"audit_binding": {"tenant_id": "old"}}})
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
    for version in range(1, 15):
        conn.execute("INSERT INTO schema_migrations(version) VALUES (?)", (version,))
    conn.execute(
        """
        CREATE TABLE events (
          id INTEGER PRIMARY KEY,
          timestamp REAL NOT NULL,
          action_json TEXT NOT NULL,
          decision_json TEXT NOT NULL,
          status TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO events(id, timestamp, action_json, decision_json, status) VALUES (1, 1, ?, ?, 'allowed')",
        (historical, json.dumps({"action": "allow"})),
    )
    conn.commit()
    conn.close()
    init_db(str(path))
    init_db(str(path))
    with sqlite3.connect(path) as conn:
        versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        stored = conn.execute("SELECT action_json FROM events WHERE id = 1").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM token_budget_accounting_findings").fetchone()[0]
    assert 15 in versions
    assert stored == historical
    assert "budget_evidence" not in stored
    assert findings == 0

    fresh_dir = tmp_path / "fresh"
    fresh_dir.mkdir()
    fresh, _box = _store(fresh_dir)
    with sqlite3.connect(fresh.db_path) as conn:
        assert 15 in {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        assert conn.execute("SELECT COUNT(*) FROM token_budget_accounting_findings").fetchone()[0] == 0
