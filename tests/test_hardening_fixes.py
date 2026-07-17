import json
from pathlib import Path

import pytest

from varden.db import connect
from varden.models import Action
from varden.rules.registry import load_budget_rules
from varden.token_budget import TokenBudgetStore, simulate_budget_trace


def _budget_policy(limit_usd: float = 0.0001, *, hard_cap: bool = True) -> dict:
    return {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "budget_rules": [
            {
                "id": "test-session-cap",
                "type": "token_budget",
                "limit_usd": limit_usd,
                "window": "session",
                "hard_cap": hard_cap,
            }
        ],
    }


def test_publish_applies_policy_to_runtime_and_file(tmp_path):
    from varden.policy import PolicyEngine
    from varden.db import init_db

    db_path = str(tmp_path / "varden.db")
    policy_file = tmp_path / "policy.json"
    init_db(db_path)
    policy_file.write_text(
        json.dumps({"block": [], "warn": [], "monitor": [], "allow": []}),
        encoding="utf-8",
    )
    engine = PolicyEngine(db_path, json.loads(policy_file.read_text()))
    candidate = {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    version_id = engine.snapshot("draft", status="draft")
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE policy_versions SET policy_json = ? WHERE id = ?",
            (json.dumps(candidate), version_id),
        )
        conn.commit()
    result = engine.publish(version_id, policy_file=str(policy_file))
    assert result["published_version"] == version_id
    assert engine.get_policy()["block"][0]["tool"] == "delete_database"
    saved = json.loads(policy_file.read_text(encoding="utf-8"))
    assert saved["block"][0]["tool"] == "delete_database"


def test_load_policy_pack_rejects_path_traversal():
    from varden.policy_packs import load_policy_pack

    assert load_policy_pack("../../../etc/passwd") is None
    assert load_policy_pack("foo/bar") is None


def test_token_budget_reserves_on_pre_check_and_releases_on_post(tmp_path):
    store = TokenBudgetStore(str(tmp_path / "varden.db"))
    rules = load_budget_rules(
        {
            "block": [],
            "warn": [],
            "monitor": [],
            "allow": [],
            "budget_rules": [
                {
                    "id": "reserve-test",
                    "type": "token_budget",
                    "limit_usd": 10.0,
                    "window": "session",
                    "hard_cap": True,
                }
            ],
        }
    )
    action = Action(type="llm_call", tool="openai", trace_id="trace-reserve", workflow_id="wf-reserve")
    payload = {"kwargs": {"model": "gpt-4o", "max_tokens": 100}}
    store.pre_check(action, payload, rules)
    rows = store.list_active_budgets()
    assert rows and float(rows[0].get("reserved_usd") or 0) > 0
    store.post_record(
        action,
        input_payload=payload,
        output_payload={"usage": {"input_tokens": 100, "output_tokens": 50}, "model": "gpt-4o"},
        rules=rules,
    )
    rows = store.list_active_budgets()
    assert float(rows[0]["reserved_usd"]) == 0.0
    assert float(rows[0]["current_usd"]) > 0


def test_token_budget_post_records_without_usage(tmp_path):
    store = TokenBudgetStore(str(tmp_path / "varden.db"))
    rules = load_budget_rules(_budget_policy(limit_usd=10.0))
    action = Action(type="llm_call", tool="openai", trace_id="trace-est", workflow_id="wf-est")
    store.post_record(
        action,
        input_payload={"kwargs": {"model": "gpt-4o", "messages": "hello world"}},
        output_payload={"text": "response without usage block"},
        rules=rules,
    )
    rows = store.list_active_budgets()
    assert rows and float(rows[0]["current_usd"]) > 0


def test_simulate_budget_trace_flags_violations():
    rules = load_budget_rules(_budget_policy(limit_usd=0.00001))
    trace_events = [
        {
            "id": 1,
            "action": {
                "type": "llm_call",
                "tool": "openai",
                "trace_id": "sim-trace",
                "workflow_id": "sim-wf",
            },
            "input_payload": {"kwargs": {"model": "gpt-4o", "max_tokens": 50000}},
            "output_payload": {"usage": {"input_tokens": 5000, "output_tokens": 5000}},
        }
    ]
    result = simulate_budget_trace(trace_events, rules)
    assert result["violations"]
