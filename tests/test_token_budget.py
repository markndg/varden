import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.exceptions import PolicyViolation
from varden.models import Action
from varden.rules.registry import load_budget_rules
from varden.rules.token_budget import TokenBudgetRule, compute_cost_usd, resolve_output_limit
from varden.token_budget import TokenBudgetStore, extract_usage_from_log_payload


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


def test_token_budget_rule_validation():
    invalid = TokenBudgetRule.from_dict({"id": "x", "limit_usd": 0, "window": "session"})
    assert invalid.validate()
    valid = TokenBudgetRule.from_dict({"id": "x", "limit_usd": 1.0, "window": "session"})
    assert not valid.validate()
    bad_window = TokenBudgetRule.from_dict({"id": "x", "limit_usd": 1.0, "window": "invalid"})
    assert any("window" in err for err in bad_window.validate())


def test_compute_cost_usd_and_output_limit():
    cost = compute_cost_usd(
        model="claude-sonnet-4-6",
        input_tokens=1_000_000,
        output_tokens=0,
        model_costs=TokenBudgetRule.from_dict({"id": "x", "limit_usd": 1, "window": "session"}).model_costs,
    )
    assert cost == pytest.approx(3.0)
    assert resolve_output_limit("gpt-4o") > 0


def test_extract_usage_from_log_payload():
    usage = extract_usage_from_log_payload(
        {"usage": {"input_tokens": 100, "output_tokens": 50}, "model": "gpt-4o"},
        None,
    )
    assert usage == ("gpt-4o", 100, 50)


def test_token_budget_store_blocks_when_projected_over_limit(tmp_path):
    store = TokenBudgetStore(str(tmp_path / "varden.db"))
    rules = load_budget_rules(_budget_policy())
    action = Action(type="llm_call", tool="openai", trace_id="trace-1", workflow_id="wf-1")
    payload = {"kwargs": {"model": "gpt-4o", "max_tokens": 50000}}
    with pytest.raises(PolicyViolation):
        store.pre_check(action, payload, rules)


def test_token_budget_store_records_usage_after_log(tmp_path):
    store = TokenBudgetStore(str(tmp_path / "varden.db"))
    rules = load_budget_rules(_budget_policy(limit_usd=10.0))
    action = Action(type="llm_call", tool="openai", trace_id="trace-2", workflow_id="wf-2")
    store.post_record(
        action,
        input_payload={"kwargs": {"model": "gpt-4o"}},
        output_payload={"usage": {"input_tokens": 1000, "output_tokens": 500}, "model": "gpt-4o"},
        rules=rules,
    )
    rows = store.list_active_budgets()
    assert rows
    assert float(rows[0]["current_usd"]) > 0


def test_sdk_guard_blocks_llm_call_when_budget_exceeded():
    with TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "policy.json"
        policy_path.write_text(json.dumps(_budget_policy()), encoding="utf-8")
        cfg = AppConfig(
            env="dev",
            db_path=str(Path(tmpdir) / "varden.db"),
            auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
            policy_file=str(policy_path),
            signing_secret="dev-secret",
            rate_limit_per_minute=1000,
        )
        with TestClient(create_app(cfg)) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            body = {
                "action": {
                    "type": "llm_call",
                    "tool": "openai",
                    "trace_id": "budget-trace",
                    "workflow_id": "budget-wf",
                    "args": {"kwargs": {"model": "gpt-4o", "max_tokens": 64000}},
                },
                "payload": {"kwargs": {"model": "gpt-4o", "max_tokens": 64000}},
            }
            response = client.post("/sdk/guard", headers={"x-api-key": key}, json=body)
            assert response.status_code == 403
            assert "budget" in response.text.lower()


def test_sdk_log_increments_budget(tmp_path):
    with TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "policy.json"
        policy_path.write_text(json.dumps(_budget_policy(limit_usd=10.0)), encoding="utf-8")
        cfg = AppConfig(
            env="dev",
            db_path=str(Path(tmpdir) / "varden.db"),
            auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
            policy_file=str(policy_path),
            signing_secret="dev-secret",
            rate_limit_per_minute=1000,
        )
        with TestClient(create_app(cfg)) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            body = {
                "action": {
                    "type": "llm_call",
                    "tool": "openai",
                    "trace_id": "log-trace",
                    "workflow_id": "log-wf",
                },
                "decision": {"action": "allow", "reason": "ok"},
                "status": "allowed",
                "output_payload": {
                    "usage": {"input_tokens": 2000, "output_tokens": 1000},
                    "model": "gpt-4o",
                },
            }
            response = client.post("/sdk/log", headers={"x-api-key": key}, json=body)
            assert response.status_code == 200
            store = TokenBudgetStore(cfg.db_path)
            rows = store.list_active_budgets()
            assert rows and float(rows[0]["current_usd"]) > 0
