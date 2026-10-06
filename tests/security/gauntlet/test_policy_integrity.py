"""G-POLICY-INT-01 — control-plane policy mutation / snapshot integrity."""

from __future__ import annotations

import concurrent.futures
import copy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.models import Action
from varden.policy import PolicyEngine


def _client(tmp_path: Path, policy: dict | None = None) -> TestClient:
    policy_path = tmp_path / "policy.json"
    doc = policy or {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
        "require_approval": [],
        "sanitise": [],
    }
    policy_path.write_text(__import__("json").dumps(doc), encoding="utf-8")
    cfg = AppConfig(
        db_path=str(tmp_path / "events.db"),
        auth_db_path=str(tmp_path / "auth.db"),
        policy_file=str(policy_path),
        signing_secret="test-secret",
        enable_dev_bootstrap=True,
    )
    app = create_app(cfg)
    return TestClient(app)


def test_gauntlet_agent_cannot_put_policy(tmp_path):
    client = _client(tmp_path)
    boot = client.get("/health").json()
    agent_key = boot["bootstrap_agent_api_key"]
    weak = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [{"type": "tool_call"}],
        "require_approval": [],
        "sanitise": [],
        "default": "allow",
    }
    assert client.put("/policy", headers={"x-api-key": agent_key}, json=weak).status_code == 403
    # Deny still holds via bootstrap admin policy
    admin = boot["bootstrap_api_key"]
    # Use agent key for guard path
    r = client.post(
        "/sdk/guard",
        headers={"x-api-key": agent_key},
        json={"action": {"type": "tool_call", "tool": "delete_database", "args": {}}, "payload": {}},
    )
    assert r.status_code == 403


def test_gauntlet_malformed_policy_rejected_preserves_prior(tmp_path):
    client = _client(tmp_path)
    admin = client.get("/health").json()["bootstrap_api_key"]
    prior = client.get("/policy", headers={"x-api-key": admin}).json()
    bad = {"block": "not-a-list", "warn": [], "monitor": [], "allow": []}
    r = client.put("/policy", headers={"x-api-key": admin}, json=bad)
    assert r.status_code == 400
    after = client.get("/policy", headers={"x-api-key": admin}).json()
    assert after["block"] == prior["block"]


def test_gauntlet_get_policy_mutation_cannot_weaken_live_engine(tmp_path):
    eng = PolicyEngine(str(tmp_path / "p.db"), {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    })
    leaked = eng.get_policy()
    leaked["block"] = []
    leaked["default"] = "allow"
    action = Action(type="tool_call", tool="delete_database", args={})
    assert eng.evaluate(action).action == "block"


def test_gauntlet_update_policy_argument_mutation_cannot_weaken(tmp_path):
    eng = PolicyEngine(str(tmp_path / "p.db"), {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    })
    candidate = {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    eng.update_policy(candidate)
    candidate["block"] = []
    action = Action(type="tool_call", tool="delete_database", args={})
    assert eng.evaluate(action).action == "block"


def test_gauntlet_concurrent_policy_update_uses_coherent_snapshot(tmp_path):
    eng = PolicyEngine(str(tmp_path / "p.db"), {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    })
    action = Action(type="tool_call", tool="delete_database", args={})
    weak = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [{"type": "tool_call"}],
        "default": "allow",
    }
    strong = {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    }

    results: list[str] = []

    def _eval(_):
        results.append(eng.evaluate(action).action)

    def _flip(_):
        for doc in (weak, strong, weak, strong):
            eng.update_policy(copy.deepcopy(doc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_eval, i) for i in range(40)]
        futs += [pool.submit(_flip, i) for i in range(10)]
        for f in futs:
            f.result()
    # Every decision must be a complete mode string — never crash / partial
    assert all(r in {"block", "allow", "monitor", "warn", "require_approval", "sanitise"} for r in results)


def test_gauntlet_legitimate_admin_policy_update_still_works(tmp_path):
    client = _client(tmp_path)
    admin = client.get("/health").json()["bootstrap_api_key"]
    agent = client.get("/health").json()["bootstrap_agent_api_key"]
    # Initially blocked
    assert client.post(
        "/sdk/guard",
        headers={"x-api-key": agent},
        json={"action": {"type": "tool_call", "tool": "delete_database", "args": {}}, "payload": {}},
    ).status_code == 403
    # Admin replaces with allow-all for that tool (legitimate dynamic update)
    new_pol = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [{"type": "tool_call", "tool": "delete_database"}],
        "require_approval": [],
        "sanitise": [],
        "default": "allow",
    }
    assert client.put("/policy", headers={"x-api-key": admin}, json=new_pol).status_code == 200
    assert client.post(
        "/sdk/guard",
        headers={"x-api-key": agent},
        json={"action": {"type": "tool_call", "tool": "delete_database", "args": {}}, "payload": {}},
    ).status_code == 200


def test_gauntlet_vacuous_put_refused_preserves_prior(tmp_path):
    client = _client(tmp_path)
    admin = client.get("/health").json()["bootstrap_api_key"]
    agent = client.get("/health").json()["bootstrap_agent_api_key"]
    prior = client.get("/policy", headers={"x-api-key": admin}).json()
    vacuous = {"block": [], "warn": [], "monitor": [], "allow": []}
    r = client.put("/policy", headers={"x-api-key": admin}, json=vacuous)
    assert r.status_code == 400
    assert "vacuous" in str(r.json()).lower()
    assert client.get("/policy", headers={"x-api-key": admin}).json()["block"] == prior["block"]
    assert client.post(
        "/sdk/guard",
        headers={"x-api-key": agent},
        json={"action": {"type": "tool_call", "tool": "delete_database", "args": {}}, "payload": {}},
    ).status_code == 403


def test_gauntlet_partial_put_missing_bucket_refused(tmp_path):
    client = _client(tmp_path)
    admin = client.get("/health").json()["bootstrap_api_key"]
    # Omitting allow (client treating PUT as PATCH) must not wipe
    partial = {"block": [], "warn": [], "monitor": []}
    r = client.put("/policy", headers={"x-api-key": admin}, json=partial)
    assert r.status_code == 400
    assert "allow" in str(r.json()).lower()


def test_gauntlet_explicit_vacuous_opt_in_allowed(tmp_path):
    client = _client(tmp_path)
    admin = client.get("/health").json()["bootstrap_api_key"]
    vacuous = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "require_approval": [],
        "sanitise": [],
        "allow_vacuous_policy": True,
    }
    assert client.put("/policy", headers={"x-api-key": admin}, json=vacuous).status_code == 200


def test_gauntlet_deny_by_default_empty_buckets_allowed(tmp_path):
    client = _client(tmp_path)
    admin = client.get("/health").json()["bootstrap_api_key"]
    deny = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "require_approval": [],
        "sanitise": [],
        "default": "block",
    }
    assert client.put("/policy", headers={"x-api-key": admin}, json=deny).status_code == 200
