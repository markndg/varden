"""P0-6: an agent must not author its own audit decision.

Baseline: POST /sdk/log stored the client's decision and skipped token-budget
accounting when the client set status=blocked.
"""

from __future__ import annotations

from pathlib import Path

from tests.runtime.helpers import make_app_client
from varden.auth import OSS_TENANT_ID, LocalAuth
from varden.stores import EventStore


def _policy(limit_usd: float = 1.0) -> dict:
    return {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "budget_rules": [
            {
                "id": "cap",
                "type": "token_budget",
                "limit_usd": limit_usd,
                "window": "session",
                "hard_cap": True,
            }
        ],
    }


def _guard(client, key, tool="read_notes"):
    response = client.post(
        "/sdk/guard",
        headers={"x-api-key": key},
        json={
            "action": {
                "type": "tool_call",
                "tool": tool,
                "args": {"path": "notes.txt"},
                "trace_id": "trace-audit",
                "metadata": {"runtime": {"coverage": "ENFORCED", "surface": "forged-surface"}},
            },
            "payload": {"path": "notes.txt"},
        },
    )
    return response


def _stored_decision(client, key, event_id):
    body = client.get(f"/events/{event_id}", headers={"x-api-key": key}).json()
    return body["event"]["decision"]["action"], body["event"]


def test_forged_decisions_are_not_authoritative(tmp_path):
    client, _app = make_app_client(str(tmp_path), policy=_policy())
    admin = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    auth = LocalAuth(str(Path(tmp_path) / "varden_auth.db"), "dev-secret")
    agent_a = auth.create_api_key(tenant_id=OSS_TENANT_ID, role="agent")["api_key"]
    agent_b = auth.create_api_key(tenant_id=OSS_TENANT_ID, role="agent")["api_key"]
    guarded = _guard(client, agent_a)
    assert guarded.status_code == 200
    event_id = guarded.json()["event_id"]
    action = guarded.json()["action"]

    forged = client.post(
        "/sdk/log",
        headers={"x-api-key": agent_a},
        json={
            "guard_event_id": event_id,
            "action": {**action, "tool": "other-tool"},
            "decision": {"action": "allow", "matched_rule": "forged", "approval_id": "fake"},
            "status": "allowed",
        },
    )
    assert forged.json()["evidence_class"] == "unverified_observation"
    decision, _event = _stored_decision(client, admin, forged.json()["event_id"])
    assert decision == "unverified_observation"

    other_principal = client.post(
        "/sdk/log",
        headers={"x-api-key": agent_b},
        json={"guard_event_id": event_id, "action": action, "decision": {"action": "block"}, "status": "blocked"},
    )
    assert other_principal.json()["evidence_class"] == "unverified_observation"

    bound = client.post(
        "/sdk/log",
        headers={"x-api-key": agent_a},
        json={
            "guard_event_id": event_id,
            "action": action,
            "decision": {"action": "block", "approval_id": "fake-approval"},
            "status": "blocked",
            "action_metadata_coverage": "ENFORCED",
        },
    )
    assert bound.json()["evidence_class"] == "server_decision"
    decision, event = _stored_decision(client, admin, bound.json()["event_id"])
    assert decision == "allow"
    assert "fake-approval" not in str(event.get("decision"))
    runtime = ((event.get("action") or {}).get("metadata") or {}).get("runtime") or {}
    assert runtime.get("coverage") != "ENFORCED"


def test_other_tenant_event_is_not_bound(tmp_path):
    client, _app = make_app_client(str(tmp_path), policy=_policy())
    admin = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    foreign = EventStore(str(Path(tmp_path) / "varden.db")).log(
        {
            "timestamp": 1.0,
            "action": {"type": "tool_call", "tool": "read_notes", "args": {}, "metadata": {"audit_binding": {"tenant_id": "other"}}},
            "decision": {"action": "allow"},
            "status": "allowed",
            "tenant_id": "other",
        }
    )
    logged = client.post(
        "/sdk/log",
        headers={"x-api-key": admin},
        json={"guard_event_id": foreign, "action": {"type": "tool_call", "tool": "read_notes"}, "decision": {"action": "allow"}},
    )
    assert logged.json()["evidence_class"] == "unverified_observation"


def test_client_status_cannot_skip_or_duplicate_budget_accounting(tmp_path):
    client, _app = make_app_client(str(tmp_path), policy=_policy(0.5))
    admin = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    action = {
        "type": "llm_call",
        "tool": "openai.responses.create",
        "trace_id": "budget-trace",
        "workflow_id": "budget-trace",
        "args": {"model": "gpt-4o", "input": "hello"},
    }
    first = client.post("/sdk/guard", headers={"x-api-key": admin}, json={"action": action, "payload": action["args"]})
    assert first.status_code == 200, first.text
    event_id = first.json()["event_id"]
    stored_action = first.json()["action"]
    usage = {"usage": {"input_tokens": 1_000_000, "output_tokens": 1_000_000}, "model": "gpt-4o"}
    reported = client.post(
        "/sdk/log",
        headers={"x-api-key": admin},
        json={
            "guard_event_id": event_id,
            "action": stored_action,
            "decision": {"action": "block"},
            "status": "blocked",
            "output_payload": usage,
        },
    )
    assert reported.status_code in {200, 403}
    reported_body = reported.json()
    if isinstance(reported_body.get("detail"), dict):
        reported_body = reported_body["detail"]
    assert reported_body["evidence_class"] == "server_decision"
    replay = client.post(
        "/sdk/log",
        headers={"x-api-key": admin},
        json={
            "guard_event_id": event_id,
            "action": stored_action,
            "decision": {"action": "allow"},
            "status": "allowed",
            "output_payload": usage,
        },
    )
    assert replay.json()["usage_accounted"] is False
    budgets = client.get("/token-budgets", headers={"x-api-key": admin}).json()
    current = budgets["items"][0]["current_usd"]
    assert current > 0
    second = client.post("/sdk/guard", headers={"x-api-key": admin}, json={"action": action, "payload": action["args"]})
    assert second.status_code == 403


def test_omitted_usage_report_still_holds_the_reservation(tmp_path):
    client, _app = make_app_client(str(tmp_path), policy=_policy(0.4))
    admin = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    action = {
        "type": "llm_call",
        "tool": "openai.responses.create",
        "trace_id": "hold-trace",
        "workflow_id": "hold-trace",
        "args": {"model": "gpt-4o", "input": "x" * 4000},
    }
    first = client.post("/sdk/guard", headers={"x-api-key": admin}, json={"action": action, "payload": {"input": "x" * 200_000}})
    assert first.status_code == 200, first.text
    second = client.post("/sdk/guard", headers={"x-api-key": admin}, json={"action": action, "payload": {"input": "x" * 200_000}})
    assert second.status_code == 403
