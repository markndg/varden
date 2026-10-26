"""P0-7: production must not hand out policy or credentials anonymously.

Baseline: GET /health returned bootstrap API keys, and GET /sdk/bootstrap
returned the full default policy without authentication.
"""

from __future__ import annotations

import inspect

from fastapi.testclient import TestClient

from tests.runtime.helpers import make_app_client
from varden.app_factory import create_app
from varden.config import AppConfig

STRONG = "p" * 32

# Routes that answer without a credential. HTML shells do not embed secrets.
# Adding a route here is a review, not an accident.
UNAUTHENTICATED_ROUTES = {
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/health/live"),
    ("GET", "/health/ready"),
    ("GET", "/sdk/bootstrap"),
    ("GET", "/ui"),
    ("GET", "/ui/rules"),
    ("GET", "/ui/decision/{event_id}"),
    ("GET", "/ui/impact"),
    ("GET", "/ui/coverage-gaps"),
    ("GET", "/ui/web-shield"),
    ("GET", "/ui/authority"),
    ("GET", "/ui/predictive"),
    ("GET", "/ui/threat-intelligence"),
    ("GET", "/ui/threat-intelligence/{item_id}"),
    ("GET", "/webshield/lab"),
    ("GET", "/favicon.ico"),
}


def _production(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"block":[],"warn":[],"monitor":[],"allow":[]}',
        encoding="utf-8",
    )
    cfg = AppConfig(
        env="production",
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "varden_auth.db"),
        policy_file=str(policy),
        signing_secret=STRONG,
        enable_dev_bootstrap=False,
        host="127.0.0.1",
    )
    assert cfg.validate() == []
    return TestClient(create_app(cfg))


def test_production_bootstrap_exposes_neither_policy_nor_credentials(tmp_path):
    client = _production(tmp_path)
    body = client.get("/sdk/bootstrap").json()
    assert "default_policy" not in body
    assert "bootstrap_api_key" not in body
    assert "rules" not in body
    assert body["base_url"]


def test_health_exposes_no_secrets(tmp_path):
    client = _production(tmp_path)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/health/detail").status_code == 403


def test_non_loopback_dev_bootstrap_is_rejected(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"block":[],"warn":[],"monitor":[],"allow":[]}', encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        host="0.0.0.0",
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "varden_auth.db"),
        policy_file=str(policy),
        signing_secret="dev-secret",
    )
    assert any("non-loopback" in error for error in cfg.validate())


def test_unsafe_override_does_not_expose_admin_credentials(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"block":[],"warn":[],"monitor":[],"allow":[]}', encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        host="0.0.0.0",
        unsafe_dev_bind=True,
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "varden_auth.db"),
        policy_file=str(policy),
        signing_secret="dev-secret",
    )
    assert cfg.validate() == []
    client = TestClient(create_app(cfg))
    body = client.get("/sdk/bootstrap").json()
    assert "bootstrap_api_key" not in body
    assert client.get("/ui/bootstrap").status_code == 403


def test_proxy_header_cannot_spoof_loopback(tmp_path):
    client, _app = make_app_client(str(tmp_path))
    remote = TestClient(client.app, client=("203.0.113.5", 40000))
    body = remote.get("/sdk/bootstrap", headers={"x-forwarded-for": "127.0.0.1"}).json()
    assert "bootstrap_api_key" not in body


def test_api_docs_follow_the_environment(tmp_path):
    production = _production(tmp_path)
    assert production.get("/docs").status_code == 404
    assert production.get("/openapi.json").status_code == 404
    dev_dir = tmp_path / "dev"
    dev_dir.mkdir()
    dev, _app = make_app_client(str(dev_dir))
    assert dev.get("/openapi.json").status_code == 200


def test_authenticated_sdk_startup_still_works(tmp_path):
    client, _app = make_app_client(str(tmp_path))
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    response = client.post(
        "/sdk/guard",
        headers={"x-api-key": key},
        json={"action": {"type": "tool_call", "tool": "echo", "args": {}}},
    )
    assert response.status_code == 200


def test_threat_intelligence_ui_is_the_public_dashboard_shell(tmp_path):
    client = _production(tmp_path)
    shell = client.get("/ui").text
    for path in ("/ui/threat-intelligence", "/ui/threat-intelligence/item-1"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.text == shell
        assert "bootstrap_api_key" not in response.text
    assert client.get("/threat-intelligence/status").status_code == 403
    assert client.get("/threat-intelligence/items").status_code == 403


def test_production_routes_match_the_auth_inventory(tmp_path):
    client = _production(tmp_path)
    unexpected = []
    for route in client.app.routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "")
        endpoint = getattr(route, "endpoint", None)
        if not path or path.startswith("/docs") or path in {"/redoc", "/openapi.json"}:
            continue
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            key = (method, path)
            if key in UNAUTHENTICATED_ROUTES:
                continue
            source = inspect.getsource(endpoint) if endpoint else ""
            if "require(" not in source and "require_role" not in source:
                unexpected.append(key)
    assert unexpected == []
