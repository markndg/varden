"""Control-plane route for monitoring integrity posture."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig


def test_integrity_route_is_honest_when_disabled(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"block": [], "warn": [], "monitor": [], "allow": []}), encoding="utf-8")
    app = create_app(AppConfig(db_path=str(tmp_path / "v.db"), policy_file=str(policy), enable_dev_bootstrap=True))
    client = TestClient(app)
    assert client.get("/ui/integrity").status_code == 200
    key = client.get("/sdk/bootstrap").json().get("bootstrap_api_key") or "admin-demo-key"
    response = client.get("/runtime/integrity", headers={"x-api-key": key})
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["posture"] == "disabled"
    assert body["verified_protection"] is False
    assert body["os_isolation"] is False
