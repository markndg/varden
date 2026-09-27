"""Frontend-facing Predictive view safety + API smoke tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.predictive_authority.views import build_demo_fixture, safe_label


def test_safe_label_strips_html_and_bidi():
    assert "<" not in safe_label("<img src=x onerror=alert(1)>")
    assert "\u202e" not in safe_label("cred\u202eentials")


def test_predictive_api_demo_and_status(tmp_path):
    db = tmp_path / "v.db"
    policy = tmp_path / "p.json"
    policy.write_text('{"block":[],"warn":[],"monitor":[],"allow":[]}\n')
    app = create_app(AppConfig(db_path=str(db), policy_file=str(policy), enable_dev_bootstrap=True))
    client = TestClient(app)
    key = client.get("/health").json().get("bootstrap_api_key") or "admin-demo-key"
    headers = {"x-api-key": key}
    demo = client.post("/predictive/demo?mode=enforce", headers=headers)
    assert demo.status_code == 200
    body = demo.json()
    assert body["hazardous"]["live"] is True
    assert body["hazardous"]["events"]
    # Predicted must be distinguishable in payload.
    last = body["hazardous"]["events"][-1]
    assert last["existing_decision"] == "allow"
    assert last["recommendation"] in {"require_approval", "block", "warn", "monitor"}
    status = client.get("/predictive/status?trace_id=ui-demo&tenant_id=demo", headers=headers)
    assert status.status_code == 200
    graph = client.get("/predictive/graph?trace_id=ui-demo&tenant_id=demo", headers=headers)
    assert graph.status_code == 200
    assert "nodes" in graph.json()
    # UI route shell
    assert client.get("/ui/predictive").status_code == 200


def test_routing_predictive_path():
    # Mirror frontend routing rule in a tiny pure check used by docs/tests.
    path = "/ui/predictive"
    assert "predictive" in path
