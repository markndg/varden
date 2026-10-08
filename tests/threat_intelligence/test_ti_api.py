"""API and CLI checks. No live feeds."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.threat_intelligence.applicability import InstallationFacts, ObservabilityFact, SurfaceFact
from varden.threat_intelligence.cli import intelligence_argv


FIXTURES = Path(__file__).parent / "fixtures"


def _client(tmp_path, *, enabled=False):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []}), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(tmp_path / "varden.db"),
        auth_db_path=str(tmp_path / "auth.db"),
        policy_file=str(policy),
        signing_secret="dev-secret",
        threat_intel_enabled=enabled,
    )
    app = create_app(cfg)
    return TestClient(app), policy


def _exposed_facts():
    facts = InstallationFacts(policy={"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []})
    for name, applicable, coverage in (("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")):
        facts.surfaces[name] = SurfaceFact(name=name, applicable=applicable, coverage=coverage)
    for name in ("provenance", "authority_flow", "data_classification", "tool_invocation", "destination"):
        facts.observability[name] = ObservabilityFact(name=name, available=True)
    return facts


def test_status_when_disabled_is_not_a_protection_claim(tmp_path):
    client, _policy = _client(tmp_path)
    with client:
        key = client.get("/health").json()["bootstrap_api_key"]
        body = client.get("/threat-intelligence/status", headers={"x-api-key": key}).json()
        assert body["watcher"] == "DISABLED"
        assert body["protection_claim"] is False
        assert body["enabled"] is False
        page = client.get("/ui/threat-intelligence")
        assert page.status_code == 200


def test_api_approval_is_explicit(tmp_path):
    client, policy = _client(tmp_path, enabled=True)
    with client:
        service = client.app.state.threat_intel
        service._facts_provider = _exposed_facts
        raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
        service.ingest_raw("nvd", [{"cve": raw}])
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        listed = client.get("/threat-intelligence/items", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["items"][0]["rule_active"] is False
        item_id = listed.json()["items"][0]["id"]
        detail = client.get(f"/threat-intelligence/items/{item_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["rule_active"] is False
        assert "Create" not in detail.text
        approved = client.post(f"/threat-intelligence/items/{item_id}/approve", headers=headers)
        assert approved.status_code == 200
        assert approved.json()["rule_active"] is True
        assert "ti-credential-exfiltration" in policy.read_text(encoding="utf-8")
        again = client.post(f"/threat-intelligence/items/{item_id}/approve", headers=headers)
        assert again.status_code == 200
        assert again.json()["idempotent"] is True


def test_cli_json_stdout_is_machine_readable(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"block": [], "warn": [], "monitor": [], "allow": []}), encoding="utf-8")

    from argparse import Namespace

    args = Namespace(
        intelligence_command="status",
        json=True,
        db=str(tmp_path / "ti.db"),
        policy=str(policy),
        source=None,
    )
    assert intelligence_argv(args) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["protection_claim"] is False
    assert payload["watcher"] == "DISABLED"
