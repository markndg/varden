"""API-level tests for provenance routes and guard enrichment."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.db import init_db
from varden.policy_packs import load_policy_pack, merge_policy_pack
from varden.fsutil import atomic_write_json


def _client(tmp_path: Path) -> TestClient:
    db = tmp_path / "t.db"
    auth = tmp_path / "a.db"
    policy = tmp_path / "policy.json"
    pack = load_policy_pack("provenance-authority-defense")
    atomic_write_json(policy, (pack or {"template": {}})["template"])
    init_db(str(db))
    cfg = AppConfig(db_path=str(db), auth_db_path=str(auth), policy_file=str(policy), signing_secret="test")
    app = create_app(cfg)
    return TestClient(app)


def test_guard_blocks_untrusted_secret_read(tmp_path):
    client = _client(tmp_path)
    # bootstrap key
    boot = client.get("/sdk/bootstrap")
    key = boot.json()["bootstrap_api_key"]
    home = str(Path.home())
    resp = client.post(
        "/sdk/guard",
        headers={"x-api-key": key},
        json={
            "action": {
                "type": "file_read",
                "tool": "read_file",
                "args": {"path": f"{home}/.ssh/id_rsa"},
                "trace_id": "api-ghost",
                "metadata": {
                    "lineage": {"sources": ["https://evil.test"]},
                    "provenance_sources": [{
                        "source_id": "w",
                        "source_type": "web_page",
                        "origin": "https://evil.test",
                        "trust_level": "untrusted",
                    }],
                },
            },
            "payload": {"path": f"{home}/.ssh/id_rsa"},
        },
    )
    assert resp.status_code in {200, 403}
    body = resp.json()
    decision = body.get("decision") or (body.get("detail") or {}).get("decision") or {}
    action = body.get("action") or (body.get("detail") or {}).get("action") or {}
    assert decision.get("action") == "block"
    assert action.get("metadata", {}).get("authority", {}).get("violation") is True


def test_provenance_summary_endpoint(tmp_path):
    client = _client(tmp_path)
    boot = client.get("/sdk/bootstrap").json()
    key = boot["bootstrap_api_key"]
    # Generate a finding first
    home = str(Path.home())
    client.post(
        "/sdk/guard",
        headers={"x-api-key": key},
        json={
            "action": {
                "type": "file_read",
                "args": {"path": f"{home}/.aws/credentials"},
                "trace_id": "sum1",
                "metadata": {"lineage": {"sources": ["mcp://evil"]}},
            },
            "payload": {},
        },
    )
    summary = client.get("/provenance/summary", headers={"x-api-key": key})
    assert summary.status_code == 200
    data = summary.json()
    assert "findings_total" in data
    assert data["findings_total"] >= 1
