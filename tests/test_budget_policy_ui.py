import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.policy_packs import load_policy_pack


def _client(tmpdir: str, policy: dict) -> TestClient:
    policy_path = Path(tmpdir) / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=1000,
    )
    return TestClient(create_app(cfg))


def test_dashboard_overview_includes_token_budget_summary():
    policy = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "budget_rules": [
            {
                "id": "overview-cap",
                "type": "token_budget",
                "limit_usd": 1.0,
                "window": "session",
                "hard_cap": True,
            }
        ],
    }
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, policy) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            overview = client.get("/dashboard/overview", headers={"x-api-key": key}).json()
            assert "token_budgets" in overview
            assert overview["token_budgets"]["rules_configured"] == 1


def test_token_budgets_endpoint_lists_configured_rules():
    policy = {
        "block": [],
        "warn": [],
        "monitor": [],
        "allow": [],
        "budget_rules": [
            {
                "id": "api-cap",
                "type": "token_budget",
                "title": "API cap",
                "limit_usd": 2.5,
                "window": "daily",
                "hard_cap": False,
            }
        ],
    }
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, policy) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            payload = client.get("/token-budgets", headers={"x-api-key": key}).json()
            assert payload["summary"]["rules_configured"] == 1
            assert payload["rules"][0]["id"] == "api-cap"


def test_llm_cost_governance_pack_budget_rules_validate(tmp_path):
    pack = load_policy_pack("llm-cost-governance")
    assert pack
    template = pack.get("template") or pack
    assert len(template.get("budget_rules") or []) >= 1
