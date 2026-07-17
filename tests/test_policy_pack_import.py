import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.policy_packs import list_policy_packs, load_policy_pack, merge_policy_pack


def _client(tmpdir: str) -> TestClient:
    policy_path = Path(tmpdir) / "policy.json"
    policy_path.write_text(
        json.dumps({"block": [], "warn": [], "monitor": [], "allow": []}),
        encoding="utf-8",
    )
    cfg = AppConfig(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=1000,
    )
    return TestClient(create_app(cfg))


def test_list_policy_packs_includes_llm_cost_governance():
    packs = list_policy_packs()
    ids = {row["id"] for row in packs}
    assert "llm-cost-governance" in ids
    pack = next(row for row in packs if row["id"] == "llm-cost-governance")
    assert pack["budget_rules"] >= 1


def test_merge_policy_pack_adds_rules_without_duplicates():
    base = {"block": [{"name": "existing", "type": "tool_call", "tool": "delete_database"}], "warn": [], "monitor": [], "allow": []}
    pack = load_policy_pack("baseline-operational-safety")
    assert pack
    merged = merge_policy_pack(base, pack, mode="merge")
    assert merged["added"]["block"] >= 1
    again = merge_policy_pack(merged["policy"], pack, mode="merge")
    assert again["added"]["block"] == 0


def test_policy_pack_api_list_get_and_import():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            headers = {"x-api-key": key}
            listed = client.get("/policy/packs", headers=headers)
            assert listed.status_code == 200
            items = listed.json()["items"]
            assert any(row["id"] == "deployment-cli-safety" for row in items)

            pack = client.get("/policy/packs/deployment-cli-safety", headers=headers)
            assert pack.status_code == 200
            assert pack.json()["name"] == "deployment-cli-safety"

            imported = client.post(
                "/policy/import-pack",
                headers=headers,
                json={"pack_id": "monitoring-foundation", "mode": "merge"},
            )
            assert imported.status_code == 200
            body = imported.json()
            assert body["status"] == "imported"
            assert body["added"]["monitor"] >= 1
            saved = json.loads(Path(tmpdir, "policy.json").read_text(encoding="utf-8"))
            assert len(saved.get("monitor") or []) >= 1
