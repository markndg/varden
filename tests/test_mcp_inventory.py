import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.mcp_inventory import McpInventoryStore, parse_mcp_config, resolve_mcp_scan_paths


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


def test_parse_mcp_config_extracts_servers(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "varden": {"command": "python", "args": ["-m", "varden_mcp"]},
                    "fetch": {"url": "http://127.0.0.1:9000"},
                }
            }
        ),
        encoding="utf-8",
    )
    rows = parse_mcp_config(config_path)
    assert len(rows) == 2
    assert rows[0]["name"] in {"varden", "fetch"}


def test_mcp_inventory_infers_varden_tools(tmp_path):
    store = McpInventoryStore(str(tmp_path / "varden.db"))
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"varden-local": {"command": "varden-mcp", "args": []}}}),
        encoding="utf-8",
    )
    result = store.scan(paths=[config_path], policy={"block": [], "warn": [], "monitor": [], "allow": []})
    assert result["summary"]["server_count"] == 1
    assert result["summary"]["tool_count"] >= 5
    tool_names = {row["tool_name"] for row in result["tools"]}
    assert "varden_guard" in tool_names


def test_resolve_mcp_scan_paths_accepts_single_path(tmp_path):
    config_path = tmp_path / "custom-mcp.json"
    config_path.write_text("{}", encoding="utf-8")
    paths = resolve_mcp_scan_paths({"path": str(config_path)})
    assert paths == [config_path]


def test_mcp_scan_rejects_missing_path(tmp_path):
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            headers = {"x-api-key": key}
            response = client.post(
                "/mcp/scan",
                headers=headers,
                json={"path": str(tmp_path / "missing-mcp.json")},
            )
            assert response.status_code == 400
            assert "not found" in response.text.lower()


def test_mcp_scan_removes_stale_servers(tmp_path):
    store = McpInventoryStore(str(tmp_path / "varden.db"))
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"alpha": {"command": "echo", "args": ["a"]}}}),
        encoding="utf-8",
    )
    store.scan(paths=[config_path], policy={"block": [], "warn": [], "monitor": [], "allow": []})
    assert store.inventory()["summary"]["server_count"] == 1
    config_path.write_text(
        json.dumps({"mcpServers": {"beta": {"command": "echo", "args": ["b"]}}}),
        encoding="utf-8",
    )
    store.scan(paths=[config_path], policy={"block": [], "warn": [], "monitor": [], "allow": []})
    inventory = store.inventory()
    assert inventory["summary"]["server_count"] == 1
    assert inventory["servers"][0]["name"] == "beta"


def test_mcp_inventory_redacts_sensitive_args(tmp_path):
    store = McpInventoryStore(str(tmp_path / "varden.db"))
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "secrets": {
                        "command": "run",
                        "args": ["--api-key", "super-secret-token-value"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    store.scan(paths=[config_path], policy={"block": [], "warn": [], "monitor": [], "allow": []})
    server = store.inventory()["servers"][0]
    args = json.loads(server["args_json"])
    assert args[1] == "[REDACTED]"


def test_mcp_inventory_api_scan_and_list(tmp_path):
    config_path = tmp_path / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"demo": {"command": "echo", "args": ["mcp"]}}}),
        encoding="utf-8",
    )
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            key = client.get("/health").json()["bootstrap_api_key"]
            headers = {"x-api-key": key}
            scanned = client.post(
                "/mcp/scan",
                headers=headers,
                json={"paths": [str(config_path)]},
            )
            assert scanned.status_code == 200
            body = scanned.json()
            assert body["summary"]["server_count"] == 1

            inventory = client.get("/mcp/inventory", headers=headers)
            assert inventory.status_code == 200
            assert inventory.json()["summary"]["server_count"] == 1
