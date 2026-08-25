"""MCP gateway cross-server enforcement with local mock servers."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.runtime.mcp_gateway import wrap_mcp_config


def test_wrap_config_routes_through_gateway():
    cfg = {
        "mcpServers": {
            "public-search": {"command": "python", "args": ["-m", "public_search"]},
            "internal-crm": {"command": "python", "args": ["-m", "internal_crm"]},
        }
    }
    wrapped, changes = wrap_mcp_config(cfg)
    assert len(changes) == 2
    for name in ("public-search", "internal-crm"):
        entry = wrapped["mcpServers"][name]
        assert "varden.runtime.mcp_gateway" in entry["args"]


def test_gateway_blocks_privileged_call_via_policy():
    """Cross-server provenance: untrusted public-search → privileged CRM delete."""
    with TemporaryDirectory() as tmpdir:
        policy = Path(tmpdir) / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "block": [
                        {
                            "type": "mcp_call",
                            "tool": "delete_customer",
                            "field:metadata.provenance_sources": {"contains": "mcp://public-search"},
                        }
                    ],
                    "warn": [],
                    "monitor": [],
                    "allow": [],
                }
            ),
            encoding="utf-8",
        )
        cfg = AppConfig(
            env="dev",
            db_path=str(Path(tmpdir) / "varden.db"),
            auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
            policy_file=str(policy),
            signing_secret="dev-secret",
            rate_limit_per_minute=5000,
        )
        app = create_app(cfg)
        client = TestClient(app)
        key = client.get("/health").json()["bootstrap_api_key"]

        action = {
            "type": "mcp_call",
            "tool": "delete_customer",
            "args": {
                "method": "tools/call",
                "params": {"name": "delete_customer", "arguments": {"id": "1"}},
                "server_id": "internal-crm",
            },
            "metadata": {
                "runtime": {
                    "boundary": True,
                    "surface": "mcp",
                    "mode": "guarded",
                    "pre_execution": True,
                    "gateway": True,
                    "server_id": "internal-crm",
                },
                "mcp": {"server_id": "internal-crm", "method": "tools/call"},
                "provenance_sources": [
                    {
                        "source_type": "mcp_tool_result",
                        "origin": "mcp://public-search/search",
                        "trust_level": "untrusted",
                        "integrity": "unverified",
                        "principal": "public-search",
                    }
                ],
                "provenance_complete": True,
            },
            "agent_name": "mcp-gateway",
            "trace_id": "mcp-cross-server-1",
        }
        resp = client.post(
            "/sdk/guard",
            headers={"x-api-key": key},
            json={"action": action, "payload": action["args"]},
        )
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert detail["decision"]["action"] == "block"
