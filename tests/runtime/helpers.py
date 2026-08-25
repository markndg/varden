"""Helpers for runtime boundary tests (not pytest fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig


def make_app_client(tmpdir: str, policy: dict | None = None) -> tuple[TestClient, object]:
    policy_path = Path(tmpdir) / "policy.json"
    doc = policy or {
        "block": [{"type": "tool_call", "tool": "delete_database"}],
        "require_approval": [{"type": "tool_call", "tool": "needs_approval"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    policy_path.write_text(json.dumps(doc), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=20000,
    )
    app = create_app(cfg)
    return TestClient(app), app


def wire_guard_to_app(guard, client: TestClient) -> None:
    """Point SDK httpx client at Starlette TestClient (in-process, no real TCP)."""
    try:
        guard.client._client.close()
    except Exception:
        pass
    guard.client._client = client
    guard.client.base_url = str(client.base_url).rstrip("/")
