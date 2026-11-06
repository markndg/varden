"""Isolated Varden process for one demonstration run.

Uses the real ASGI application and ``POST /sdk/guard``. Nothing here invents
a decision. The disposable directory is removed on close.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig


def varden_version() -> str:
    text = (Path(__file__).resolve().parents[3] / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "unknown"


def git_commit() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(Path(__file__).resolve().parents[3]),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return "unknown"
    return (proc.stdout or "unknown").strip() or "unknown"


class IsolatedVarden:
    def __init__(self, policy: dict[str, Any], *, env: dict[str, str] | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="varden-gauntlet-"))
        self.policy = policy
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        self._env_previous: dict[str, str | None] = {}
        for key, value in (env or {}).items():
            self._env_previous[key] = os.environ.get(key)
            os.environ[key] = value
        config = AppConfig(
            env="dev",
            db_path=str(self.root / "varden.db"),
            auth_db_path=str(self.root / "auth.db"),
            policy_file=str(policy_path),
            signing_secret="dev-secret",
            rate_limit_per_minute=10_000,
            enable_dev_bootstrap=True,
        )
        self.client = TestClient(create_app(config))
        bootstrap = self.client.get("/sdk/bootstrap")
        if bootstrap.status_code != 200:
            raise RuntimeError(f"bootstrap failed: {bootstrap.status_code} {bootstrap.text[:200]}")
        self.api_key = bootstrap.json().get("bootstrap_api_key")
        if not self.api_key:
            raise RuntimeError("bootstrap did not return an API key")

    def guard(self, action: dict[str, Any], payload: Any = None) -> dict[str, Any]:
        response = self.client.post(
            "/sdk/guard",
            headers={"x-api-key": self.api_key},
            json={"action": action, "payload": payload if payload is not None else {}},
        )
        body: dict[str, Any]
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {"raw": parsed}
        except Exception:
            body = {"raw": response.text[:500]}
        detail = body.get("detail")
        if isinstance(detail, dict) and isinstance(detail.get("decision"), dict):
            body = detail
        decision = body.get("decision") if isinstance(body.get("decision"), dict) else {}
        return {
            "http_status": response.status_code,
            "decision": str(decision.get("action") or decision.get("effective_action") or ""),
            "reason": str(decision.get("reason") or ""),
            "event_id": body.get("event_id"),
            "body": body,
            "telemetry_present": bool(decision.get("action") or decision.get("effective_action")),
        }

    def close(self) -> None:
        for key, previous in self._env_previous.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        self.client.close()
        shutil.rmtree(self.root, ignore_errors=True)
