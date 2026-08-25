#!/usr/bin/env python3
"""Approval race: exactly one concurrent retry may consume a token."""

from __future__ import annotations

import concurrent.futures
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.runtime.helpers import make_app_client


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        policy = {
            "block": [],
            "require_approval": [{"type": "tool_call", "tool": "needs_approval"}],
            "warn": [],
            "monitor": [],
            "allow": [],
        }
        client, _ = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        action = {
            "type": "tool_call",
            "tool": "needs_approval",
            "args": {"target": "race"},
            "trace_id": "approval-race-trace",
        }
        first = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": action["args"]})
        assert first.status_code == 403
        approval_id = first.json()["detail"]["approval_id"]
        token = client.post(f"/approvals/{approval_id}/approve", headers=headers).json()["token"]

        def retry(_n: int) -> str:
            retry_action = {**action, "metadata": {"approval_token": token}}
            r = client.post("/sdk/guard", headers=headers, json={"action": retry_action, "payload": action["args"]})
            if r.status_code == 200:
                return "success"
            return "rejected"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(retry, [1, 2]))
        successes = results.count("success")
        rejected = results.count("rejected")
        print("APPROVAL RACE")
        print(f"  successes={successes} rejected={rejected} results={results}")
        ok = successes == 1 and rejected == 1
        print("RESULT", "PASS" if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
