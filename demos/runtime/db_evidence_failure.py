#!/usr/bin/env python3
"""DB evidence failure vs policy-decision failure — explicit semantics."""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main() -> int:
    from tests.runtime.helpers import make_app_client
    from varden.stores import EventStore

    print("DB EVIDENCE vs DECISION FAILURE")
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(
            tmpdir,
            policy={
                "block": [{"type": "tool_call", "tool": "must_block"}],
                "require_approval": [],
                "warn": [],
                "monitor": [],
                "allow": [],
            },
        )
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}

        action_ok = {"type": "tool_call", "tool": "harmless", "args": {}, "trace_id": "db-1"}
        with patch.object(EventStore, "log", side_effect=RuntimeError("db down")):
            r1 = client.post("/sdk/guard", headers=headers, json={"action": action_ok, "payload": {}})
        detail1 = r1.json().get("detail") if r1.status_code >= 400 else r1.json()
        print(f"  decision allow + DB fail: status={r1.status_code}")
        print(f"    decision={(detail1 or {}).get('decision', {}).get('action')}")
        print(f"    audit_persistence_failed={(detail1 or {}).get('audit_persistence_failed')}")
        case1 = (
            r1.status_code == 503
            and (detail1 or {}).get("decision", {}).get("action") == "allow"
            and (detail1 or {}).get("audit_persistence_failed") is True
        )

        action_block = {"type": "tool_call", "tool": "must_block", "args": {}, "trace_id": "db-2"}
        with patch.object(EventStore, "log", side_effect=RuntimeError("db down")):
            r2 = client.post("/sdk/guard", headers=headers, json={"action": action_block, "payload": {}})
        detail2 = r2.json().get("detail") if r2.status_code >= 400 else r2.json()
        print(f"  decision block + DB fail: status={r2.status_code}")
        print(f"    decision={(detail2 or {}).get('decision', {}).get('action')}")
        case2 = r2.status_code == 403 and (detail2 or {}).get("decision", {}).get("action") == "block"

        print("")
        print("Semantics:")
        print("  policy decision unavailable → fail closed (see control_plane_outage)")
        print("  allow + audit fail → 503 (decision preserved, not silent success)")
        print("  block + audit fail → 403 (block wins; never converts to allow)")
        ok = case1 and case2
        print("RESULT", "PASS" if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
