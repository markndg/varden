#!/usr/bin/env python3
"""Approval scope binding: exact success; mismatch/replay/expiry fail.

Also simulates token theft: a stolen token still cannot broaden scope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.runtime.helpers import make_app_client
from varden.runtime.approvals import ApprovalStore


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        policy = {
            "require_approval": [
                {"type": "tool_call", "tool": "read_file"},
                {"type": "tool_call", "tool": "write_file"},
            ],
            "block": [],
            "warn": [],
            "monitor": [],
            "allow": [],
        }
        client, _ = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        base = {
            "type": "tool_call",
            "tool": "read_file",
            "args": {"path": "/tmp/demo/private.txt"},
            "trace_id": "T1",
            "metadata": {
                "authority": {"required": ["READ_PRIVATE"], "resource": "/tmp/demo/private.txt"}
            },
        }

        def issue(action):
            r = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": action["args"]})
            assert r.status_code == 403, r.text
            aid = r.json()["detail"]["approval_id"]
            return client.post(f"/approvals/{aid}/approve", headers=headers).json()["token"]

        def try_token(label, action, token):
            a = {**action, "metadata": {**(action.get("metadata") or {}), "approval_token": token}}
            r = client.post("/sdk/guard", headers=headers, json={"action": a, "payload": a["args"]})
            status = "success" if r.status_code == 200 else "fail"
            print(f"  {label}: {status.upper()}")
            return status

        print("APPROVAL SCOPE")
        # Fresh token per mismatch so we test scope binding, not just consumption.
        results = []
        t1 = issue(base)
        results.append(try_token("1 exact retry", base, t1))

        t2 = issue(base)
        results.append(
            try_token("2 different file", {**base, "args": {"path": "/tmp/demo/other.txt"}}, t2)
        )

        t3 = issue(base)
        results.append(try_token("3 different action", {**base, "tool": "write_file"}, t3))

        # Authority binding is enforced inside verify_and_consume. HTTP /sdk/guard
        # re-derives authority from classification, so test the store contract directly.
        t4 = issue(base)
        store = ApprovalStore(str(Path(tmpdir) / "varden.db"), signing_secret="dev-secret")
        try:
            store.verify_and_consume(
                tenant_id="default",
                token=t4,
                action={
                    **base,
                    "metadata": {"authority": {"required": ["ADMIN"], "resource": "/tmp/demo/private.txt"}},
                },
            )
            print("  4 different authority: SUCCESS")
            results.append("success")
        except ValueError:
            print("  4 different authority: FAIL")
            results.append("fail")

        t5 = issue(base)
        results.append(try_token("5 different trace", {**base, "trace_id": "T2"}, t5))

        t6 = issue(base)
        results.append(try_token("6 exact then replay", base, t6))
        results.append(try_token("7 replay exact", base, t6))

        action_e = {**base, "args": {"path": "/tmp/demo/exp.txt"}, "trace_id": "T-exp"}
        tok_e = issue(action_e)
        payload = json.loads(tok_e)
        payload["claims"]["expires_at"] = time.time() - 5
        body = json.dumps(payload["claims"], sort_keys=True, separators=(",", ":"), default=str)
        payload["sig"] = hmac.new(b"dev-secret", body.encode(), hashlib.sha256).hexdigest()
        expired = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        try:
            store.verify_and_consume(tenant_id="default", token=expired, action=action_e)
            print("  8 expired token: SUCCESS")
            results.append("success")
        except ValueError:
            print("  8 expired token: FAIL")
            results.append("fail")

        # Theft: stolen token cannot broaden to another file (scope is primary control).
        stolen = issue(base)
        theft = try_token(
            "9 theft→different file",
            {**base, "args": {"path": "/tmp/demo/stolen-target.txt"}},
            stolen,
        )
        results.append(theft)

        expected = [
            "success",  # 1
            "fail",  # 2
            "fail",  # 3
            "fail",  # 4
            "fail",  # 5
            "success",  # 6
            "fail",  # 7
            "fail",  # 8
            "fail",  # 9
        ]
        ok = results == expected
        print("RESULT", "PASS" if ok else "FAIL")
        if not ok:
            print(f"  got={results}")
            print(f"  want={expected}")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
