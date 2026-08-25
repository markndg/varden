#!/usr/bin/env python3
"""Strict mode downgrade attempt after protect() must not silently succeed."""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main() -> int:
    from tests.runtime.helpers import make_app_client, wire_guard_to_app
    import varden
    from varden.runtime.coverage import get_coverage_registry

    print("STRICT DOWNGRADE ATTACK")
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(
            mode="strict",
            fail_mode="closed",
            base_url="http://testserver",
            api_key=key,
            emit_attestation=False,
            allow_uncovered=["mcp", "http.raw_sockets", "http.aiohttp", "http.urllib3"],
        )
        wire_guard_to_app(guard, client)
        reg = get_coverage_registry()
        before_mode = reg.attestation().get("mode")
        before_fail = reg.attestation().get("fail_mode")
        print(f"  before mode={before_mode} fail_mode={before_fail}")

        locked = False
        try:
            reg.set_session(mode="observe", fail_mode="open", lock_mode=False)
        except RuntimeError as exc:
            locked = True
            print(f"  downgrade rejected: {exc}")

        # Also try mutating guard attributes (must not change locked registry session).
        try:
            guard.product_mode = "observe"
            guard.fail_mode = "open"
        except Exception:
            pass
        after = reg.attestation()
        print(f"  after  mode={after.get('mode')} fail_mode={after.get('fail_mode')}")

        ok = locked and after.get("mode") == "strict" and after.get("fail_mode") == "closed"
        print("RESULT", "PASS" if ok else "FAIL")
        varden.unpatch_runtime()
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
