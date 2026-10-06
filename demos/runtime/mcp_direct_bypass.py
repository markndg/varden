#!/usr/bin/env python3
"""Direct MCP vs gateway-routed coverage reporting."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import varden
from varden.runtime.coverage import ENFORCED, NOT_ROUTED, get_coverage_registry
from varden.runtime.mcp_gateway import (
    register_mcp_gateway_coverage,
    release_mcp_gateway_coverage,
    wrap_mcp_config,
)


def main() -> int:
    print("MCP DIRECT BYPASS")
    with TemporaryDirectory() as tmpdir:
        cfg = {"mcpServers": {"public-search": {"command": "python", "args": ["-m", "x"]}}}
        path = Path(tmpdir) / "mcp.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")

        # Direct / discovered — protect locks coverage mode; MCP stays NOT_ROUTED
        # until a live gateway session installs a sealed interceptor probe.
        g = varden.protect(
            mode="guarded",
            emit_attestation=False,
            auto_instrument=True,
            mcp_config=str(path),
            base_url="http://127.0.0.1:9",
            api_key="x",
            fail_mode="open",
        )
        mcp = get_coverage_registry().get("mcp")
        print(f"Direct/discovered: {mcp.status if mcp else None} (expected NOT_ROUTED)")
        direct_ok = mcp is not None and mcp.status == NOT_ROUTED

        # Routed: same registration path as run_stdio_gateway (install_interceptor
        # + live probe). Do not mark(ENFORCED) — that is rejected after mode lock.
        register_mcp_gateway_coverage(server_id="public-search")
        try:
            mcp2 = get_coverage_registry().get("mcp")
            print(f"Gateway-routed: {mcp2.status if mcp2 else None} (expected ENFORCED)")
            routed_ok = mcp2 is not None and mcp2.status == ENFORCED and mcp2.active
            # Live probe must keep ENFORCED under verify while the session is active.
            get_coverage_registry().verify()
            still = get_coverage_registry().get("mcp")
            verify_ok = still is not None and still.status == ENFORCED
        finally:
            release_mcp_gateway_coverage("public-search")

        # After release, probe fails — coverage must not keep a fake ENFORCED claim.
        after = get_coverage_registry().get("mcp")
        print(f"After gateway release: {after.status if after else None} (expected not ENFORCED)")
        released_ok = after is None or after.status != ENFORCED

        wrapped, changes = wrap_mcp_config(cfg)
        print(f"wrap changes: {changes[0]['change']}")
        wrap_ok = "varden.runtime.mcp_gateway" in wrapped["mcpServers"]["public-search"]["args"]

        varden.unpatch_runtime()
        ok = direct_ok and routed_ok and verify_ok and released_ok and wrap_ok
        print("RESULT", "PASS" if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
