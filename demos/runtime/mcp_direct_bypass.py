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
from varden.runtime.mcp_gateway import wrap_mcp_config


def main() -> int:
    print("MCP DIRECT BYPASS")
    with TemporaryDirectory() as tmpdir:
        cfg = {"mcpServers": {"public-search": {"command": "python", "args": ["-m", "x"]}}}
        path = Path(tmpdir) / "mcp.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")

        # Direct / discovered
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

        # Routed mark (as gateway would)
        get_coverage_registry().mark("mcp", status=ENFORCED, interceptor="varden.runtime.mcp_gateway", active=True)
        mcp2 = get_coverage_registry().get("mcp")
        print(f"Gateway-routed: {mcp2.status if mcp2 else None} (expected ENFORCED)")
        routed_ok = mcp2 is not None and mcp2.status == ENFORCED

        wrapped, changes = wrap_mcp_config(cfg)
        print(f"wrap changes: {changes[0]['change']}")
        wrap_ok = "varden.runtime.mcp_gateway" in wrapped["mcpServers"]["public-search"]["args"]

        varden.unpatch_runtime()
        ok = direct_ok and routed_ok and wrap_ok
        print("RESULT", "PASS" if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
