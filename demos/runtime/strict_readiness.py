#!/usr/bin/env python3
"""Strict readiness: discovered MCP NOT_ROUTED vs exceptions."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import varden
from varden.runtime.coverage import get_coverage_registry


def main() -> int:
    print("STRICT READINESS")
    results = []

    # Scenario A: no MCP config
    with TemporaryDirectory() as tmpdir:
        cwd = Path(tmpdir)
        # empty dir — no mcp.json
        import os

        os.chdir(cwd)
        try:
            g = varden.protect(
                mode="strict",
                auto_instrument=True,
                emit_attestation=False,
                fail_mode="closed",
                base_url="http://127.0.0.1:9",
                api_key="x",
            )
            # Will fail closed on network but activate may succeed if http/subprocess patches OK
            # Actually missing control plane with fail_mode closed still activates; missing coverage for http?
            # http patches mark ENFORCED without needing server.
            ready = get_coverage_registry().strict_readiness()
            print(f"Scenario A (no MCP): {ready['status']}")
            results.append(ready["status"] in {"READY", "READY WITH EXCEPTIONS"})
            varden.unpatch_runtime()
        except RuntimeError as exc:
            print(f"Scenario A raised: {exc}")
            results.append(False)
            varden.unpatch_runtime()

    # Scenario B: MCP config discovered, not routed
    with TemporaryDirectory() as tmpdir:
        cwd = Path(tmpdir)
        (cwd / "mcp.json").write_text(
            json.dumps({"mcpServers": {"public-search": {"command": "python"}, "internal-crm": {"command": "python"}}}),
            encoding="utf-8",
        )
        import os

        os.chdir(cwd)
        try:
            varden.protect(
                mode="strict",
                auto_instrument=True,
                emit_attestation=False,
                mcp_config=str(cwd / "mcp.json"),
                base_url="http://127.0.0.1:9",
                api_key="x",
            )
            print("Scenario B: READY (unexpected)")
            results.append(False)
            varden.unpatch_runtime()
        except RuntimeError as exc:
            print("Scenario B: STRICT NOT READY")
            print(f"  {exc}")
            results.append("NOT_ROUTED" in str(exc) or "mcp" in str(exc).lower() or "discovered" in str(exc).lower())
            varden.unpatch_runtime()

    # Scenario C: explicit exception
    with TemporaryDirectory() as tmpdir:
        cwd = Path(tmpdir)
        (cwd / "mcp.json").write_text(
            json.dumps({"mcpServers": {"a": {"command": "python"}}}),
            encoding="utf-8",
        )
        import os

        os.chdir(cwd)
        try:
            varden.protect(
                mode="strict",
                auto_instrument=True,
                emit_attestation=False,
                mcp_config=str(cwd / "mcp.json"),
                allow_uncovered=["mcp"],
                base_url="http://127.0.0.1:9",
                api_key="x",
            )
            ready = get_coverage_registry().strict_readiness()
            print(f"Scenario C (allow_uncovered=mcp): {ready['status']}")
            print(f"  Accepted: {ready.get('accepted_exceptions')}")
            results.append(ready["status"] == "READY WITH EXCEPTIONS" and "mcp" in ready.get("accepted_exceptions", []))
            varden.unpatch_runtime()
        except RuntimeError as exc:
            print(f"Scenario C raised: {exc}")
            results.append(False)
            varden.unpatch_runtime()

    ok = all(results)
    print("RESULT", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
