#!/usr/bin/env python3
"""Control-plane outage: guarded/strict fail closed."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import varden


def main() -> int:
    print("CONTROL PLANE OUTAGE")
    # Unreachable control plane + fail closed
    guard = varden.protect(
        base_url="http://127.0.0.1:1",
        api_key="x",
        mode="guarded",
        fail_mode="closed",
        emit_attestation=False,
        auto_instrument=True,
    )
    blocked = False
    try:
        guard.guarded_action(
            type="http_request",
            tool="requests",
            url="https://example.com",
            method="GET",
            args={},
            payload={},
        )
        print("  guarded: ALLOWED (unexpected)")
    except Exception as exc:
        blocked = True
        print(f"  guarded: BLOCKED ({type(exc).__name__})")
    varden.unpatch_runtime()

    # Explicit fail-open warns and may allow
    guard2 = varden.protect(
        base_url="http://127.0.0.1:1",
        api_key="x",
        mode="guarded",
        fail_mode="open",
        emit_attestation=False,
        auto_instrument=False,
    )
    result = guard2.guarded_action(
        type="http_request",
        tool="requests",
        url="https://example.com",
        method="GET",
        args={},
        payload={},
    )
    print(f"  fail-open: result={result} (may be None — not claimed enforced)")
    varden.unpatch_runtime()
    ok = blocked and result is None
    print("RESULT", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
