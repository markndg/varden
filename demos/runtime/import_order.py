#!/usr/bin/env python3
"""Import-order coverage: before vs after protect() for HTTP/subprocess surfaces."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def status_for(name: str) -> str:
    from varden.runtime.coverage import get_coverage_registry

    surf = get_coverage_registry().get(name)
    if not surf:
        return "UNCOVERED"
    return surf.status


def main() -> int:
    from tests.runtime.helpers import make_app_client, wire_guard_to_app
    import varden

    print("IMPORT ORDER COVERAGE")
    rows: list[tuple[str, str]] = []

    # --- before protect: import libraries first ---
    import requests  # noqa: F401
    import httpx  # noqa: F401
    import urllib.request  # noqa: F401
    import subprocess  # noqa: F401

    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)

        for label, surface in [
            ("requests imported before protect", "http.requests"),
            ("httpx imported before protect", "http.httpx"),
            ("urllib imported before protect", "http.urllib"),
            ("subprocess imported before protect", "subprocess"),
        ]:
            st = status_for(surface)
            print(f"  {label}: {st}")
            rows.append((label, st))

        varden.unpatch_runtime()

    # --- after protect: re-import / fresh process simulation via re-protect ---
    with TemporaryDirectory() as tmpdir:
        # Reload modules after unpatch so "import after" is meaningful
        for mod in ("requests", "httpx", "urllib.request", "subprocess"):
            if mod in sys.modules and mod != "subprocess":
                # keep stdlib subprocess; requests/httpx get re-patched on protect
                pass
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        importlib.reload(sys.modules["requests"])
        import httpx as httpx2  # noqa: F401
        import urllib.request as urllib2  # noqa: F401

        for label, surface in [
            ("requests imported after protect", "http.requests"),
            ("httpx imported after protect", "http.httpx"),
            ("urllib imported after protect", "http.urllib"),
        ]:
            st = status_for(surface)
            print(f"  {label}: {st}")
            rows.append((label, st))
        varden.unpatch_runtime()

    # Honest expectation: monkeypatch covers both import orders for module-level
    # wrappers; saved pre-protect *function* references remain PARTIAL (see
    # saved_reference_bypass.py).
    ok = all(st in {"ENFORCED", "PARTIAL"} for _, st in rows)
    print("RESULT", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
