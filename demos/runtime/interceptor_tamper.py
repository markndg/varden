#!/usr/bin/env python3
"""Interceptor tamper: coverage must downgrade after monkeypatch restoration."""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import requests
import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.runtime.coverage import ENFORCED, UNCOVERED, get_coverage_registry


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        original = requests.sessions.Session.request
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        reg = get_coverage_registry()
        before_status = reg.get("http.requests").status if reg.get("http.requests") else None
        print("INTERCEPTOR TAMPER")
        print(f"  before: http.requests={before_status}")
        requests.sessions.Session.request = original
        result = reg.verify()
        after_status = reg.get("http.requests").status if reg.get("http.requests") else None
        print(f"  after verify: http.requests={after_status}")
        print(f"  changes={result.get('changes')}")
        ok = before_status == ENFORCED and after_status == UNCOVERED
        print("RESULT", "PASS" if ok else "FAIL")
        varden.unpatch_runtime()
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
