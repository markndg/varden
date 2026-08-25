#!/usr/bin/env python3
"""Saved pre-protect Popen reference bypass — honest limitation."""

from __future__ import annotations

import sys
from pathlib import Path
from subprocess import Popen as saved_popen
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.runtime.coverage import get_coverage_registry


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        proc = saved_popen(["/usr/bin/true"], stdout=-1, stderr=-1)
        proc.wait()
        print("BYPASS CONFIRMED")
        print("Saved pre-protect reference bypasses Python monkeypatch.")
        print("")
        print("Coverage:")
        print("Subprocess = ENFORCED (active patch) but saved refs bypass")
        print("Reason:")
        print("saved references cannot be retroactively intercepted")
        print("")
        print("Distinction:")
        print("  protect() runtime monkeypatch coverage ≠ session-level process controls")
        print("  Use `varden session --strict` for PATH/shim layer (still not OS sandbox).")
        sub = get_coverage_registry().get("subprocess")
        print(f"  limitations: {sub.limitations if sub else []}")
        varden.unpatch_runtime()
        print("RESULT PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
