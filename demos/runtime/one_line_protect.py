"""One-line protect() demo agent — no custom guards."""

from __future__ import annotations

import os
import subprocess
import sys

import varden

# Product invariant: one line.
varden.protect()

def main() -> int:
    print("--- attempts ---")
    try:
        import requests
        requests.get("https://example.com", timeout=2)
        print("requests GET example.com: attempted (allowed or network error)")
    except varden.VardenBlockedError as exc:
        print("requests blocked:", exc)
    except Exception as exc:
        print("requests error:", type(exc).__name__, exc)

    try:
        subprocess.run(["/usr/bin/true"], check=False)
        print("subprocess /usr/bin/true: completed under boundary")
    except varden.VardenBlockedError as exc:
        print("subprocess blocked:", exc)

    try:
        home = os.path.expanduser("~/.ssh/id_rsa")
        if os.path.exists(home):
            open(home, "r").close()
            print("secret file open: completed (policy dependent)")
        else:
            print("secret file open: path not present; skipped")
    except varden.VardenBlockedError as exc:
        print("filesystem blocked:", exc)

    from varden.runtime.coverage import get_coverage_registry
    print("--- coverage ---")
    print("\n".join(get_coverage_registry().startup_log_lines()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
