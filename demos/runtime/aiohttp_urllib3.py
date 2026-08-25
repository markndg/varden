#!/usr/bin/env python3
"""aiohttp / urllib3-direct coverage honesty (loopback only)."""

from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _start_server() -> tuple[HTTPServer, int]:
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            return

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def main() -> int:
    from tests.runtime.helpers import make_app_client, wire_guard_to_app
    import varden
    from varden.runtime.coverage import get_coverage_registry

    srv, port = _start_server()
    url = f"http://127.0.0.1:{port}/"
    print("AIOHTTP / URLLIB3 DIRECT")

    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        reg = get_coverage_registry()

        aio_status = (reg.get("http.aiohttp").status if reg.get("http.aiohttp") else "UNCOVERED")
        u3_status = (reg.get("http.urllib3").status if reg.get("http.urllib3") else "UNCOVERED")
        print(f"  HTTP / aiohttp        {aio_status}")
        print(f"  HTTP / urllib3-direct {u3_status}")

        # Attempt urllib3 direct if installed
        try:
            import urllib3

            http = urllib3.PoolManager()
            r = http.request("GET", url, timeout=2.0)
            print(f"  urllib3 direct call completed status={r.status} (not intercepted)")
            u3_bypassed = True
        except ImportError:
            print("  urllib3 not installed — skipped live call")
            u3_bypassed = True
        except varden.VardenBlockedError:
            print("  urllib3 direct BLOCKED (unexpected if uncovered)")
            u3_bypassed = False
        except Exception as exc:
            print(f"  urllib3 direct error: {exc}")
            u3_bypassed = True

        try:
            import aiohttp  # noqa: F401

            print("  aiohttp installed — coverage remains observational/uncovered without interceptor")
        except ImportError:
            print("  aiohttp not installed")

        ok = aio_status in {"UNCOVERED", "UNSUPPORTED", "PARTIAL"} and u3_status in {
            "UNCOVERED",
            "UNSUPPORTED",
            "PARTIAL",
        } and u3_bypassed
        print("RESULT", "PASS" if ok else "FAIL")
        varden.unpatch_runtime()
        srv.shutdown()
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
