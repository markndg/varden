#!/usr/bin/env python3
"""Raw socket loopback — must remain UNCOVERED."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.runtime.coverage import UNCOVERED, get_coverage_registry


def main() -> int:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept():
        conn, _ = srv.accept()
        conn.close()

    threading.Thread(target=_accept, daemon=True).start()
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        s = socket.socket()
        s.connect(("127.0.0.1", port))
        s.close()
        srv.close()
        surf = get_coverage_registry().get("http.raw_sockets")
        print("RAW SOCKET BYPASS")
        print(f"  raw sockets = {surf.status if surf else None}")
        ok = surf is not None and surf.status == UNCOVERED
        print("RESULT", "PASS" if ok else "FAIL")
        varden.unpatch_runtime()
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
