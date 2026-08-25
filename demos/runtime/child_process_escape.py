#!/usr/bin/env python3
"""Child process escape: network from a child is outside Python monkeypatches."""

from __future__ import annotations

import socket
import subprocess
import sys
import textwrap
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main() -> int:
    from tests.runtime.helpers import make_app_client, wire_guard_to_app
    import varden
    from varden.runtime.coverage import get_coverage_registry

    print("CHILD PROCESS ESCAPE")
    # Local TCP listener
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    child_script = textwrap.dedent(
        f"""
        import socket
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", {port}))
        s.sendall(b"escape")
        s.close()
        print("CHILD_CONNECTED")
        """
    )

    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)

        # Parent protect() does not wrap the child's interpreter.
        proc = subprocess.run(
            [sys.executable, "-c", child_script],
            capture_output=True,
            text=True,
            timeout=5,
        )
        conn, _ = srv.accept()
        data = conn.recv(64)
        conn.close()
        srv.close()

        reg = get_coverage_registry()
        raw = reg.get("http.raw_sockets")
        print(f"  child stdout: {(proc.stdout or '').strip()}")
        print(f"  child connected bytes: {data!r}")
        print(f"  child process syscall coverage = {(raw.status if raw else 'UNCOVERED')}")
        print("")
        print("  Note: varden session --strict PATH/proxy wrappers may catch some")
        print("  child HTTP paths, but raw TCP from a new interpreter is outside")
        print("  protect() monkeypatch coverage.")
        print("")
        print("  Distinction:")
        print("    protect() runtime monkeypatch coverage  → this process only")
        print("    session-level process controls          → optional outer boundary")

        ok = data == b"escape" and (raw is None or raw.status in {"UNCOVERED", "PARTIAL", "UNSUPPORTED"})
        print("RESULT", "PASS" if ok else "FAIL")
        varden.unpatch_runtime()
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
