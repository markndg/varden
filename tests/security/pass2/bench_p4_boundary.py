"""Local phase 4 overhead measurements.

Not collected by pytest. Prints microseconds per operation. These numbers are
one machine, one process, and a stubbed control plane. They are not a claim
about production latency behind a real policy service.
"""

from __future__ import annotations

import os
import socket
import statistics
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import varden
from varden.destination_binding import hook_installed, resolver_scope
from varden.runtime.coverage import get_coverage_registry
from varden.runtime.filesystem import canonicalize_path, classify_path


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def _stats(samples: list[float]) -> str:
    ordered = sorted(samples)
    median = statistics.median(ordered)
    p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
    return f"median {median * 1e6:8.1f} us   p95 {p95 * 1e6:8.1f} us   n={len(samples)}"


def _time(fn, n: int) -> list[float]:
    for _ in range(10):
        fn()
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return samples


def main() -> None:
    varden.unpatch_runtime()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/bench"
    host_url = f"http://pinned.bench:{port}/bench"

    def raw_open():
        with open(__file__, "rb") as handle:
            handle.read(1)

    print("unpatched open     ", _stats(_time(raw_open, 200)))
    workspace = os.getcwd()

    def canon():
        canonicalize_path(__file__, workspace=workspace)

    def classify():
        classify_path(__file__, workspace=workspace, mode="rb")

    print("canonicalize_path  ", _stats(_time(canon, 200)))
    print("classify_path      ", _stats(_time(classify, 200)))

    raw_session = requests.Session()
    raw_session.trust_env = False

    def raw_http():
        response = raw_session.get(url, timeout=2)
        response.close()

    print("unpatched requests ", _stats(_time(raw_http, 50)))

    guard = varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        mode="guarded",
        fail_mode="closed",
    )

    class _Result:
        blocked = False
        decision = {"action": "allow"}
        action = {}
        event_id = None

    def post(target, **kwargs):
        class _Resp:
            status_code = 200
            headers = {"content-type": "application/json"}
            text = "{}"

            def json(self):
                return {"decision": {"action": "allow"}, "action": {}, "event_id": 1}

            def raise_for_status(self):
                return None

        return _Resp()

    guard.client._client.post = post
    guard.client.guard = lambda payload: _Result()

    print("activation already done; measuring steady state")
    print("hook installed     ", hook_installed())

    def guarded_call():
        guard.guarded_action(type="tool_call", tool="bench", args={"n": 1})

    print("guarded_action     ", _stats(_time(guarded_call, 200)))

    def verify():
        get_coverage_registry().verify()

    print("coverage verify    ", _stats(_time(verify, 200)))

    def patched_open():
        with open(__file__, "rb") as handle:
            handle.read(1)

    print("patched open       ", _stats(_time(patched_open, 200)))

    session = requests.Session()
    session.trust_env = False

    def patched_literal():
        response = session.get(url, timeout=2)
        response.close()

    print("patched literal IP ", _stats(_time(patched_literal, 40)))

    def resolver(host, _port):
        if host == "pinned.bench":
            return ["127.0.0.1"]
        raise OSError("unresolved")

    def patched_pinned():
        response = session.get(host_url, timeout=2)
        response.close()

    with resolver_scope(resolver):
        print("patched pinned host", _stats(_time(patched_pinned, 40)))

    def lookup():
        socket.getaddrinfo("localhost", 9, socket.AF_INET, socket.SOCK_STREAM)

    print("getaddrinfo no pin ", _stats(_time(lookup, 100)))

    varden.unpatch_runtime()
    print("getaddrinfo after  ", _stats(_time(lookup, 100)))

    samples = []
    for _ in range(5):
        start = time.perf_counter()
        again = varden.protect(
            base_url="http://testserver",
            api_key="k",
            emit_attestation=False,
            mode="guarded",
            fail_mode="closed",
        )
        samples.append(time.perf_counter() - start)
        again.client.guard = lambda payload: _Result()
        varden.unpatch_runtime()
    print("protect+unpatch    ", _stats(samples))

    held = varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        mode="guarded",
        fail_mode="closed",
    )
    repeat = []
    for _ in range(20):
        start = time.perf_counter()
        try:
            varden.protect(
                base_url="http://testserver",
                api_key="k",
                emit_attestation=False,
                mode="observe",
                fail_mode="open",
            )
        except RuntimeError:
            repeat.append(time.perf_counter() - start)
    print("repeat downgrade   ", _stats(repeat))
    del held
    varden.unpatch_runtime()
    server.shutdown()


if __name__ == "__main__":
    main()
