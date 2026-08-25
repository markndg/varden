"""Lightweight median/p95/p99 overhead probe for the runtime boundary."""

from __future__ import annotations

import statistics
import time
from tempfile import TemporaryDirectory

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def _bench(fn, n: int = 25) -> dict[str, float]:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {
        "median_ms": statistics.median(samples),
        "p95_ms": _pct(samples, 95),
        "p99_ms": _pct(samples, 99),
    }


def test_boundary_overhead_report():
    with TemporaryDirectory() as tmpdir:
        policy = {
            "block": [{"type": "http_request", "field:url": {"contains": "block.example"}}],
            "warn": [],
            "monitor": [{"type": "http_request"}],
            "allow": [],
        }
        client, app = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)

            def plain():
                return 1 + 1

            def allow_http():
                guard.guarded_action(
                    type="http_request",
                    tool="requests",
                    url="https://example.com/ok",
                    method="GET",
                    args={},
                    payload={},
                )

            def block_http():
                try:
                    guard.guarded_action(
                        type="http_request",
                        tool="requests",
                        url="https://block.example/x",
                        method="POST",
                        args={"body": {"a": 1}},
                        payload={"a": 1},
                    )
                except varden.VardenBlockedError:
                    return

            report = {
                "plain": _bench(plain),
                "guarded_allowed_http": _bench(allow_http),
                "guarded_blocked_http": _bench(block_http),
            }
            print("RUNTIME_BOUNDARY_PERF", report)
            assert report["guarded_allowed_http"]["median_ms"] >= 0
        finally:
            varden.unpatch_runtime()
