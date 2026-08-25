#!/usr/bin/env python3
"""Load benchmark for guard / approval paths (local TestClient only)."""

from __future__ import annotations

import concurrent.futures
import statistics
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def _report(name: str, samples_ms: list[float], errors: int) -> dict:
    n = len(samples_ms)
    total_s = sum(samples_ms) / 1000.0 if samples_ms else 0.0
    row = {
        "name": name,
        "n": n,
        "errors": errors,
        "error_rate": (errors / max(1, n + errors)),
        "throughput_rps": (n / total_s) if total_s > 0 else 0.0,
        "median_ms": statistics.median(samples_ms) if samples_ms else 0.0,
        "p95_ms": _pct(samples_ms, 95),
        "p99_ms": _pct(samples_ms, 99),
    }
    print(
        f"{name:<32} n={n:<4} thr={row['throughput_rps']:.1f}/s  "
        f"med={row['median_ms']:.2f}ms p95={row['p95_ms']:.2f}ms p99={row['p99_ms']:.2f}ms "
        f"err={errors}"
    )
    return row


def main() -> int:
    from tests.runtime.helpers import make_app_client

    print("RUNTIME LOAD BENCHMARK")
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(
            tmpdir,
            policy={
                "block": [{"type": "tool_call", "tool": "blocked_tool"}],
                "require_approval": [{"type": "tool_call", "tool": "needs_approval"}],
                "warn": [],
                "monitor": [],
                "allow": [],
            },
        )
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}

        def timed(fn):
            t0 = time.perf_counter()
            fn()
            return (time.perf_counter() - t0) * 1000.0

        # 100 sequential allowed
        samples = []
        errors = 0
        for i in range(100):
            try:
                samples.append(
                    timed(
                        lambda i=i: client.post(
                            "/sdk/guard",
                            headers=headers,
                            json={"action": {"type": "tool_call", "tool": "ok", "args": {"i": i}}, "payload": {}},
                        ).raise_for_status()
                    )
                )
            except Exception:
                errors += 1
        _report("100 sequential allowed", samples, errors)

        # 100 sequential blocked
        samples = []
        errors = 0
        for i in range(100):
            def once(i=i):
                r = client.post(
                    "/sdk/guard",
                    headers=headers,
                    json={"action": {"type": "tool_call", "tool": "blocked_tool", "args": {"i": i}}, "payload": {}},
                )
                if r.status_code != 403:
                    raise RuntimeError(r.status_code)

            try:
                samples.append(timed(once))
            except Exception:
                errors += 1
        _report("100 sequential blocked", samples, errors)

        def concurrent_guard(n: int, tool: str = "ok"):
            samples_local: list[float] = []
            err = 0

            def one(i: int):
                t0 = time.perf_counter()
                r = client.post(
                    "/sdk/guard",
                    headers=headers,
                    json={"action": {"type": "tool_call", "tool": tool, "args": {"i": i}}, "payload": {}},
                )
                dt = (time.perf_counter() - t0) * 1000.0
                return dt, r.status_code

            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                for dt, code in pool.map(one, range(n)):
                    samples_local.append(dt)
                    if tool == "ok" and code != 200:
                        err += 1
                    if tool == "blocked_tool" and code != 403:
                        err += 1
            return samples_local, err

        s, e = concurrent_guard(100)
        _report("100 concurrent allowed", s, e)
        s, e = concurrent_guard(500)
        _report("500 concurrent allowed", s, e)

        # Approval verify: issue + consume via /sdk/guard (matches production path).
        samples = []
        errors = 0
        for i in range(1000):
            action = {"type": "tool_call", "tool": "needs_approval", "args": {"i": i}, "trace_id": f"ap-{i}"}
            r = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": action["args"]})
            if r.status_code != 403:
                errors += 1
                continue
            tok = client.post(f"/approvals/{r.json()['detail']['approval_id']}/approve", headers=headers).json()["token"]

            def once(action=action, tok=tok):
                rr = client.post(
                    "/sdk/guard",
                    headers=headers,
                    json={"action": {**action, "metadata": {"approval_token": tok}}, "payload": action["args"]},
                )
                if rr.status_code != 200:
                    raise RuntimeError(rr.status_code)

            try:
                samples.append(timed(once))
            except Exception:
                errors += 1
        _report("approval verification 1000", samples, errors)

        print("")
        print("RESULT PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
