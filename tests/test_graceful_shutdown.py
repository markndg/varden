"""SIGINT shutdown of the real ``python -m varden.api`` process.

A test fails if the process has to be killed. Termination by SIGKILL is not
a graceful shutdown.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHUTDOWN_BUDGET_SECONDS = 12.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http(host: str, port: int, path: str, timeout: float = 2.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode("ascii"))
        chunks: list[bytes] = []
        while True:
            part = sock.recv(8192)
            if not part:
                break
            chunks.append(part)
    return b"".join(chunks)


def _wait_ready(port: int, proc: subprocess.Popen, output: list[str], timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"server exited before ready ({proc.returncode}): {''.join(output)[-2000:]}")
        try:
            body = _http("127.0.0.1", port, "/health/live", timeout=1.0)
        except OSError:
            time.sleep(0.15)
            continue
        if b" 200 " in body.split(b"\r\n", 1)[0]:
            return
        time.sleep(0.15)
    pytest.fail(f"server did not become ready: {''.join(output)[-2000:]}")


def _start(tmp_path: Path, extra: dict[str, str]) -> tuple[subprocess.Popen, int, list[str]]:
    port = _free_port()
    policy = tmp_path / "policy.json"
    policy.write_text('{"block":[],"warn":[],"monitor":[],"allow":[]}\n', encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "VARDEN_ENV": "dev",
            "VARDEN_ENABLE_DEV_BOOTSTRAP": "true",
            "VARDEN_HOST": "127.0.0.1",
            "VARDEN_PORT": str(port),
            "VARDEN_DB_PATH": str(tmp_path / "varden.db"),
            "VARDEN_AUTH_DB_PATH": str(tmp_path / "auth.db"),
            "VARDEN_POLICY_FILE": str(policy),
            "VARDEN_CONFIG": "",
            "VARDEN_TI_ENABLED": "false",
            "PYTHONUNBUFFERED": "1",
        }
    )
    env.update(extra)
    output: list[str] = []

    def _pump(stream) -> None:
        for line in stream:
            output.append(line)

    proc = subprocess.Popen(
        [sys.executable, "-m", "varden.api"],
        cwd=str(tmp_path),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    threading.Thread(target=_pump, args=(proc.stdout,), daemon=True).start()
    try:
        _wait_ready(port, proc, output)
    except Exception:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        raise
    return proc, port, output


def _finish(proc: subprocess.Popen, output: list[str]) -> float:
    started = time.monotonic()
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=SHUTDOWN_BUDGET_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        pytest.fail(
            "SIGINT did not stop the process within "
            f"{SHUTDOWN_BUDGET_SECONDS:.0f}s. SIGKILL is not a graceful shutdown.\n"
            f"{''.join(output)[-3000:]}"
        )
    elapsed = time.monotonic() - started
    text = "".join(output)
    assert proc.returncode == 0, f"expected a clean exit, got {proc.returncode}\n{text[-3000:]}"
    assert "Traceback (most recent call last)" not in text
    assert "CancelledError" not in text
    assert "starlette/responses.py" not in text
    return elapsed


def _open_stream(port: int) -> socket.socket:
    health = _http("127.0.0.1", port, "/health").decode("latin1", errors="ignore")
    marker = '"bootstrap_api_key":"'
    start = health.find(marker)
    assert start >= 0, health[-500:]
    token = health[start + len(marker):].split('"', 1)[0]
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(
        (
            f"GET /stream/updates?token={quote(token, safe='')} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Accept: text/event-stream\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii")
    )
    seen = b""
    while b": connected" not in seen:
        part = sock.recv(4096)
        if not part:
            break
        seen += part
        if len(seen) > 65536:
            break
    assert b": connected" in seen, seen[-300:]
    return sock


def test_sigint_with_no_clients(tmp_path: Path):
    proc, _port, output = _start(tmp_path, {})
    elapsed = _finish(proc, output)
    assert elapsed < SHUTDOWN_BUDGET_SECONDS


def test_sigint_during_active_api_request(tmp_path: Path):
    proc, port, output = _start(tmp_path, {})
    holder: list[BaseException | None] = [None]

    def _call() -> None:
        try:
            _http("127.0.0.1", port, "/health", timeout=5)
        except BaseException as exc:  # connection may close as the server exits
            holder[0] = exc

    thread = threading.Thread(target=_call)
    thread.start()
    time.sleep(0.05)
    elapsed = _finish(proc, output)
    thread.join(timeout=5)
    assert elapsed < SHUTDOWN_BUDGET_SECONDS


def test_sigint_with_open_event_stream(tmp_path: Path):
    proc, port, output = _start(tmp_path, {})
    sock = _open_stream(port)
    try:
        elapsed = _finish(proc, output)
    finally:
        sock.close()
    assert elapsed < SHUTDOWN_BUDGET_SECONDS


def test_sigint_with_threat_intelligence_disabled(tmp_path: Path):
    proc, _port, output = _start(tmp_path, {"VARDEN_TI_ENABLED": "false"})
    assert _finish(proc, output) < SHUTDOWN_BUDGET_SECONDS


def test_sigint_with_threat_intelligence_enabled(tmp_path: Path):
    proc, _port, output = _start(
        tmp_path,
        {
            "VARDEN_TI_ENABLED": "true",
            "VARDEN_TI_ATLAS_INTERVAL_SECONDS": "86400",
            "VARDEN_TI_NVD_INTERVAL_SECONDS": "86400",
            "VARDEN_TI_CWE_INTERVAL_SECONDS": "86400",
            "VARDEN_TI_TIMEOUT_SECONDS": "2",
            "VARDEN_TI_MAX_ATTEMPTS": "1",
        },
    )
    assert _finish(proc, output) < SHUTDOWN_BUDGET_SECONDS


def test_sigint_while_source_request_can_be_in_progress(tmp_path: Path):
    proc, _port, output = _start(
        tmp_path,
        {
            "VARDEN_TI_ENABLED": "true",
            "VARDEN_TI_ATLAS_INTERVAL_SECONDS": "1",
            "VARDEN_TI_NVD_INTERVAL_SECONDS": "1",
            "VARDEN_TI_CWE_INTERVAL_SECONDS": "1",
            "VARDEN_TI_TIMEOUT_SECONDS": "2",
            "VARDEN_TI_MAX_ATTEMPTS": "1",
            "VARDEN_TI_BACKOFF_BASE_SECONDS": "0",
            "VARDEN_TI_JITTER_RATIO": "0",
        },
    )
    time.sleep(1.5)
    assert _finish(proc, output) < SHUTDOWN_BUDGET_SECONDS
