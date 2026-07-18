"""Pre-parse request-body size enforcement (docs/web-shield-hardening-review.md #8).

Covers both the standalone ASGI middleware (`varden/middleware.py`) against a
minimal fake downstream app -- so we can prove the downstream app is never
invoked and that oversized streaming bodies are rejected without reading the
whole thing -- and integration-level behaviour through the real Web Shield
API surface.
"""

import asyncio
import json
from functools import wraps
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.middleware import PAYLOAD_TOO_LARGE_ERROR_CODE, RequestBodySizeLimitMiddleware


def _cfg(tmpdir: str, **overrides) -> AppConfig:
    policy_path = Path(tmpdir) / "policy.json"
    policy_path.write_text(
        json.dumps({"block": [], "require_approval": [], "sanitise": [], "warn": [], "monitor": [], "allow": []}),
        encoding="utf-8",
    )
    defaults = dict(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret-" + tmpdir,
        rate_limit_per_minute=1000,
        read_rate_limit_per_minute=1000,
        write_rate_limit_per_minute=1000,
        ingest_rate_limit_per_minute=1000,
    )
    defaults.update(overrides)
    return AppConfig(**defaults)


def _client(tmpdir: str, **overrides) -> TestClient:
    return TestClient(create_app(_cfg(tmpdir, **overrides)))


def _bootstrap_headers(client: TestClient) -> dict:
    key = client.get("/health").json()["bootstrap_api_key"]
    return {"x-api-key": key}


BENIGN_TOOL = {"name": "get_weather", "description": "Get the current weather for a city."}


def async_test(fn):
    """Runs an async test body with plain ``asyncio.run`` so these unit
    tests don't need to pull in the ``pytest-asyncio`` plugin just for a
    handful of coroutine-based ASGI middleware tests."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        asyncio.run(fn(*args, **kwargs))

    return wrapper


# --------------------------------------------------------------------------
# Unit-level: the middleware in isolation, against a minimal fake app.
# --------------------------------------------------------------------------


class _RecordingApp:
    """Minimal ASGI app that records whether/how it was invoked and echoes
    back the concatenated body it received as JSON, so tests can assert both
    on the HTTP response *and* on whether the downstream app ever ran."""

    def __init__(self):
        self.invocations = 0
        self.received_bytes = b""

    async def __call__(self, scope, receive, send):
        self.invocations += 1
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            body += message.get("body") or b""
            if not message.get("more_body", False):
                break
        self.received_bytes = body
        payload = json.dumps({"received_len": len(body)}).encode()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": payload})


def _scope(*, method="POST", path="/x", content_length=None):
    headers = []
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode()))
    return {"type": "http", "method": method, "path": path, "headers": headers}


class _CollectingSend:
    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)

    @property
    def status(self):
        for m in self.messages:
            if m["type"] == "http.response.start":
                return m["status"]
        return None

    @property
    def body(self):
        return b"".join(m.get("body", b"") for m in self.messages if m["type"] == "http.response.body")


def _fixed_receive(chunks: list[bytes]):
    """Simulates a client streaming ``chunks`` with no advance knowledge of
    total size on the server's side (mirrors "absent Content-Length")."""
    remaining = list(chunks)

    async def receive():
        if not remaining:
            return {"type": "http.request", "body": b"", "more_body": False}
        chunk = remaining.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(remaining)}

    return receive


@async_test
async def test_small_body_passes_through_untouched():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=1000)
    send = _CollectingSend()
    await mw(_scope(content_length=10), _fixed_receive([b"0123456789"]), send)
    assert downstream.invocations == 1
    assert downstream.received_bytes == b"0123456789"
    assert send.status == 200


@async_test
async def test_get_requests_bypass_the_limit_entirely():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=10)
    send = _CollectingSend()
    await mw(_scope(method="GET", content_length=999999), _fixed_receive([b"x" * 999999]), send)
    assert downstream.invocations == 1


@async_test
async def test_oversized_content_length_is_rejected_before_touching_body():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=100)

    async def never_called():
        raise AssertionError("receive() must never be called once Content-Length already exceeds the limit")

    send = _CollectingSend()
    await mw(_scope(content_length=99999), never_called, send)
    assert downstream.invocations == 0
    assert send.status == 413
    assert json.loads(send.body)["error_code"] == PAYLOAD_TOO_LARGE_ERROR_CODE


@async_test
async def test_malformed_content_length_is_rejected():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=100)
    send = _CollectingSend()
    scope = {"type": "http", "method": "POST", "path": "/x", "headers": [(b"content-length", b"not-a-number")]}
    await mw(scope, _fixed_receive([b"short"]), send)
    assert downstream.invocations == 0
    assert send.status == 413


@async_test
async def test_absent_content_length_with_oversized_streaming_body_is_rejected():
    """No Content-Length at all; the middleware must size-check the actual
    bytes as they stream in rather than trusting (or requiring) the header."""
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=20)
    send = _CollectingSend()
    chunks = [b"x" * 10 for _ in range(10)]  # 100 bytes total, well over the 20-byte limit
    await mw(_scope(content_length=None), _fixed_receive(chunks), send)
    assert downstream.invocations == 0
    assert send.status == 413
    assert json.loads(send.body)["error_code"] == PAYLOAD_TOO_LARGE_ERROR_CODE


@async_test
async def test_false_small_content_length_is_still_caught_by_streaming_check():
    """A lying Content-Length that understates the real body must not let an
    oversized body through — the streaming byte count is authoritative."""
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=20)
    send = _CollectingSend()
    chunks = [b"x" * 10 for _ in range(10)]
    await mw(_scope(content_length=5), _fixed_receive(chunks), send)  # header says 5 bytes; real stream is 100
    assert downstream.invocations == 0
    assert send.status == 413


@async_test
async def test_chunked_body_without_content_length_within_limit_is_forwarded():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=1000)
    send = _CollectingSend()
    chunks = [b"abc", b"def", b"ghi"]
    await mw(_scope(content_length=None), _fixed_receive(chunks), send)
    assert downstream.invocations == 1
    assert downstream.received_bytes == b"abcdefghi"
    assert send.status == 200


@async_test
async def test_deeply_nested_but_byte_small_payload_passes_the_middleware():
    """Recursion/structural depth limits are the concern of the WebMCP model
    layer (objective #7), not this byte-size middleware — a small-but-deeply
    -nested JSON document must pass through here untouched."""
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=5000)
    nested: dict = {"v": 1}
    for _ in range(200):
        nested = {"child": nested}
    body = json.dumps(nested).encode()
    send = _CollectingSend()
    await mw(_scope(content_length=len(body)), _fixed_receive([body]), send)
    assert downstream.invocations == 1
    assert send.status == 200


@async_test
async def test_byte_large_shallow_payload_is_rejected():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=5000)
    body = json.dumps({"description": "x" * 20000}).encode()
    send = _CollectingSend()
    await mw(_scope(content_length=len(body)), _fixed_receive([body]), send)
    assert downstream.invocations == 0
    assert send.status == 413


@async_test
async def test_path_specific_limit_overrides_default():
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(
        downstream, default_max_bytes=10, path_limits={"/webshield/outputs": 10_000},
    )
    body = b"y" * 5000

    # Under the path-specific limit but over the default -> must be allowed
    # on the overridden path...
    send_ok = _CollectingSend()
    await mw(_scope(path="/webshield/outputs", content_length=len(body)), _fixed_receive([body]), send_ok)
    assert send_ok.status == 200
    assert downstream.invocations == 1

    # ...and still rejected on a different path using the tighter default.
    send_rejected = _CollectingSend()
    await mw(_scope(path="/webshield/registrations", content_length=len(body)), _fixed_receive([body]), send_rejected)
    assert send_rejected.status == 413
    assert downstream.invocations == 1  # unchanged — second call never reached the app


@async_test
async def test_streaming_check_stops_reading_as_soon_as_limit_is_exceeded():
    """The middleware must not keep draining an unbounded body after it has
    already decided to reject it."""
    downstream = _RecordingApp()
    mw = RequestBodySizeLimitMiddleware(downstream, default_max_bytes=15)

    read_count = 0
    total_available_chunks = 10_000  # would hang/be extremely slow if fully drained

    async def receive():
        nonlocal read_count
        read_count += 1
        if read_count > total_available_chunks:
            raise AssertionError("must not be called this many times")
        return {"type": "http.request", "body": b"x" * 10, "more_body": True}

    send = _CollectingSend()
    await mw(_scope(content_length=None), receive, send)
    assert send.status == 413
    # 15-byte limit, 10 bytes/chunk -> exceeded on the 2nd chunk; must not
    # have proceeded to read anywhere near all 10,000 available chunks.
    assert read_count <= 3


# --------------------------------------------------------------------------
# Integration-level: the real Web Shield API surface, wired through
# varden.app_factory.create_app, using the app's configured limits.
# --------------------------------------------------------------------------


def test_registration_with_oversized_content_length_is_rejected_pre_parse():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=1000) as client:
            headers = _bootstrap_headers(client)
            huge_tool = {"name": "get_weather", "description": "x" * 5000}
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": huge_tool},
                headers=headers,
            )
            assert response.status_code == 413
            assert response.json()["error_code"] == PAYLOAD_TOO_LARGE_ERROR_CODE


def test_413_response_never_invokes_scanner_or_persistence():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=1000) as client:
            headers = _bootstrap_headers(client)
            huge_tool = {"name": "get_weather", "description": "x" * 5000}
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "reject-me", "owner_origin": "https://x.test", "tool": huge_tool},
                headers=headers,
            )
            assert response.status_code == 413
            sessions = client.get("/webshield/sessions", headers=headers).json()["items"]
            assert not any(s.get("session_id") == "reject-me" for s in sessions)
            tools = client.get("/webshield/tools", headers=headers).json()["items"]
            assert not any(t.get("tool_name") == "get_weather" for t in tools)


def test_registration_within_limit_still_succeeds():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=5000) as client:
            headers = _bootstrap_headers(client)
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": BENIGN_TOOL},
                headers=headers,
            )
            assert response.status_code == 200


def test_output_endpoint_has_its_own_higher_limit_than_the_default_ingest_limit():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=2000, max_output_body_bytes=50_000) as client:
            headers = _bootstrap_headers(client)
            reg = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://docs.test", "tool": BENIGN_TOOL},
                headers=headers,
            ).json()
            identity_key = reg["identity_key"]

            # Bigger than the default ingest limit (2000) but within the
            # dedicated output limit (50,000) -> must not be pre-parse rejected.
            medium_output = "benign text " * 1000
            ok = client.post(
                "/webshield/outputs",
                json={"session_id": "s1", "identity_key": identity_key, "output_text": medium_output},
                headers=headers,
            )
            assert ok.status_code != 413

            # Bigger than even the dedicated output limit -> still rejected.
            huge_output = "z" * 100_000
            too_big = client.post(
                "/webshield/outputs",
                json={"session_id": "s1", "identity_key": identity_key, "output_text": huge_output},
                headers=headers,
            )
            assert too_big.status_code == 413


def test_event_batch_sized_lifecycle_payload_is_bounded_by_default_limit():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=2000) as client:
            headers = _bootstrap_headers(client)
            response = client.post(
                "/webshield/lifecycle",
                json={"session_id": "s1", "event": "context_replaced", "top_origin": "https://x.test", "details": {"blob": "q" * 10_000}},
                headers=headers,
            )
            assert response.status_code == 413


def test_chunked_transfer_without_content_length_is_still_size_checked():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=2000) as client:
            headers = dict(_bootstrap_headers(client))
            huge_tool = {"name": "get_weather", "description": "x" * 20_000}
            body_bytes = json.dumps({"session_id": "s1", "owner_origin": "https://x.test", "tool": huge_tool}).encode()

            def body_stream():
                # A generator body forces httpx to use chunked transfer
                # encoding with no Content-Length header, exercising the
                # streaming (rather than header-based) enforcement path.
                chunk_size = 512
                for i in range(0, len(body_bytes), chunk_size):
                    yield body_bytes[i : i + chunk_size]

            headers["content-type"] = "application/json"
            response = client.post("/webshield/registrations", content=body_stream(), headers=headers)
            assert response.status_code == 413
