"""Independent-review remediation: delivered responses, nested bypasses, providers.

Side effects are temporary files and local sockets. Provider tests replace
``create`` before ``protect()`` and never call a paid API.
"""

from __future__ import annotations

import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import requests

import varden
from tests.security.pass2.test_p3_enforcement_integrity import _load_standalone
from varden.runtime.coverage import ENFORCED, PARTIAL, UNCOVERED, get_coverage_registry
from varden.runtime.guard_response import (
    APPROVAL_REQUIRED,
    AUTHORITATIVE_ALLOW,
    AUTHORITATIVE_DENY,
    INVALID_DECISION,
    NO_DECISION,
    SERVICE_FAILURE,
    SERVICE_FAILURE_WITH_ALLOW,
    classify_guard_response,
    fail_open_applies,
    is_transport_failure,
)
from varden_langchain.integration import instrument_tool
from varden_sdk.sdk import VardenBlockedError


class _Resp:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.headers = {"content-type": "application/json"}
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode()

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        if isinstance(self._body, str):
            return json.loads(self._body)
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://testserver/sdk/guard")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("error", request=request, response=response)


def _protect(**kwargs):
    params = {
        "mode": "guarded",
        "fail_mode": "closed",
        "base_url": "http://testserver",
        "api_key": "test-key",
        "auto_instrument": False,
        "emit_attestation": False,
    }
    params.update(kwargs)
    return varden.protect(**params)


def _stub(guard, status, body, *, error=None):
    def post(*_args, **_kwargs):
        if error is not None:
            raise error
        return _Resp(status, body)

    guard.client._client.post = post


def _read(path: Path) -> str:
    from varden_sdk.sdk import _ORIGINALS

    opener = _ORIGINALS.get("builtins.open", open)
    with opener(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _allow():
    return {"decision": {"action": "allow", "reason": "ok"}, "action": {}, "event_id": 1}


@pytest.fixture(autouse=True)
def _reset_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()


_CASES = [
    (200, {"decision": {"action": "allow"}, "action": {}}, AUTHORITATIVE_ALLOW),
    (200, {"decision": {"action": "block"}, "action": {}}, AUTHORITATIVE_DENY),
    (200, {"decision": {"action": "require_approval"}, "action": {}}, APPROVAL_REQUIRED),
    (200, {"decision": {"action": "allow", "effective_action": "block"}}, AUTHORITATIVE_DENY),
    (200, {"decision": {"action": "not-a-decision"}}, INVALID_DECISION),
    (200, {}, NO_DECISION),
    (200, {"detail": "not json"}, NO_DECISION),
    (200, {"decision": None}, INVALID_DECISION),
    (403, {"decision": {"action": "allow"}}, AUTHORITATIVE_DENY),
    (401, {}, SERVICE_FAILURE),
    (404, {"detail": "missing"}, SERVICE_FAILURE),
    (429, {}, SERVICE_FAILURE),
    (500, {"detail": "down"}, SERVICE_FAILURE),
    (502, {}, SERVICE_FAILURE),
    (503, {}, SERVICE_FAILURE),
    (503, {"decision": {"action": "allow"}, "action": {}}, SERVICE_FAILURE_WITH_ALLOW),
    (503, {"detail": {"decision": {"action": "require_approval"}}}, APPROVAL_REQUIRED),
]


@pytest.mark.parametrize("status,body,expected", _CASES)
def test_root_and_standalone_classify_the_same_response(status, body, expected):
    assert classify_guard_response(body, status_code=status) == expected
    standalone = _load_standalone()
    assert standalone._classify_response(body, status_code=status) == expected
    if expected in {AUTHORITATIVE_ALLOW, SERVICE_FAILURE_WITH_ALLOW}:
        assert fail_open_applies(expected) is (expected == SERVICE_FAILURE_WITH_ALLOW)
    else:
        assert fail_open_applies(expected) is False


def test_transport_exceptions_are_not_delivered_responses():
    assert is_transport_failure(httpx.ConnectError("refused"))
    assert is_transport_failure(httpx.ReadTimeout("slow"))
    assert is_transport_failure(ConnectionResetError("reset"))
    assert is_transport_failure(TimeoutError("timeout"))
    assert is_transport_failure(httpx.HTTPStatusError("status", request=httpx.Request("POST", "http://x"), response=httpx.Response(500))) is False
    assert is_transport_failure(RuntimeError("bug")) is False
    assert is_transport_failure(json.JSONDecodeError("bad", "x", 0)) is False


@pytest.mark.parametrize(
    "status,body",
    [
        (200, {}),
        (200, {"detail": "not a decision"}),
        (200, {"decision": None}),
        (200, json.JSONDecodeError("bad", "{", 0)),
        (401, {}),
        (404, {}),
        (429, {}),
        (500, {"detail": "down"}),
        (502, {}),
        (503, {"detail": "down"}),
    ],
)
def test_delivered_non_authorization_does_not_execute_under_fail_open(tmp_path, status, body):
    sentinel = tmp_path / "effect.txt"
    guard = _protect(fail_mode="open")
    _stub(guard, status, body)

    def tool():
        sentinel.write_text("ran", encoding="utf-8")

    with pytest.raises(VardenBlockedError):
        guard.guard_tool(tool, name="delete_database")()
    assert not sentinel.exists()


def test_service_failure_with_allow_still_fail_opens(tmp_path):
    sentinel = tmp_path / "effect.txt"
    guard = _protect(fail_mode="open")
    _stub(guard, 503, {"decision": {"action": "allow"}, "action": {}, "event_id": 1})

    def tool():
        sentinel.write_text("ran", encoding="utf-8")
        return "ok"

    assert guard.guard_tool(tool, name="delete_database")() == "ok"
    assert sentinel.read_text(encoding="utf-8") == "ran"


def test_unexpected_client_exception_does_not_fail_open(tmp_path):
    sentinel = tmp_path / "effect.txt"
    guard = _protect(fail_mode="open")
    _stub(guard, 200, _allow(), error=RuntimeError("parser blew up"))

    def tool():
        sentinel.write_text("ran", encoding="utf-8")

    with pytest.raises(VardenBlockedError):
        guard.guard_tool(tool, name="delete_database")()
    assert not sentinel.exists()


def test_guard_callback_cannot_write_a_secret_during_an_authorized_open(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE", encoding="utf-8")
    allowed = tmp_path / "credentials.json"
    allowed.write_text("ok", encoding="utf-8")
    guard = _protect(fail_mode="open", auto_instrument=True)
    leaked = {"hit": False}

    def post(_url, **kwargs):
        blob = json.dumps(kwargs.get("json") or {})
        if "id_rsa" in blob:
            return _Resp(200, {"decision": {"action": "block"}, "action": {}})
        if not leaked["hit"]:
            leaked["hit"] = True
            try:
                with open(secret, "a", encoding="utf-8") as handle:
                    handle.write("LEAK")
            except VardenBlockedError:
                pass
        return _Resp(200, _allow())

    guard.client._client.post = post
    with open(allowed, "a", encoding="utf-8") as handle:
        handle.write("x")
    assert _read(secret) == "PRIVATE"
    assert leaked["hit"] is True


def test_pathlike_callback_cannot_write_a_secret(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE", encoding="utf-8")
    allowed = tmp_path / "notes.txt"
    guard = _protect(fail_mode="open", auto_instrument=True)

    def post(_url, **kwargs):
        blob = json.dumps(kwargs.get("json") or {})
        if "id_rsa" in blob:
            return _Resp(200, {"decision": {"action": "block"}, "action": {}})
        return _Resp(200, _allow())

    guard.client._client.post = post

    class Evil(os.PathLike):
        def __fspath__(self):
            try:
                with open(secret, "a", encoding="utf-8") as handle:
                    handle.write("LEAK")
            except VardenBlockedError:
                pass
            return str(allowed)

    with open(Evil(), "w", encoding="utf-8") as handle:
        handle.write("ok")
    assert _read(secret) == "PRIVATE"
    assert _read(allowed) == "ok"


def test_filesystem_exception_does_not_leave_interception_disabled(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE", encoding="utf-8")
    guard = _protect(fail_mode="closed", auto_instrument=True)
    guard.client._client.post = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom"))
    with pytest.raises(VardenBlockedError):
        open(secret, "r", encoding="utf-8")
    guard.client._client.post = lambda *_a, **_k: _Resp(200, {"decision": {"action": "block"}, "action": {}})
    with pytest.raises(VardenBlockedError):
        open(secret, "r", encoding="utf-8")
    assert _read(secret) == "PRIVATE"


def test_async_task_created_during_guard_does_not_inherit_a_bypass(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE", encoding="utf-8")
    allowed = tmp_path / "credentials.json"
    allowed.write_text("ok", encoding="utf-8")
    guard = _protect(fail_mode="open", auto_instrument=True)

    async def nested():
        try:
            with open(secret, "a", encoding="utf-8") as handle:
                handle.write("LEAK")
        except VardenBlockedError:
            pass

    def post(_url, **kwargs):
        blob = json.dumps(kwargs.get("json") or {})
        if "id_rsa" in blob:
            return _Resp(200, {"decision": {"action": "block"}, "action": {}})
        asyncio.run(nested())
        return _Resp(200, _allow())

    guard.client._client.post = post
    with open(allowed, "a", encoding="utf-8") as handle:
        handle.write("x")
    assert _read(secret) == "PRIVATE"


def test_path_open_does_not_charge_the_guard_twice(tmp_path):
    target = tmp_path / "credentials.json"
    guard = _protect(auto_instrument=True)
    calls = {"n": 0}

    def post(*_args, **_kwargs):
        calls["n"] += 1
        return _Resp(200, _allow())

    guard.client._client.post = post
    target.write_text("ok", encoding="utf-8")
    assert calls["n"] == 1
    assert target.read_text(encoding="utf-8") == "ok"


def test_nested_langchain_tool_is_authorized_independently():
    class Child:
        name = "child"

        def invoke(self, payload, config=None):
            self.ran = payload
            return "child"

    class Outer:
        name = "outer"

        def __init__(self, child):
            self.child = child

            def invoke(payload, config=None):
                return self._run(payload)

            def _run(payload):
                return self.child.invoke(payload)

            self.invoke = invoke
            self._run = _run

    class Guard:
        mode = "enforce"
        product_mode = "guarded"
        fail_mode = "closed"

        def __init__(self):
            self.calls = []

        def guarded_action(self, **kwargs):
            self.calls.append(kwargs.get("tool"))
            action = "block" if kwargs.get("tool") == "child" else "allow"
            from varden_sdk.sdk import GuardResult

            return GuardResult(decision={"action": action}, action=kwargs, event_id=len(self.calls))

        def record_result(self, **_kwargs):
            return {"ok": True}

    child = Child()
    outer = Outer(child)
    guard = Guard()
    instrument_tool(child, guard=guard)
    instrument_tool(outer, guard=guard)
    with pytest.raises(VardenBlockedError):
        outer.invoke({"q": "go"})
    assert child.__dict__.get("ran") is None
    assert guard.calls == ["outer", "child"]


def test_langchain_exception_restores_enforcement():
    class Tool:
        name = "tool"

        def invoke(self, payload, config=None):
            raise RuntimeError("tool failed")

    class Guard:
        mode = "enforce"
        calls = 0

        def guarded_action(self, **kwargs):
            self.calls += 1
            from varden_sdk.sdk import GuardResult

            return GuardResult(decision={"action": "allow"}, action=kwargs, event_id=1)

        def record_result(self, **_kwargs):
            return None

    tool = Tool()
    guard = Guard()
    instrument_tool(tool, guard=guard)
    with pytest.raises(RuntimeError):
        tool.invoke({})
    with pytest.raises(RuntimeError):
        tool.invoke({})
    assert guard.calls == 2


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append({"path": self.path, "auth": self.headers.get("Authorization"), "cookie": self.headers.get("Cookie")})
        if self.server.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.end_headers()
            self.server.redirect_to = ""
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        return


class _Recorder(ThreadingHTTPServer):
    def __init__(self, host="127.0.0.1", family=0):
        import socket

        self.hits = []
        self.redirect_to = ""
        self.address_family = family or socket.AF_INET
        super().__init__((host, 0), _Handler)


def test_nested_session_send_to_another_host_is_not_preauthorized():
    import socket
    import threading

    first = _Recorder("127.0.0.1")
    second = _Recorder("::1", socket.AF_INET6)
    for server in (first, second):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    second_url = f"http://[::1]:{second.server_address[1]}/secret"
    guard = varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        fail_mode="open",
        mode="guarded",
    )

    def post(_url, **kwargs):
        blob = json.dumps(kwargs.get("json") or {})
        if "::1" in blob:
            return _Resp(200, {"decision": {"action": "block"}, "action": {}})
        return _Resp(200, _allow())

    guard.client._client.post = post
    session = requests.Session()

    class NestedAdapter(requests.adapters.HTTPAdapter):
        nested = False

        def send(self, request, **kwargs):
            if not self.nested and "::1" not in str(request.url):
                self.nested = True
                prepared = requests.Request("GET", second_url).prepare()
                try:
                    session.send(prepared, timeout=2)
                except VardenBlockedError:
                    pass
            return super().send(request, **kwargs)

    session.mount("http://", NestedAdapter())
    try:
        response = session.get(f"http://127.0.0.1:{first.server_address[1]}/ok", timeout=2)
        assert response.status_code == 200
        assert second.hits == []
    finally:
        first.shutdown()
        second.shutdown()
        varden.unpatch_runtime()


def test_httpx_redirect_is_reauthorized_and_drops_credentials():
    import socket
    import threading

    first = _Recorder("127.0.0.1")
    second = _Recorder("::1", socket.AF_INET6)
    for server in (first, second):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    second_url = f"http://[::1]:{second.server_address[1]}/landed"
    first.redirect_to = second_url
    guard = varden.protect(base_url="http://testserver", api_key="k", emit_attestation=False, mode="guarded")
    seen = []

    def post(_url, json=None, **_kwargs):
        action = (json or {}).get("action") or {}
        seen.append(action.get("url"))
        return _Resp(200, _allow())

    guard.client._client.post = post
    try:
        with httpx.Client(follow_redirects=True) as client:
            response = client.get(
                f"http://127.0.0.1:{first.server_address[1]}/start",
                headers={"Authorization": "Bearer secret", "Cookie": "sid=1"},
            )
        assert response.status_code == 200
        assert len(seen) >= 2
        assert any("::1" in (url or "") for url in seen)
        assert second.hits
        assert second.hits[0]["auth"] is None
        assert second.hits[0]["cookie"] is None
    finally:
        first.shutdown()
        second.shutdown()
        varden.unpatch_runtime()


def test_blocked_retry_does_not_connect():
    import threading

    server = _Recorder("127.0.0.1")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    guard = varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        fail_mode="open",
        mode="guarded",
    )
    guard.client._client.post = lambda *_a, **_k: _Resp(200, {"decision": {"action": "block"}, "action": {}})
    url = f"http://127.0.0.1:{server.server_address[1]}/retry"
    try:
        for _ in range(2):
            with pytest.raises(VardenBlockedError):
                requests.get(url, timeout=2)
        assert server.hits == []
    finally:
        server.shutdown()
        varden.unpatch_runtime()


def _install_fake_create(owner, *, async_method: bool):
    called = {"n": 0}

    if async_method:
        async def create(self, *args, **kwargs):
            called["n"] += 1
            return type("Resp", (), {"model": "fake", "usage": None, "object": "test"})()
    else:
        def create(self, *args, **kwargs):
            called["n"] += 1
            return type("Resp", (), {"model": "fake", "usage": None, "object": "test"})()

    owner.create = create
    return called


@pytest.mark.parametrize(
    "module,attr,async_method",
    [
        ("openai.resources.chat.completions.completions", "Completions", False),
        ("openai.resources.chat.completions.completions", "AsyncCompletions", True),
        ("openai.resources.responses.responses", "Responses", False),
        ("openai.resources.responses.responses", "AsyncResponses", True),
        ("anthropic.resources.messages", "Messages", False),
        ("anthropic.resources.messages", "AsyncMessages", True),
    ],
)
def test_provider_create_block_does_not_call_the_sdk(module, attr, async_method):
    pytest.importorskip(module.split(".", 1)[0])
    import importlib

    owner = getattr(importlib.import_module(module), attr)
    called = _install_fake_create(owner, async_method=async_method)
    guard = varden.protect(base_url="http://testserver", api_key="k", emit_attestation=False, auto_instrument=True)
    guard.client._client.post = lambda *_a, **_k: _Resp(200, {"decision": {"action": "block"}, "action": {}})
    instance = owner.__new__(owner)
    try:
        if async_method:
            with pytest.raises(VardenBlockedError):
                asyncio.run(owner.create(instance, model="fake", messages=[]))
        else:
            with pytest.raises(VardenBlockedError):
                owner.create(instance, model="fake", messages=[])
        assert called["n"] == 0
        guard.client._client.post = lambda *_a, **_k: _Resp(200, _allow())
        if async_method:
            asyncio.run(owner.create(instance, model="fake", messages=[]))
        else:
            owner.create(instance, model="fake", messages=[])
        assert called["n"] == 1
    finally:
        varden.unpatch_runtime()


def test_unwrapping_async_openai_create_downgrades_coverage():
    pytest.importorskip("openai")
    import openai.resources.chat.completions.completions as completions

    _install_fake_create(completions.Completions, async_method=False)
    _install_fake_create(completions.AsyncCompletions, async_method=True)
    varden.protect(base_url="http://testserver", api_key="k", emit_attestation=False, auto_instrument=True)
    try:
        surface = get_coverage_registry().get("llm.openai_transport")
        assert surface is not None
        assert surface.status == ENFORCED
        from varden_sdk import sdk as sdk_mod

        original = sdk_mod._ORIGINALS["openai.chat.completions.async_create"]
        completions.AsyncCompletions.create = original
        get_coverage_registry().verify()
        assert get_coverage_registry().get("llm.openai_transport").status == UNCOVERED
    finally:
        varden.unpatch_runtime()


def test_missing_async_provider_method_is_not_enforced(monkeypatch):
    pytest.importorskip("openai")
    import openai.resources.chat.completions.completions as completions

    monkeypatch.delattr(completions, "AsyncCompletions", raising=False)
    _install_fake_create(completions.Completions, async_method=False)
    varden.protect(base_url="http://testserver", api_key="k", emit_attestation=False, auto_instrument=True)
    try:
        surface = get_coverage_registry().get("llm.openai_transport")
        assert surface is not None
        assert surface.status == PARTIAL
        assert surface.status != ENFORCED
    finally:
        varden.unpatch_runtime()
