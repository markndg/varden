"""Phase 3 final HTTP remediation: per-operation authorization and origin credentials.

Transports are local servers, a capturing adapter, or httpx.MockTransport.
Nothing in this module dials an external host.
"""

from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import requests

import varden
from varden_sdk.sdk import VardenBlockedError


class _Resp:
    def __init__(self, body):
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()

    def json(self):
        return self._body

    def raise_for_status(self):
        return None


def _allow():
    return {"decision": {"action": "allow", "reason": "ok"}, "action": {}, "event_id": 1}


def _block():
    return {"decision": {"action": "block", "reason": "no"}, "action": {}}


@pytest.fixture(autouse=True)
def _reset_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()


def _guard():
    return varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        mode="guarded",
        fail_mode="closed",
    )


def _install(guard, decide):
    """Replace the control-plane post. ``decide`` sees each guard action."""
    seen = []

    def post(url, **kwargs):
        if "/sdk/guard" not in str(url):
            return _Resp({"ok": True})
        action = (kwargs.get("json") or {}).get("action") or {}
        seen.append(action)
        return _Resp(decide(action))

    guard.client._client.post = post
    return seen


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.server.hits.append("POST " + self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        return


class _Server(ThreadingHTTPServer):
    def __init__(self):
        self.hits = []
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"


def _serve():
    server = _Server()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _action_url(action) -> str:
    return str(action.get("url") or "")


def _blocks_delete(action) -> dict:
    url = _action_url(action)
    method = str(action.get("method") or "GET").upper()
    if "operation=delete" in url or method == "POST" or "::1" in url:
        return _block()
    return _allow()


class _NestedAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, session, build):
        super().__init__()
        self.session = session
        self.build = build
        self.done = False
        self.blocked = False

    def send(self, request, **kwargs):
        if not self.done and "operation=read" in str(request.url):
            self.done = True
            prepared = self.build()
            try:
                self.session.send(prepared, timeout=2)
            except VardenBlockedError:
                self.blocked = True
        return super().send(request, **kwargs)


def test_session_request_authorizes_the_initial_request_once():
    server = _serve()
    guard = _guard()
    seen = _install(guard, lambda _action: _allow())
    try:
        response = requests.Session().get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200
        assert server.hits == ["/api/action?operation=read"]
        assert len(seen) == 1
        assert "operation=read" in _action_url(seen[0])
    finally:
        server.shutdown()
        server.server_close()


def test_nested_send_with_a_different_query_is_authorized_on_its_own():
    server = _serve()
    guard = _guard()
    seen = _install(guard, _blocks_delete)
    session = requests.Session()
    adapter = _NestedAdapter(
        session,
        lambda: requests.Request("GET", server.url + "/api/action?operation=delete").prepare(),
    )
    session.mount("http://", adapter)
    try:
        response = session.get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200
        assert adapter.blocked
        assert server.hits == ["/api/action?operation=read"]
        assert any("operation=delete" in _action_url(action) for action in seen)
    finally:
        server.shutdown()
        server.server_close()


def test_nested_send_with_a_different_method_is_authorized_on_its_own():
    server = _serve()
    guard = _guard()
    seen = _install(guard, _blocks_delete)
    session = requests.Session()

    def build():
        return requests.Request("POST", server.url + "/api/action?operation=read").prepare()

    adapter = _NestedAdapter(session, build)
    session.mount("http://", adapter)
    try:
        response = session.get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200
        assert adapter.blocked
        assert server.hits == ["/api/action?operation=read"]
        assert any(str(action.get("method") or "").upper() == "POST" for action in seen)
    finally:
        server.shutdown()
        server.server_close()


def test_nested_send_to_a_different_origin_is_authorized_on_its_own():
    server = _serve()
    guard = _guard()
    seen = _install(guard, _blocks_delete)
    session = requests.Session()
    adapter = _NestedAdapter(
        session,
        lambda: requests.Request("GET", "http://[::1]:9/secret").prepare(),
    )
    session.mount("http://", adapter)
    try:
        response = session.get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200
        assert adapter.blocked
        assert server.hits == ["/api/action?operation=read"]
        assert any("::1" in _action_url(action) for action in seen)
    finally:
        server.shutdown()
        server.server_close()


def test_distinct_prepared_request_with_the_same_url_is_not_preauthorized():
    server = _serve()
    guard = _guard()
    calls = {"n": 0}

    def decide(_action):
        calls["n"] += 1
        if calls["n"] == 1:
            return _allow()
        return _block()

    _install(guard, decide)
    session = requests.Session()
    same = server.url + "/api/action?operation=read"
    adapter = _NestedAdapter(session, lambda: requests.Request("GET", same).prepare())
    session.mount("http://", adapter)
    try:
        response = session.get(same, timeout=2)
        assert response.status_code == 200
        assert adapter.blocked
        assert calls["n"] == 2
        assert server.hits == ["/api/action?operation=read"]
    finally:
        server.shutdown()
        server.server_close()


def test_blocked_nested_send_makes_no_connection():
    server = _serve()
    guard = _guard()
    _install(guard, lambda _action: _block())
    session = requests.Session()
    prepared = requests.Request("GET", server.url + "/api/action?operation=delete").prepare()
    try:
        with pytest.raises(VardenBlockedError):
            session.send(prepared, timeout=2)
        assert server.hits == []
    finally:
        server.shutdown()
        server.server_close()


def test_an_exception_does_not_leave_authorization_for_the_next_request():
    server = _serve()
    guard = _guard()
    seen = _install(guard, lambda _action: _allow())
    session = requests.Session()

    class Boom(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            raise RuntimeError("transport failed")

    session.mount("http://", Boom())
    try:
        with pytest.raises(RuntimeError):
            session.get(server.url + "/api/action?operation=read", timeout=2)
        session.mount("http://", requests.adapters.HTTPAdapter())
        response = session.get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200
        assert len(seen) == 2
        assert server.hits == ["/api/action?operation=read"]
    finally:
        server.shutdown()
        server.server_close()


def test_another_thread_cannot_reuse_an_in_flight_authorization():
    server = _serve()
    guard = _guard()
    seen = _install(guard, _blocks_delete)
    barrier = threading.Barrier(2)

    def read():
        barrier.wait(timeout=2)
        response = requests.get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200

    def delete():
        barrier.wait(timeout=2)
        requests.get(server.url + "/api/action?operation=delete", timeout=2)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            read_future = pool.submit(read)
            delete_future = pool.submit(delete)
            read_future.result(timeout=5)
            with pytest.raises(VardenBlockedError):
                delete_future.result(timeout=5)
        assert server.hits == ["/api/action?operation=read"]
        assert any("operation=delete" in _action_url(action) for action in seen)
    finally:
        server.shutdown()
        server.server_close()


def test_an_async_context_cannot_reuse_an_in_flight_authorization():
    server = _serve()
    guard = _guard()
    seen = _install(guard, _blocks_delete)
    session = requests.Session()

    class NestedAsync(requests.adapters.HTTPAdapter):
        def __init__(self):
            super().__init__()
            self.blocked = False

        def send(self, request, **kwargs):
            if "operation=read" in str(request.url) and not self.blocked:
                async def nested():
                    prepared = requests.Request(
                        "GET", server.url + "/api/action?operation=delete"
                    ).prepare()
                    session.send(prepared, timeout=2)

                try:
                    asyncio.run(nested())
                except VardenBlockedError:
                    self.blocked = True
            return super().send(request, **kwargs)

    adapter = NestedAsync()
    session.mount("http://", adapter)
    try:
        response = session.get(server.url + "/api/action?operation=read", timeout=2)
        assert response.status_code == 200
        assert adapter.blocked
        assert server.hits == ["/api/action?operation=read"]
        assert any("operation=delete" in _action_url(action) for action in seen)
    finally:
        server.shutdown()
        server.server_close()


def test_redirect_hops_are_authorized_independently_and_a_block_does_not_connect():
    guard = _guard()
    seen = _install(guard, lambda action: _block() if _action_url(action).endswith("/land") else _allow())
    captured = []

    class Capture(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            captured.append(str(request.url))
            response = requests.Response()
            response.status_code = 302
            response.url = request.url
            response.request = request
            response.headers["Location"] = "https://example.test/land"
            response.reason = "found"
            response._content = b""
            return response

    session = requests.Session()
    session.mount("https://", Capture())
    with pytest.raises(VardenBlockedError):
        session.get("https://example.test/start", timeout=2)
    assert captured == ["https://example.test/start"]
    assert any(url.endswith("/start") for url in map(_action_url, seen))
    assert any(url.endswith("/land") for url in map(_action_url, seen))


def _capture_redirect(start, location, *, session_setup=None, headers=None, auth=None, cookies=None):
    captured = []

    class Capture(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            captured.append(
                {
                    "url": str(request.url),
                    "authorization": request.headers.get("Authorization"),
                    "cookie": request.headers.get("Cookie"),
                    "proxy": request.headers.get("Proxy-Authorization"),
                }
            )
            response = requests.Response()
            response.status_code = 302 if len(captured) == 1 else 200
            response.url = request.url
            response.request = request
            if len(captured) == 1:
                response.headers["Location"] = location
            response.reason = "ok"
            response._content = b"ok"
            return response

    session = requests.Session()
    if session_setup is not None:
        session_setup(session)
    session.mount("https://", Capture())
    session.mount("http://", Capture())
    response = session.get(
        start,
        headers=headers,
        auth=auth,
        cookies=cookies,
        timeout=2,
        allow_redirects=True,
    )
    assert response.status_code == 200
    return captured


def _sensitive(hop) -> tuple:
    return (hop["authorization"], hop["cookie"], hop["proxy"])


@pytest.mark.parametrize(
    ("start", "location", "keep"),
    [
        ("https://example.test/start", "https://other.test/land", False),
        ("https://example.test/start", "http://example.test/land", False),
        ("https://example.test/start", "https://example.test:8443/land", False),
        ("https://example.test/start", "https://example.test:443/land", True),
        ("https://example.test:8443/start", "https://example.test/land", False),
        ("https://example.test/start", "https://example.test/other", True),
        ("https://example.test/start", "https://example.test/start?operation=read", True),
        ("http://example.test/start", "https://example.test/land", False),
        ("https://EXAMPLE.TEST./start", "https://example.test/land", True),
    ],
)
def test_requests_redirect_strips_credentials_only_when_the_origin_changes(start, location, keep):
    _guard()
    # The decide closure is installed below; allow every hop so the header is observable.
    guard = varden.current_guard()
    _install(guard, lambda _action: _allow())
    headers = {
        "Authorization": "Bearer SECRET",
        "Cookie": "sid=SECRET",
        "Proxy-Authorization": "Basic cHJveHk=",
    }
    captured = _capture_redirect(start, location, headers=headers)
    assert len(captured) == 2
    assert _sensitive(captured[0]) == ("Bearer SECRET", "sid=SECRET", "Basic cHJveHk=")
    if keep:
        assert _sensitive(captured[1]) == ("Bearer SECRET", "sid=SECRET", "Basic cHJveHk=")
    else:
        assert _sensitive(captured[1]) == (None, None, None)


def test_requests_session_auth_and_cookies_are_not_rebuilt_cross_origin():
    guard = _guard()
    _install(guard, lambda _action: _allow())

    def setup(session):
        session.auth = ("user", "password")
        session.cookies.set("sid", "SECRET")

    captured = _capture_redirect(
        "https://example.test/start",
        "http://example.test/land",
        session_setup=setup,
    )
    assert captured[0]["authorization"].startswith("Basic ")
    assert "sid=SECRET" in captured[0]["cookie"]
    assert captured[1]["authorization"] is None
    assert captured[1]["cookie"] is None


def test_requests_same_origin_keeps_session_credentials():
    guard = _guard()
    _install(guard, lambda _action: _allow())

    def setup(session):
        session.auth = ("user", "password")
        session.cookies.set("sid", "SECRET")

    captured = _capture_redirect(
        "https://example.test/start",
        "https://example.test/other?operation=read",
        session_setup=setup,
    )
    assert captured[1]["authorization"].startswith("Basic ")
    assert "sid=SECRET" in captured[1]["cookie"]


def test_malformed_redirect_is_rejected_before_the_next_connection():
    guard = _guard()
    _install(guard, lambda _action: _allow())
    captured = []

    class Capture(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            captured.append(str(request.url))
            response = requests.Response()
            response.status_code = 302
            response.url = request.url
            response.request = request
            response.headers["Location"] = "https://example.test:99999/land"
            response.reason = "found"
            response._content = b""
            return response

    session = requests.Session()
    session.mount("https://", Capture())
    with pytest.raises(VardenBlockedError):
        session.get("https://example.test/start", timeout=2)
    assert captured == ["https://example.test/start"]


def _httpx_transport(location):
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(
            {
                "url": str(request.url),
                "authorization": request.headers.get("authorization"),
                "cookie": request.headers.get("cookie"),
                "proxy": request.headers.get("proxy-authorization"),
            }
        )
        # A query-only change of /start is the landing hop, not another redirect.
        if request.url.path == "/start" and not request.url.query:
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler), captured


@pytest.mark.parametrize("async_client", [False, True])
@pytest.mark.parametrize(
    ("start", "location", "keep"),
    [
        ("https://example.test/start", "https://other.test/land", False),
        ("https://example.test/start", "http://example.test/land", False),
        ("https://example.test/start", "https://example.test:8443/land", False),
        ("https://example.test/start", "https://example.test:443/other", True),
        ("https://example.test:8443/start", "https://example.test:443/land", False),
        ("https://example.test/start", "https://example.test/other", True),
        ("https://example.test/start", "https://example.test/start?operation=read", True),
        ("http://example.test/start", "https://example.test/land", False),
        ("https://EXAMPLE.TEST./start", "https://example.test/land", True),
    ],
)
def test_httpx_redirect_strips_credentials_only_when_the_origin_changes(async_client, start, location, keep):
    guard = _guard()
    seen = _install(guard, lambda _action: _allow())
    transport, captured = _httpx_transport(location)
    headers = {
        "Authorization": "Bearer SECRET",
        "Proxy-Authorization": "Basic cHJveHk=",
    }

    async def _run():
        async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
            client.cookies.set("sid", "SECRET", domain="example.test")
            return await client.get(start, headers=headers)

    if async_client:
        response = asyncio.run(_run())
    else:
        with httpx.Client(transport=transport, follow_redirects=True) as client:
            client.cookies.set("sid", "SECRET", domain="example.test")
            response = client.get(start, headers=headers)
    assert response.status_code == 200
    assert len(captured) == 2
    assert len(seen) >= 2
    assert captured[0]["authorization"] == "Bearer SECRET"
    assert captured[0]["proxy"] == "Basic cHJveHk="
    if keep:
        assert captured[1]["authorization"] == "Bearer SECRET"
        assert captured[1]["proxy"] == "Basic cHJveHk="
        assert captured[1]["cookie"] is not None and "sid=SECRET" in captured[1]["cookie"]
    else:
        assert captured[1]["authorization"] is None
        assert captured[1]["proxy"] is None
        assert captured[1]["cookie"] is None


def test_httpx_client_auth_is_not_rebuilt_on_an_origin_change():
    guard = _guard()
    _install(guard, lambda _action: _allow())
    transport, captured = _httpx_transport("http://example.test/land")
    with httpx.Client(
        transport=transport,
        follow_redirects=True,
        auth=("user", "password"),
    ) as client:
        response = client.get("https://example.test/start")
    assert response.status_code == 200
    assert captured[0]["authorization"].startswith("Basic ")
    assert captured[1]["authorization"] is None


def test_httpx_malformed_redirect_does_not_reach_the_transport():
    guard = _guard()
    _install(guard, lambda _action: _allow())
    transport, captured = _httpx_transport("https://example.test:99999/land")
    with httpx.Client(transport=transport, follow_redirects=True) as client, pytest.raises(VardenBlockedError):
        client.get("https://example.test/start")
    assert [hop["url"] for hop in captured] == ["https://example.test/start"]
