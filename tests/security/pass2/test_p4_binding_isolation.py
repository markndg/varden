"""Operation-scoped destination binding and pooled-peer verification.

Connection evidence is the address passed to the socket or to ``anyio.connect_tcp``.
A policy decision alone is not the assertion.
"""

from __future__ import annotations

import asyncio
import socket
import threading

import anyio
import httpx
import pytest
import requests

import varden
from tests.security.pass2.test_p4_boundary_integrity import (
    _allow,
    _guard,
    _install,
    _session,
)
from varden.destination_binding import (
    DestinationBinding,
    ResolvedAddress,
    binding_for_host,
    operation_bindings,
    pinned_connection,
    resolver_scope,
    transport_binding_installed,
)

_A = "203.0.113.10"
_B = "203.0.113.20"
_C = "203.0.113.30"


@pytest.fixture(autouse=True)
def _reset_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()


def _refuse_connect():
    real = socket.socket.connect
    seen: list[tuple[int, str]] = []

    def connect(sock, address):
        host = address[0] if isinstance(address, tuple) else ""
        seen.append((threading.get_ident(), str(host)))
        if str(host).startswith("203.0.113.") or str(host).startswith("198.51.100."):
            raise OSError(111, "connection refused")
        return real(sock, address)

    socket.socket.connect = connect
    return seen, real


def test_two_threads_do_not_share_a_hostname_pin():
    guard = _guard()
    _install(guard, lambda action: _allow())
    session = _session()
    seen, real = _refuse_connect()
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def connect(sock, address):
        host = address[0] if isinstance(address, tuple) else ""
        seen.append((threading.get_ident(), str(host)))
        try:
            barrier.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        raise OSError(111, "connection refused")

    socket.socket.connect = connect

    def work(ip: str):
        def resolver(_host, _port):
            return [ip]

        try:
            with resolver_scope(resolver):
                try:
                    session.get("http://same.test/x", timeout=2)
                except requests.exceptions.RequestException:
                    pass
        except Exception as exc:  # noqa: BLE001 - the assertion reports the worker failure
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(ip,)) for ip in (_A, _B)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    socket.socket.connect = real
    assert not errors
    by_thread: dict[int, set[str]] = {}
    for ident, host in seen:
        by_thread.setdefault(ident, set()).add(host)
    assert set().union(*by_thread.values()) == {_A, _B}
    for hosts in by_thread.values():
        assert len(hosts) == 1
    assert operation_bindings() == ()


def test_two_asyncio_tasks_do_not_share_a_hostname_pin():
    guard = _guard()
    _install(guard, lambda action: _allow())
    seen: list[tuple[str, str]] = []
    arrived = {"n": 0}
    release = asyncio.Event()

    async def fake_connect_tcp(*, remote_host, remote_port, **_kwargs):
        task = asyncio.current_task()
        seen.append((task.get_name() if task else "", str(remote_host)))
        arrived["n"] += 1
        if arrived["n"] >= 2:
            release.set()
        await release.wait()
        raise OSError(111, "connection refused")

    async def one(name: str, ip: str):
        asyncio.current_task().set_name(name)  # type: ignore[union-attr]

        def resolver(_host, _port):
            return [ip]

        with resolver_scope(resolver):
            async with httpx.AsyncClient(trust_env=False) as client:
                try:
                    await client.get("http://same.test/x", timeout=2)
                except httpx.HTTPError:
                    pass

    async def run():
        original = anyio.connect_tcp
        anyio.connect_tcp = fake_connect_tcp
        try:
            await asyncio.gather(one("task-a", _A), one("task-b", _B))
        finally:
            anyio.connect_tcp = original

    asyncio.run(run())
    assert seen
    by_task: dict[str, set[str]] = {}
    for name, host in seen:
        by_task.setdefault(name, set()).add(host)
    assert by_task["task-a"] == {_A}
    assert by_task["task-b"] == {_B}
    assert operation_bindings() == ()


def test_nested_request_uses_its_own_authorization():
    guard = _guard()
    _install(guard, lambda action: _allow())
    session = _session()
    seen: list[str] = []
    real = socket.socket.connect
    nested = {"done": False}

    def connect(sock, address):
        host = str(address[0] if isinstance(address, tuple) else "")
        seen.append(host)
        if host == _A and not nested["done"]:
            nested["done"] = True

            def resolver(_host, _port):
                return [_B]

            with resolver_scope(resolver):
                try:
                    session.get("http://same.test/inner", timeout=2)
                except requests.exceptions.RequestException:
                    pass
        raise OSError(111, "connection refused")

    socket.socket.connect = connect
    try:
        def resolver(_host, _port):
            return [_A]

        with resolver_scope(resolver), pytest.raises(requests.exceptions.RequestException):
            session.get("http://same.test/outer", timeout=2)
    finally:
        socket.socket.connect = real
    assert _A in seen and _B in seen
    assert seen[0] == _A
    assert _B in seen[1:]
    assert operation_bindings() == ()


def test_unrelated_getaddrinfo_does_not_inherit_the_pin():
    guard = _guard()
    _install(guard, lambda action: _allow())
    session = _session()
    looked: list[str] = []
    dialed: list[str] = []
    real = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def connect(sock, address):
        host = str(address[0] if isinstance(address, tuple) else "")
        dialed.append(host)

        def worker():
            try:
                real_getaddrinfo("not-a-real-host.invalid", 80)
                looked.append("resolved")
            except socket.gaierror:
                looked.append("gaierror")

        other = threading.Thread(target=worker)
        other.start()
        other.join(timeout=2)
        # Same-thread library lookup while this operation is dialing.
        try:
            real_getaddrinfo("not-a-real-host.invalid", 9)
            looked.append("same-thread-resolved")
        except socket.gaierror:
            looked.append("same-thread-gaierror")
        raise OSError(111, "connection refused")

    socket.socket.connect = connect
    try:
        def resolver(_host, _port):
            return [_A]

        with resolver_scope(resolver), pytest.raises(requests.exceptions.RequestException):
            session.get("http://same.test/x", timeout=2)
    finally:
        socket.socket.connect = real
    assert "gaierror" in looked
    assert "same-thread-gaierror" in looked
    assert dialed == [_A]
    assert operation_bindings() == ()


def test_cancelled_task_does_not_leave_its_binding():
    guard = _guard()
    _install(guard, lambda action: _allow())
    started = asyncio.Event()

    async def fake_connect_tcp(*, remote_host, remote_port, **_kwargs):
        if str(remote_host) == _A:
            started.set()
            await asyncio.Event().wait()
        raise OSError(111, "connection refused")

    async def run():
        original = anyio.connect_tcp
        anyio.connect_tcp = fake_connect_tcp
        try:
            async def first():
                def resolver(_host, _port):
                    return [_A]

                with resolver_scope(resolver):
                    async with httpx.AsyncClient(trust_env=False) as client:
                        await client.get("http://same.test/x", timeout=2)

            task = asyncio.create_task(first())
            await asyncio.wait_for(started.wait(), timeout=2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert operation_bindings() == ()

            seen: list[str] = []

            async def second_connect(*, remote_host, remote_port, **_kwargs):
                seen.append(str(remote_host))
                raise OSError(111, "connection refused")

            anyio.connect_tcp = second_connect

            def resolver(_host, _port):
                return [_B]

            with resolver_scope(resolver):
                async with httpx.AsyncClient(trust_env=False) as client:
                    try:
                        await client.get("http://same.test/y", timeout=2)
                    except httpx.HTTPError:
                        pass
            assert seen == [_B]
            assert operation_bindings() == ()
        finally:
            anyio.connect_tcp = original

    asyncio.run(run())


def test_redirect_and_concurrent_request_keep_separate_addresses():
    guard = _guard()
    _install(guard, lambda action: _allow())
    seen, real = _refuse_connect()
    # First hop of the redirecting caller is a literal listener. The redirect
    # name is resolved to _C while the other thread resolves the same name to _B.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://same.test/next")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ready = threading.Event()

    def redirecting():
        calls = {"n": 0}

        def resolver(host, _port):
            if host == "same.test":
                calls["n"] += 1
                return [_C]
            return ["127.0.0.1"]

        try:
            with resolver_scope(resolver):
                ready.wait(timeout=2)
                try:
                    _session().get(f"http://127.0.0.1:{port}/start", timeout=2, allow_redirects=True)
                except requests.exceptions.RequestException:
                    pass
        finally:
            ready.set()

    def other():
        def resolver(_host, _port):
            return [_B]

        ready.wait(timeout=2)
        with resolver_scope(resolver):
            try:
                _session().get("http://same.test/other", timeout=2)
            except requests.exceptions.RequestException:
                pass

    left = threading.Thread(target=redirecting)
    right = threading.Thread(target=other)
    left.start()
    right.start()
    left.join(timeout=5)
    right.join(timeout=5)
    server.shutdown()
    socket.socket.connect = real
    hosts = [host for _ident, host in seen]
    assert _C in hosts
    assert _B in hosts
    # The redirecting thread's non-literal dial is _C, never _B.
    redirect_ident = left.ident
    redirect_hosts = {host for ident, host in seen if ident == redirect_ident}
    assert _C in redirect_hosts
    assert _B not in redirect_hosts


def test_binding_is_cleared_when_connect_fails():
    guard = _guard()
    _install(guard, lambda action: _allow())
    session = _session()
    real = socket.socket.connect

    def connect(sock, address):
        raise OSError(111, "connection refused")

    socket.socket.connect = connect
    try:
        def resolver(_host, _port):
            return [_A]

        with resolver_scope(resolver), pytest.raises(requests.exceptions.RequestException):
            session.get("http://same.test/x", timeout=2)
        assert operation_bindings() == ()
    finally:
        socket.socket.connect = real


def test_known_allowed_peer_is_reused():
    guard = _guard()
    _install(guard, lambda action: _allow())
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    connects = {"n": 0}
    real = socket.socket.connect

    def connect(sock, address):
        connects["n"] += 1
        return real(sock, address)

    socket.socket.connect = connect
    session = _session()
    try:
        def resolver(_host, _port):
            return ["127.0.0.1"]

        with resolver_scope(resolver):
            first = session.get(f"http://reuse.test:{port}/one", timeout=2)
            second = session.get(f"http://reuse.test:{port}/two", timeout=2)
        assert first.text == "ok" and second.text == "ok"
        assert connects["n"] == 1
    finally:
        socket.socket.connect = real
        server.shutdown()


def test_disallowed_and_unknown_pooled_peers_are_not_reused():
    guard = _guard()
    _install(guard, lambda action: _allow())
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    hits = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits["n"] += 1
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    seen: list[str] = []
    real = socket.socket.connect

    def connect(sock, address):
        seen.append(str(address[0]))
        if str(address[0]).startswith("203.0.113."):
            raise OSError(111, "connection refused")
        return real(sock, address)

    socket.socket.connect = connect
    session = _session()
    try:
        calls = {"n": 0}

        def resolver(_host, _port):
            calls["n"] += 1
            if calls["n"] == 1:
                return ["127.0.0.1"]
            return [_B]

        with resolver_scope(resolver):
            ok = session.get(f"http://reuse.test:{port}/one", timeout=2)
            assert ok.text == "ok"
            with pytest.raises(requests.exceptions.RequestException):
                session.get(f"http://reuse.test:{port}/two", timeout=2)
        assert hits["n"] == 1
        assert _B in seen
        assert seen[-1] == _B
    finally:
        socket.socket.connect = real
        server.shutdown()

    # A connection whose peer cannot be read is closed instead of reused.
    session = _session()
    connects = {"n": 0}
    socket.socket.connect = connect
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        def resolver(_host, _port):
            return ["127.0.0.1"]

        with resolver_scope(resolver):
            assert session.get(f"http://reuse.test:{port}/one", timeout=2).text == "ok"

        class BadSock:
            def getpeername(self):
                raise OSError("peer unavailable")

        class FakeConn:
            def __init__(self):
                self.sock = BadSock()
                self.closed = False

            @property
            def is_connected(self):
                return True

            def close(self):
                self.closed = True

        adapter = session.get_adapter(f"http://reuse.test:{port}/")
        key = next(iter(adapter.poolmanager.pools.keys()))
        pool = adapter.poolmanager.pools[key]
        idle = pool.pool.get(block=False)
        fake = FakeConn()
        pool.pool.put(fake, block=False)

        def counting(sock, address):
            connects["n"] += 1
            return real(sock, address)

        socket.socket.connect = counting
        with resolver_scope(resolver):
            assert session.get(f"http://reuse.test:{port}/again", timeout=2).text == "ok"
        assert fake.closed
        assert connects["n"] == 1
        idle.close()
    finally:
        socket.socket.connect = real
        server.shutdown()


def test_http2_style_connection_with_unknown_peer_is_not_reused():
    guard = _guard()
    _install(guard, lambda action: _allow())
    used = {"n": 0}

    class FakeH2:
        def can_handle_request(self, origin):
            return True

        def is_available(self):
            return True

        def is_idle(self):
            return False

        def is_closed(self):
            return False

        def has_expired(self):
            return False

        def handle_request(self, request):
            used["n"] += 1
            raise AssertionError("multiplexed onto an unverified connection")

        async def handle_async_request(self, request):
            self.handle_request(request)

        async def aclose(self):
            return None

        _connection = object()

    seen: list[str] = []

    async def fake_connect_tcp(*, remote_host, remote_port, **_kwargs):
        seen.append(str(remote_host))
        raise OSError(111, "connection refused")

    async def run():
        original = anyio.connect_tcp
        anyio.connect_tcp = fake_connect_tcp
        try:
            def resolver(_host, _port):
                return [_A]

            with resolver_scope(resolver):
                async with httpx.AsyncClient(trust_env=False) as client:
                    pool = client._transport._pool
                    pool._connections.append(FakeH2())
                    try:
                        await client.get("http://same.test/x", timeout=2)
                    except httpx.HTTPError:
                        pass
        finally:
            anyio.connect_tcp = original

    asyncio.run(run())
    assert used["n"] == 0
    assert seen == [_A]


def test_repeated_activation_restores_transport_bindings():
    _guard()
    assert transport_binding_installed()
    varden.unpatch_runtime()
    assert not transport_binding_installed()
    _guard()
    assert transport_binding_installed()
    with pytest.raises(RuntimeError):
        varden.protect(base_url="http://testserver", api_key="k", emit_attestation=False, mode="observe", fail_mode="open")
    assert transport_binding_installed()


def test_connect_failure_during_nested_pin_clears_only_the_inner_binding():
    """An inner failure must not drop the outer operation's authorization."""
    _guard()
    outer = DestinationBinding(
        url="http://same.test/",
        host="same.test",
        port=80,
        scheme="http",
        addresses=(ResolvedAddress(_A, "private"),),
        status="pinned",
        socket_bound=True,
    )
    inner = DestinationBinding(
        url="http://same.test/in",
        host="same.test",
        port=80,
        scheme="http",
        addresses=(ResolvedAddress(_B, "private"),),
        status="pinned",
        socket_bound=True,
    )
    with pinned_connection(outer):
        assert binding_for_host("same.test").address_ips == (_A,)
        with pytest.raises(RuntimeError), pinned_connection(inner):
            assert binding_for_host("same.test").address_ips == (_B,)
            raise RuntimeError("boom")
        assert binding_for_host("same.test").address_ips == (_A,)
    assert operation_bindings() == ()
