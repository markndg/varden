"""Phase 4 boundary gauntlet.

These tests record the address passed to ``socket.connect`` or the accepts
on a local listener. A policy decision alone is not evidence that a
forbidden destination was not contacted.

DNS answers come from an injected resolver. Nothing here dials a public host.
The 203.0.113.0/24 addresses are documentation addresses; the connect wrapper
refuses them immediately so the suite does not wait on an unreachable route.
"""

from __future__ import annotations

import contextvars
import json
import os
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import requests

import varden
from varden.action_identity import bind_security_identity
from varden.destination_binding import (
    DestinationBindingError,
    resolver_scope,
)
from varden.models import Action
from varden.runtime.coverage import ENFORCED, PARTIAL, UNCOVERED, CoverageRegistry, get_coverage_registry
from varden_sdk.sdk import VardenBlockedError, reconcile_runtime

_DOC_PREFIXES = ("203.0.113.", "10.", "192.168.", "169.254.", "172.16.")
_SIMULATED_PUBLIC = frozenset({"1.1.1.1", "8.8.8.8", "9.9.9.9"})


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
    seen = []

    def post(url, **kwargs):
        if "/sdk/guard" not in str(url):
            return _Resp({"ok": True})
        action = (kwargs.get("json") or {}).get("action") or {}
        seen.append(action)
        return _Resp(decide(action))

    guard.client._client.post = post
    return seen


def _binding(action):
    return ((action.get("metadata") or {}).get("destination_binding")) or {}


def _categories(action):
    return {item.get("category") for item in _binding(action).get("addresses") or []}


class _ConnectLog:
    def __init__(self):
        self.attempts: list[tuple] = []
        self._real = socket.socket.connect

    def __enter__(self):
        real = self._real
        attempts = self.attempts

        def connect(sock, address):
            attempts.append(address if isinstance(address, tuple) else (address,))
            host = address[0] if isinstance(address, tuple) else ""
            if isinstance(host, str) and (host in _SIMULATED_PUBLIC or host.startswith(_DOC_PREFIXES)):
                raise OSError(111, "connection refused")
            return real(sock, address)

        socket.socket.connect = connect
        return self

    def __exit__(self, *exc):
        socket.socket.connect = self._real
        return False

    def hosts(self):
        return [item[0] for item in self.attempts if item]


class _Listener(threading.Thread):
    def __init__(self, host="127.0.0.1"):
        super().__init__(daemon=True)
        self.host = host
        self.accepted: list[tuple] = []
        # Thread._stop is a method on Python 3.12 and earlier. An Event under
        # that name is called when the thread exits.
        self._stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]

    def run(self):
        self.sock.settimeout(0.1)
        while not self._stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            self.accepted.append(addr)
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            except OSError:
                pass
            conn.close()

    def close(self):
        self._stop_event.set()
        self.join(timeout=1)
        self.sock.close()


class _HTTP(ThreadingHTTPServer):
    def __init__(self, host="127.0.0.1"):
        self.hits: list[str] = []
        super().__init__((host, 0), _Handler)

    @property
    def url(self):
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        location = getattr(self.server, "redirect_to", None)
        if location and self.path == "/start":
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        return


def _session():
    session = requests.Session()
    session.trust_env = False
    return session


def _deny_nonpublic_hostnames(action):
    binding = _binding(action)
    host = binding.get("host")
    if host in {None, "127.0.0.1", "::1"}:
        return _allow()
    if _categories(action) & {"loopback", "private", "link_local", "metadata", "reserved"}:
        return _block()
    return _allow()


# --- Destination identity vs connection --------------------------------------


def test_url_identity_still_reports_hostname_rebinding_open():
    from varden.url_identity import canonicalize_destination

    dest = canonicalize_destination("https://example.com/a")
    assert dest.dns_rebinding == "open"
    assert canonicalize_destination("http://127.0.0.1/").dns_rebinding == "not_applicable"


def test_resolved_private_address_elevates_category_and_ignores_client_label():
    action = Action(
        type="http_request",
        url="https://rebind.test/a",
        metadata={
            "destination_binding": {
                "status": "pinned",
                "addresses": [{"ip": "10.1.2.3", "category": "public"}, {"ip": "not-an-ip", "category": "public"}],
            }
        },
    )
    bind_security_identity(action)
    assert action.metadata["destination"]["category"] == "private"
    assert action.metadata["identity"]["dns_rebinding"] == "open"
    assert action.metadata["identity"]["connection_binding"] == "pinned"
    assert action.metadata["destination"]["resolved_addresses"] == [{"ip": "10.1.2.3", "category": "private"}]


def test_literal_category_is_not_downgraded_by_a_claimed_public_address():
    action = Action(
        type="http_request",
        url="http://127.0.0.1/",
        metadata={"destination_binding": {"status": "literal", "addresses": [{"ip": "1.1.1.1", "category": "public"}]}},
    )
    bind_security_identity(action)
    assert action.metadata["destination"]["category"] == "loopback"


def test_public_resolution_then_rebinding_does_not_connect_to_loopback():
    """Authorization sees a documentation address. A later answer is loopback.

    The listener on 127.0.0.1 is the forbidden destination. It must accept
    nothing. The connect log must show the authorized address, not 127.0.0.1.
    """
    guard = _guard()
    answers = {"rebind.test": ["203.0.113.10"]}

    def resolver(host, port):
        return list(answers.get(host, []))

    def decide(action):
        answers["rebind.test"] = ["127.0.0.1"]
        return _allow()

    _install(guard, decide)
    forbidden = _Listener()
    forbidden.start()
    try:
        with resolver_scope(resolver), _ConnectLog() as log:
            session = _session()
            with pytest.raises(OSError):
                session.get(f"http://rebind.test:{forbidden.port}/secret", timeout=2)
        assert forbidden.accepted == []
        assert "127.0.0.1" not in log.hosts()
        assert "203.0.113.10" in log.hosts()
    finally:
        forbidden.close()


def test_rebinding_to_rfc1918_and_link_local_is_not_connected():
    guard = _guard()
    _install(guard, lambda action: _allow())
    cases = {
        "rfc1918.test": "10.2.3.4",
        "linklocal.test": "169.254.9.9",
    }
    for host, forbidden_ip in cases.items():
        answers = {host: ["203.0.113.20"]}

        def resolver(name, port, host=host, answers=answers):
            return list(answers[name])

        def decide(action, answers=answers, forbidden_ip=forbidden_ip, host=host):
            answers[host] = [forbidden_ip]
            return _allow()

        _install(guard, decide)
        with resolver_scope(resolver), _ConnectLog() as log:
            with pytest.raises(OSError):
                _session().get(f"http://{host}:9/x", timeout=2)
        assert forbidden_ip not in log.hosts()
        assert "203.0.113.20" in log.hosts()


def test_mixed_public_and_loopback_answers_connect_nowhere_when_blocked():
    guard = _guard()
    seen = _install(guard, _deny_nonpublic_hostnames)

    def resolver(host, port):
        return ["1.1.1.1", "127.0.0.1"]

    forbidden = _Listener()
    forbidden.start()
    try:
        with resolver_scope(resolver), _ConnectLog() as log:
            with pytest.raises(VardenBlockedError):
                _session().get(f"http://mixed.test:{forbidden.port}/x", timeout=2)
        assert forbidden.accepted == []
        assert "127.0.0.1" not in log.hosts()
        assert _categories(seen[-1]) >= {"public", "loopback"}
    finally:
        forbidden.close()


def test_ipv6_loopback_and_unique_local_categories_block_before_connect():
    guard = _guard()
    seen = _install(guard, _deny_nonpublic_hostnames)

    def resolver(host, port):
        if host == "v6loop.test":
            return ["::1"]
        if host == "ula.test":
            return ["fd12:3456:789a::1"]
        return []

    with resolver_scope(resolver), _ConnectLog() as log:
        with pytest.raises(VardenBlockedError):
            _session().get("http://v6loop.test/x", timeout=2)
        with pytest.raises(VardenBlockedError):
            _session().get("http://ula.test/x", timeout=2)
    assert log.attempts == []
    assert _categories(seen[0]) == {"loopback"}
    assert _categories(seen[1]) == {"private"}


def test_redirect_into_a_loopback_name_makes_no_second_connection():
    guard = _guard()
    _install(guard, _deny_nonpublic_hostnames)
    first = _HTTP()
    second = _Listener()
    second.start()
    first.redirect_to = f"http://evil.rebind:{second.port}/land"
    thread = threading.Thread(target=first.serve_forever, daemon=True)
    thread.start()

    def resolver(host, port):
        return ["127.0.0.1"]

    try:
        with resolver_scope(resolver), _ConnectLog() as log:
            with pytest.raises(VardenBlockedError):
                _session().get(f"http://127.0.0.1:{first.server_address[1]}/start", timeout=2)
        assert first.hits == ["/start"]
        assert second.accepted == []
        assert all(item[0] == "127.0.0.1" and item[1] == first.server_address[1] for item in log.attempts)
    finally:
        first.shutdown()
        first.server_close()
        second.close()


def test_allowed_literal_connects_and_a_later_name_lookup_does_not_redirect_it():
    guard = _guard()
    _install(guard, lambda action: _allow())
    server = _HTTP()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def resolver(host, port):
        raise AssertionError(f"literal destination must not be resolved: {host}")

    try:
        with resolver_scope(resolver):
            response = _session().get(server.url + "/ok", timeout=2)
        assert response.status_code == 200
        assert server.hits == ["/ok"]
    finally:
        server.shutdown()
        server.server_close()


def test_pooled_connection_to_the_old_address_is_not_reused():
    guard = _guard()
    _install(guard, lambda action: _allow())
    server = _HTTP()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    phase = {"second": False}

    def resolver(host, port):
        if phase["second"]:
            return ["203.0.113.40"]
        return ["127.0.0.1"]

    try:
        session = _session()
        with resolver_scope(resolver):
            first = session.get(f"http://pool.test:{server.server_address[1]}/one", timeout=2)
            assert first.status_code == 200
            phase["second"] = True
            with _ConnectLog() as log:
                with pytest.raises(OSError):
                    session.get(f"http://pool.test:{server.server_address[1]}/two", timeout=2)
        assert server.hits == ["/one"]
        assert "203.0.113.40" in log.hosts()
        assert "127.0.0.1" not in log.hosts()
    finally:
        server.shutdown()
        server.server_close()


def test_explicit_proxy_is_a_separate_boundary_and_can_be_blocked():
    guard = _guard()
    seen = _install(guard, lambda action: _block() if _binding(action).get("proxy") else _allow())
    proxy = _Listener()
    proxy.start()
    forbidden = _Listener()
    forbidden.start()

    def resolver(host, port):
        return ["10.9.9.9"]

    try:
        session = _session()
        session.proxies.update({"http": f"http://127.0.0.1:{proxy.port}"})
        with resolver_scope(resolver), _ConnectLog() as log:
            with pytest.raises(VardenBlockedError):
                session.get(f"http://target.test:{forbidden.port}/secret", timeout=2)
        assert proxy.accepted == []
        assert forbidden.accepted == []
        assert "10.9.9.9" not in log.hosts()
        assert seen[-1]["metadata"]["destination_binding"]["socket_bound"] is False
        assert seen[-1]["metadata"]["destination_binding"]["status"] == "proxy"
    finally:
        proxy.close()
        forbidden.close()


def test_allowed_proxy_receives_the_connection_and_the_target_ip_does_not():
    guard = _guard()
    _install(guard, lambda action: _allow())
    proxy = _Listener()
    proxy.start()

    def resolver(host, port):
        raise AssertionError("proxied target must not be locally resolved for the pin")

    try:
        session = _session()
        session.proxies.update({"http": f"http://127.0.0.1:{proxy.port}"})
        with resolver_scope(resolver), _ConnectLog() as log:
            try:
                session.get("http://target.test/secret", timeout=2)
            except requests.exceptions.RequestException:
                pass
        assert proxy.accepted
        assert "10.9.9.9" not in log.hosts()
    finally:
        proxy.close()


def test_unresolved_and_malformed_dns_make_no_connection():
    guard = _guard()
    _install(guard, lambda action: _allow())
    forbidden = _Listener()
    forbidden.start()

    def unresolved(host, port):
        raise DestinationBindingError("unresolved")

    def malformed(host, port):
        return ["not-an-ip", "999.999.999.999"]

    try:
        with _ConnectLog() as log:
            with resolver_scope(unresolved):
                with pytest.raises(VardenBlockedError):
                    _session().get(f"http://missing.test:{forbidden.port}/x", timeout=2)
            with resolver_scope(malformed):
                with pytest.raises(VardenBlockedError):
                    _session().get(f"http://bad.test:{forbidden.port}/x", timeout=2)
        assert forbidden.accepted == []
        assert log.attempts == []
    finally:
        forbidden.close()


def test_https_pin_keeps_the_hostname_for_certificate_verification(tmp_path):
    openssl = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    if openssl.returncode != 0:
        pytest.skip("openssl is not available")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    minted = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=pinned.test",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "subjectAltName=DNS:pinned.test",
        ],
        capture_output=True,
        text=True,
    )
    if minted.returncode != 0:
        pytest.skip(f"could not mint a certificate: {minted.stderr}")

    raw = socket.socket()
    raw.bind(("127.0.0.1", 0))
    raw.listen(1)
    port = raw.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    seen = []

    def serve():
        try:
            accepted, _addr = raw.accept()
        except OSError:
            return
        try:
            conn = context.wrap_socket(accepted, server_side=True)
        except OSError:
            accepted.close()
            return
        seen.append(True)
        try:
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except OSError:
            pass
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    guard = _guard()
    _install(guard, lambda action: _allow())

    def resolver(host, port):
        assert host == "pinned.test"
        return ["127.0.0.1"]

    try:
        with resolver_scope(resolver):
            response = _session().get(
                f"https://pinned.test:{port}/tls",
                timeout=2,
                verify=str(cert),
            )
        assert response.status_code == 200
        assert seen == [True]
    finally:
        raw.close()


def test_httpx_sync_and_async_pin_the_same_way():
    guard = _guard()
    _install(guard, _deny_nonpublic_hostnames)
    forbidden = _Listener()
    forbidden.start()

    def resolver(host, port):
        if host == "async.test":
            return ["10.8.8.8"]
        return ["1.1.1.1"]

    async def run_async():
        async with httpx.AsyncClient(trust_env=False) as client:
            await client.get(f"http://async.test:{forbidden.port}/x", timeout=2)

    try:
        with resolver_scope(resolver), _ConnectLog() as log:
            with pytest.raises((OSError, httpx.HTTPError)):
                with httpx.Client(trust_env=False) as client:
                    client.get(f"http://sync.test:{forbidden.port}/x", timeout=2)
            with pytest.raises(VardenBlockedError):
                import asyncio
                asyncio.run(run_async())
        assert forbidden.accepted == []
        assert "10.8.8.8" not in log.hosts()
        assert "1.1.1.1" in log.hosts()
    finally:
        forbidden.close()


def test_custom_transport_is_not_reported_as_socket_bound():
    guard = _guard()
    seen = _install(guard, lambda action: _allow())

    def handler(request):
        return httpx.Response(200, text="mocked")

    with httpx.Client(transport=httpx.MockTransport(handler), trust_env=False) as client:
        response = client.get("https://example.test/mocked")
    assert response.status_code == 200
    assert seen[-1]["metadata"]["destination_binding"]["socket_bound"] is False
    assert seen[-1]["metadata"]["destination_binding"]["status"] == "unbound"


# --- Runtime tamper ----------------------------------------------------------


def test_replacing_session_send_cannot_stay_enforced():
    guard = varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        mode="guarded",
        fail_mode="closed",
        require_coverage=["http.requests"],
    )
    _install(guard, lambda action: _block())
    reg = get_coverage_registry()
    assert reg.get("http.requests").status == ENFORCED
    import varden_sdk.sdk as sdk_mod

    requests.sessions.Session.send = sdk_mod._ORIGINALS["requests.sessions.Session.send"]
    ready = reg.strict_readiness()
    assert ready["ready"] is False
    assert reg.get("http.requests").status == UNCOVERED
    assert reg.get("http.requests").evidence.get("operational") is False
    assert reg.attestation()["tamper_events"]


def test_request_path_fails_closed_when_send_was_replaced(tmp_path):
    guard = _guard()
    _install(guard, lambda action: _allow())
    import varden_sdk.sdk as sdk_mod

    requests.sessions.Session.send = sdk_mod._ORIGINALS["requests.sessions.Session.send"]
    sentinel = tmp_path / "sent"
    with pytest.raises(VardenBlockedError):
        _session().get("http://127.0.0.1:9/nope", timeout=1)
    assert not sentinel.exists()
    assert get_coverage_registry().get("http.requests").status != ENFORCED


def test_safe_reconcile_restores_and_foreign_wrapper_does_not():
    _guard()
    import varden_sdk.sdk as sdk_mod

    original = sdk_mod._ORIGINALS["requests.sessions.Session.send"]
    wrapper = sdk_mod._WRAPPERS["requests.sessions.Session.send"]
    requests.sessions.Session.send = original
    restored = reconcile_runtime()
    assert restored["requests.sessions.Session.send"] == "restored"
    assert requests.sessions.Session.send is wrapper
    assert get_coverage_registry().get("http.requests").status == ENFORCED

    def foreign(*_args, **_kwargs):
        raise AssertionError("foreign send")

    requests.sessions.Session.send = foreign
    report = reconcile_runtime()
    assert report["requests.sessions.Session.send"] == "foreign"
    assert requests.sessions.Session.send is foreign
    assert get_coverage_registry().get("http.requests").status != ENFORCED


def test_locked_contract_ignores_field_mutation_and_attribute_assignment():
    guard = _guard()
    reg = get_coverage_registry()
    reg._mode = "observe"
    reg._fail_mode = "open"
    contract = reg.enforcement_contract()
    assert contract["mode"] == "guarded"
    assert contract["fail_mode"] == "closed"
    assert contract["mode_locked"] is True
    with pytest.raises(RuntimeError):
        guard.fail_mode = "open"
    with pytest.raises(RuntimeError):
        guard.product_mode = "observe"
    with pytest.raises(RuntimeError):
        reg.set_session(mode="observe", fail_mode="open", lock_mode=True)


def test_repeated_protect_does_not_drop_the_http_wrapper():
    first = _guard()
    import varden_sdk.sdk as sdk_mod

    wrapper = sdk_mod._WRAPPERS["requests.sessions.Session.send"]
    with pytest.raises(RuntimeError):
        varden.protect(
            base_url="http://testserver",
            api_key="k",
            emit_attestation=False,
            mode="observe",
            fail_mode="open",
        )
    assert requests.sessions.Session.send is wrapper
    assert get_coverage_registry().enforcement_contract()["mode"] == "guarded"
    _install(first, lambda action: _block())
    with pytest.raises(VardenBlockedError):
        _session().get("http://127.0.0.1:9/x", timeout=1)


def test_concurrent_tamper_cannot_report_ready():
    reg = CoverageRegistry()
    state = {"ok": True}
    entered = threading.Event()
    release = threading.Event()

    def checker():
        entered.set()
        release.wait(timeout=2)
        return state["ok"]

    reg.register_interceptor_check("http.requests", checker)
    reg.mark("http.requests", status=ENFORCED, active=True, applicable=True, verified=True)
    reg.set_session(mode="strict", fail_mode="closed", require_coverage=["http"], lock_mode=True)

    def tamper():
        assert entered.wait(timeout=2)
        state["ok"] = False
        release.set()

    threading.Thread(target=tamper, daemon=True).start()
    ready = reg.strict_readiness()
    assert ready["ready"] is False
    assert reg.get("http.requests").status != ENFORCED


def test_unknown_required_surface_is_not_ready():
    reg = CoverageRegistry()
    reg.set_session(mode="strict", fail_mode="closed", require_coverage=["not.a.surface"], lock_mode=True)
    ready = reg.strict_readiness()
    assert ready["ready"] is False
    assert "not.a.surface" in ready["required_coverage_missing"]


# --- Filesystem --------------------------------------------------------------


def _fs_guard(decide):
    guard = _guard()
    _install(guard, decide)
    return guard


def test_dir_fd_relative_secret_is_not_opened(tmp_path):
    secret_dir = tmp_path / ".ssh"
    secret_dir.mkdir()
    secret = secret_dir / "notes.txt"
    secret.write_text("secret-body")
    before = secret.stat().st_size
    fd = os.open(secret_dir, os.O_RDONLY)
    _fs_guard(
        lambda action: _block()
        if ((action.get("metadata") or {}).get("filesystem") or {}).get("classification") == "secrets"
        else _allow()
    )
    try:
        with pytest.raises(VardenBlockedError):
            os.open("notes.txt", os.O_RDONLY, dir_fd=fd)
    finally:
        os.close(fd)
    assert secret.stat().st_size == before


def test_unresolvable_dir_fd_is_refused(tmp_path):
    _fs_guard(lambda action: _allow())
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(VardenBlockedError) as caught:
            os.open("notes.txt", os.O_RDONLY, dir_fd=read_fd)
        assert caught.value.decision.get("reason") == "filesystem_dir_fd_unresolved"
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_dir_fd_rmtree_of_a_temp_directory_still_works(tmp_path):
    import shutil

    _fs_guard(lambda action: _allow())
    target = tmp_path / "tree"
    target.mkdir()
    (target / "leaf.txt").write_text("x")
    shutil.rmtree(target)
    assert not target.exists()


def test_symlink_swap_after_check_does_not_open_the_secret(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("SECRET-KEY")
    benign = tmp_path / "notes.txt"
    benign.write_text("hello")
    real_open = os.open
    real_remove = os.remove
    real_symlink = os.symlink

    def shim(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(benign):
            real_remove(benign)
            real_symlink(secret, benign)
        return real_open(path, flags, *args, **kwargs)

    os.open = shim
    try:
        _fs_guard(lambda action: _allow())
        with pytest.raises(OSError):
            fd = os.open(benign, os.O_RDONLY)
            os.close(fd)
    finally:
        import varden_sdk.sdk as sdk_mod

        if sdk_mod._ORIGINALS.get("os.open") is shim:
            sdk_mod._ORIGINALS["os.open"] = real_open
        os.open = real_open
    assert secret.read_text() == "SECRET-KEY"


def test_preexisting_hard_link_is_not_contained(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("SECRET-KEY")
    alias = tmp_path / "notes.txt"
    os.link(secret, alias)
    _fs_guard(lambda action: _block() if "id_rsa" in json.dumps(action) else _allow())
    with open(alias) as handle:
        body = handle.read()
    assert body == "SECRET-KEY"
    surface = get_coverage_registry().get("filesystem")
    assert surface.status == PARTIAL
    assert any("hard link" in item.lower() for item in surface.limitations)


def test_async_task_does_not_inherit_filesystem_passthrough(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("SECRET-KEY")
    calls = {"n": 0}

    def decide(action):
        calls["n"] += 1
        if calls["n"] == 1:
            return _allow()
        return _block()

    real_open = open

    def shim(file, *args, **kwargs):
        box = {}

        def child():
            try:
                with open(file) as handle:
                    box["data"] = handle.read()
            except VardenBlockedError:
                box["blocked"] = True

        ctx = contextvars.copy_context()
        worker = threading.Thread(target=lambda: ctx.run(child))
        worker.start()
        worker.join()
        assert box.get("blocked") is True
        assert "data" not in box
        return real_open(file, *args, **kwargs)

    import builtins

    import varden_sdk.sdk as sdk_mod

    builtins.open = shim
    try:
        _fs_guard(decide)
        with open(secret) as handle:
            assert handle.read() == "SECRET-KEY"
    finally:
        if sdk_mod._ORIGINALS.get("builtins.open") is shim:
            sdk_mod._ORIGINALS["builtins.open"] = real_open
        builtins.open = real_open
    assert calls["n"] >= 2


def test_native_descriptor_access_is_named_unsupported(tmp_path):
    surface_limits = []
    _fs_guard(lambda action: _allow())
    surface = get_coverage_registry().get("filesystem")
    surface_limits.extend(surface.limitations)
    text = " ".join(surface_limits).lower()
    assert "raw file descriptor" in text or "native" in text
    assert surface.status == PARTIAL
    # A descriptor obtained before interception is not mediated. This is the
    # explicit unsupported case, not a claim that the bytes were blocked.
    fd = os.open(os.devnull, os.O_RDONLY)
    try:
        os.read(fd, 1)
    finally:
        os.close(fd)
