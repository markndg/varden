"""Phase 3: a block must prevent the side effect, not only return a decision.

Sentinels are temporary files, local HTTP servers, and fake MCP stdin.
Nothing here contacts an external network.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import httpx
import pytest
import requests

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.runtime.coverage import ENFORCED, PARTIAL, UNCOVERED, get_coverage_registry
from varden.runtime.guard_response import response_authorizes_execution
from varden.runtime.mcp_gateway import McpGatewaySession
from varden.runtime.mcp_host import VardenMcpHost
from varden.url_identity import canonicalize_destination
from varden_sdk.sdk import VardenBlockedError


class _Resp:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.headers = {"content-type": "application/json"}
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode()

    def json(self):
        if isinstance(self._body, str):
            return json.loads(self._body)
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://testserver/sdk/guard")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("error", request=request, response=response)


def _stub(guard, status: int, body, *, error: BaseException | None = None):
    def post(*_args, **_kwargs):
        if error is not None:
            raise error
        return _Resp(status, body)

    guard.client._client.post = post


_ALLOW = {"decision": {"action": "allow", "reason": "ok"}, "action": {}, "event_id": 1}


@pytest.fixture(autouse=True)
def _reset_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()


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
    if params.get("mode") == "strict" and "allow_uncovered" not in params:
        # The matrix checks decision enforcement, not the strict coverage gate.
        params["allow_uncovered"] = ["http", "subprocess"]
    return varden.protect(**params)


# --- Decision matrix ---------------------------------------------------------
# observe always executes. strict refuses fail_mode=open at construction.
# A delivered deny, ambiguous decision, or completed response without a
# decision does not execute. fail_mode=open executes for a transport failure,
# and for a non-success status whose body is an authoritative allow.


_MATRIX = [
    ("observe", "open", 200, {"decision": {"action": "block"}}, None, True),
    ("observe", "closed", 200, {"decision": {"action": "block"}}, None, True),
    ("guarded", "closed", 200, {"decision": {"action": "allow"}}, None, True),
    ("guarded", "closed", 200, {"decision": {"action": "block"}}, None, False),
    ("guarded", "open", 200, {"decision": {"action": "block"}}, None, False),
    ("guarded", "closed", 200, {"decision": {"action": "require_approval"}}, None, False),
    ("guarded", "open", 200, {"decision": {"action": "require_approval"}}, None, False),
    ("guarded", "open", 200, {"decision": {"action": "approval_required"}}, None, False),
    ("guarded", "open", 403, {"decision": {"action": "allow"}}, None, False),
    ("guarded", "open", 200, {"decision": {"action": "not-a-decision"}}, None, False),
    ("guarded", "open", 200, {}, None, False),
    ("guarded", "closed", 200, {}, None, False),
    ("guarded", "open", 500, {"detail": "down"}, None, False),
    ("guarded", "closed", 500, {"detail": "down"}, None, False),
    ("guarded", "open", 503, {"decision": {"action": "allow"}, "action": {}, "event_id": 1}, None, True),
    ("guarded", "closed", 503, {"decision": {"action": "allow"}, "action": {}, "event_id": 1}, None, False),
    ("guarded", "open", 503, {"detail": {"decision": {"action": "require_approval"}}}, None, False),
    ("guarded", "open", 200, _ALLOW, TimeoutError("timed out"), True),
    ("guarded", "closed", 200, _ALLOW, TimeoutError("timed out"), False),
    ("guarded", "open", 200, _ALLOW, ConnectionError("refused"), True),
    ("guarded", "closed", 200, _ALLOW, ConnectionError("refused"), False),
    ("strict", "closed", 200, {"decision": {"action": "block"}}, None, False),
    ("strict", "closed", 200, {"decision": {"action": "require_approval"}}, None, False),
]


@pytest.mark.parametrize("mode,fail_mode,status,body,error,executes", _MATRIX)
def test_fail_mode_matrix_side_effect(tmp_path, mode, fail_mode, status, body, error, executes):
    sentinel = tmp_path / "effect.txt"
    guard = _protect(mode=mode, fail_mode=fail_mode)
    _stub(guard, status, body, error=error)

    def tool():
        sentinel.write_text("ran", encoding="utf-8")
        return "ok"

    wrapped = guard.guard_tool(tool, name="delete_database")
    if executes:
        assert wrapped() == "ok"
        assert sentinel.read_text(encoding="utf-8") == "ran"
    else:
        with pytest.raises(VardenBlockedError):
            wrapped()
        assert not sentinel.exists()


def test_strict_refuses_fail_open():
    with pytest.raises(ValueError):
        _protect(mode="strict", fail_mode="open")


def test_missing_decision_is_not_authorization():
    assert response_authorizes_execution({}) is False
    assert response_authorizes_execution({"decision": {"action": "allow"}}) is True
    assert response_authorizes_execution({"decision": {"action": "block"}}) is False
    assert response_authorizes_execution({"detail": "not a decision"}) is False


# --- Filesystem --------------------------------------------------------------


def _read_unpatched(path: Path) -> str:
    from varden_sdk import sdk as sdk_mod

    opener = sdk_mod._ORIGINALS.get("builtins.open", open)
    with opener(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _fs_guard(tmpdir: str, policy: dict):
    client, _app = make_app_client(tmpdir, policy=policy)
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
    wire_guard_to_app(guard, client)
    return client, guard


_SECRET_BLOCK = {
    "block": [
        {"type": "filesystem", "field:metadata.filesystem.classification": {"in": ["secrets", "system"]}},
        {"type": "filesystem", "field:metadata.filesystem_source.classification": {"in": ["secrets", "system"]}},
        {"type": "filesystem", "field:metadata.mutation": "WRITE_CI"},
        {"type": "filesystem", "field:metadata.filesystem.mutation": "WRITE_CI"},
        {"type": "filesystem", "field:metadata.filesystem_destination.mutation": "WRITE_CI"},
    ],
    "warn": [],
    "monitor": [],
    "allow": [],
}


def test_keyword_remove_and_rename_produce_no_side_effect(tmp_path):
    with TemporaryDirectory() as td:
        ws = Path(td) / "ws"
        secret = ws / "id_rsa"
        secret.parent.mkdir()
        secret.write_text("PRIVATE", encoding="utf-8")
        src = ws / "benign.txt"
        src.write_text("x", encoding="utf-8")
        workflows = ws / ".github" / "workflows"
        workflows.mkdir(parents=True)
        dst = workflows / "evil.yml"
        _fs_guard(td, _SECRET_BLOCK)
        prev = os.getcwd()
        try:
            os.chdir(ws)
            with pytest.raises(VardenBlockedError):
                os.remove(path=secret)
            assert _read_unpatched(secret) == "PRIVATE"
            with pytest.raises(VardenBlockedError):
                os.rename(src=src, dst=dst)
            assert src.exists()
            assert not dst.exists()
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_os_open_and_path_touch_do_not_open_or_create_secrets(tmp_path):
    with TemporaryDirectory() as td:
        ws = Path(td) / "ws"
        ws.mkdir()
        secret = ws / "id_rsa"
        secret.write_text("PRIVATE", encoding="utf-8")
        touched = ws / "credentials.json"
        _fs_guard(td, _SECRET_BLOCK)
        prev = os.getcwd()
        try:
            os.chdir(ws)
            marker = object()
            opened = marker
            with pytest.raises(VardenBlockedError):
                opened = os.open(secret, os.O_RDONLY)
            assert opened is marker
            with pytest.raises(VardenBlockedError):
                opened = os.open(path=os.fspath(secret), flags=os.O_RDONLY)
            assert opened is marker
            with pytest.raises(VardenBlockedError):
                touched.touch()
            assert not touched.exists()
            assert _read_unpatched(secret) == "PRIVATE"
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_hard_link_of_secret_is_not_created(tmp_path):
    with TemporaryDirectory() as td:
        ws = Path(td) / "ws"
        ws.mkdir()
        secret = ws / "id_rsa"
        secret.write_text("PRIVATE", encoding="utf-8")
        alias = ws / "notes.txt"
        _fs_guard(td, _SECRET_BLOCK)
        prev = os.getcwd()
        try:
            os.chdir(ws)
            with pytest.raises(VardenBlockedError):
                os.link(secret, alias)
            assert not alias.exists()
            assert _read_unpatched(secret) == "PRIVATE"
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_dir_fd_secret_name_is_not_opened(tmp_path):
    """A secret basename is still mediated when passed with dir_fd.

    A benign relative name against an untracked directory descriptor is not
    contained. That case stays PARTIAL rather than denying every dir_fd call,
    which would stop the process deleting its own temporary files.
    """
    with TemporaryDirectory() as td:
        ws = Path(td) / "ws"
        ws.mkdir()
        secret = ws / "id_rsa"
        secret.write_text("PRIVATE", encoding="utf-8")
        _fs_guard(td, _SECRET_BLOCK)
        dirfd = os.open(ws, os.O_RDONLY)
        try:
            marker = object()
            opened = marker
            with pytest.raises(VardenBlockedError):
                opened = os.open("id_rsa", os.O_RDONLY, dir_fd=dirfd)
            assert opened is marker
            assert _read_unpatched(secret) == "PRIVATE"
        finally:
            os.close(dirfd)
            varden.unpatch_runtime()


def test_allowed_workspace_write_still_happens(tmp_path):
    with TemporaryDirectory() as td:
        _fs_guard(td, {"block": [], "warn": [], "monitor": [], "allow": []})
        ws = Path(td) / "ws"
        ws.mkdir()
        path = ws / "notes.txt"
        prev = os.getcwd()
        try:
            os.chdir(ws)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("hello")
            assert path.read_text(encoding="utf-8") == "hello"
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_filesystem_coverage_stays_partial(tmp_path):
    with TemporaryDirectory() as td:
        try:
            _fs_guard(td, {"block": [], "warn": [], "monitor": [], "allow": []})
            surface = get_coverage_registry().get("filesystem")
            assert surface is not None
            assert surface.status == PARTIAL
            text = " ".join(surface.limitations).lower()
            assert "toctou" in text or "race" in text
            assert "dir_fd" in text
            assert "enforced for secrets" not in text
        finally:
            varden.unpatch_runtime()


# --- Subprocess --------------------------------------------------------------


_BLOCK_TOOLS = {
    "block": [{"type": "tool_call"}],
    "require_approval": [],
    "warn": [],
    "monitor": [],
    "allow": [],
}

_APPROVE_TOOLS = {
    "block": [],
    "require_approval": [{"type": "tool_call"}],
    "warn": [],
    "monitor": [],
    "allow": [],
}


def _write_cmd(path: Path) -> list[str]:
    code = f"open({str(path)!r}, 'w', encoding='utf-8').write('ran')"
    return [sys.executable, "-c", code]


def test_blocked_subprocess_forms_create_no_child_file(tmp_path):
    import subprocess

    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=_BLOCK_TOOLS)
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(
            base_url="http://testserver",
            api_key=key,
            emit_attestation=False,
            fail_mode="open",
        )
        wire_guard_to_app(guard, client)
        targets = {
            "run": tmp_path / "run.txt",
            "call": tmp_path / "call.txt",
            "popen": tmp_path / "popen.txt",
            "system": tmp_path / "system.txt",
            "shell": tmp_path / "shell.txt",
        }
        with pytest.raises(VardenBlockedError):
            subprocess.run(_write_cmd(targets["run"]), check=False)
        with pytest.raises(VardenBlockedError):
            subprocess.call(_write_cmd(targets["call"]))
        with pytest.raises(VardenBlockedError):
            subprocess.Popen(_write_cmd(targets["popen"]))
        with pytest.raises(VardenBlockedError):
            os.system(" ".join(_write_cmd(targets["system"])))
        with pytest.raises(VardenBlockedError):
            subprocess.run(" ".join(_write_cmd(targets["shell"])), shell=True, check=False)
        for path in targets.values():
            assert not path.exists(), path


def test_allowed_subprocess_creates_the_sentinel(tmp_path):
    import subprocess

    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy={"block": [], "warn": [], "monitor": [], "allow": []})
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        sentinel = tmp_path / "allowed.txt"
        completed = subprocess.run(_write_cmd(sentinel), check=True, capture_output=True)
        assert completed.returncode == 0
        assert sentinel.read_text(encoding="utf-8") == "ran"


def test_approval_required_subprocess_does_not_start(tmp_path):
    import subprocess

    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=_APPROVE_TOOLS)
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False, fail_mode="open")
        wire_guard_to_app(guard, client)
        sentinel = tmp_path / "held.txt"
        with pytest.raises(VardenBlockedError):
            subprocess.run(_write_cmd(sentinel), check=False)
        assert not sentinel.exists()


def test_blocked_asyncio_subprocess_creates_no_file(tmp_path):
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=_BLOCK_TOOLS)
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        sentinel = tmp_path / "async.txt"

        async def go():
            await asyncio.create_subprocess_exec(*_write_cmd(sentinel))

        with pytest.raises(VardenBlockedError):
            asyncio.run(go())
        assert not sentinel.exists()


def test_subprocess_coverage_names_unpatched_exec(tmp_path):
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy={"block": [], "warn": [], "monitor": [], "allow": []})
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(varden.current_guard(), client)
        surface = get_coverage_registry().get("subprocess")
        assert surface is not None
        assert surface.status == ENFORCED
        assert any("os.exec" in item for item in surface.limitations)


# --- MCP ---------------------------------------------------------------------


def _gateway_session():
    written: list[str] = []

    class Stdin:
        def write(self, data):
            written.append(data)

        def flush(self):
            pass

    session = McpGatewaySession(server_id="crm", command=["true"], base_url="http://testserver", api_key="k")
    session.proc = SimpleNamespace(stdin=Stdin(), stdout=SimpleNamespace(readline=lambda: ""))
    session._written = written
    return session


def _install_gateway_client(monkeypatch, body, status=200):
    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, *args, **kwargs):
            return _Resp(404, {})

        def post(self, *args, **kwargs):
            return _Resp(status, body)

    monkeypatch.setattr("varden.runtime.mcp_gateway.httpx.Client", Client)


@pytest.mark.parametrize(
    "method,params",
    [
        ("tools/call", {"name": "delete", "arguments": {}}),
        ("resources/read", {"uri": "file://secret"}),
        ("prompts/get", {"name": "danger"}),
    ],
)
def test_blocked_mcp_methods_never_reach_downstream(monkeypatch, method, params):
    _install_gateway_client(monkeypatch, {"decision": {"action": "block", "reason": "no"}, "action": {}})
    session = _gateway_session()
    resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    assert resp["error"]["code"] == -32000
    assert session._written == []


def test_mcp_missing_decision_does_not_forward(monkeypatch):
    _install_gateway_client(monkeypatch, {})
    session = _gateway_session()
    resp = session.exchange({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "delete", "arguments": {}}})
    assert session._written == []
    assert "no_decision" in json.dumps(resp)


def test_mcp_malformed_message_is_not_forwarded():
    session = _gateway_session()
    resp = session.exchange(["not", "an", "object"])
    assert resp["error"]["code"] == -32600
    assert session._written == []


def test_mcp_host_http_200_deny_does_not_call_handler(monkeypatch, tmp_path):
    sentinel = tmp_path / "handler.txt"

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            return _Resp(200, {"decision": {"action": "require_approval"}, "action": {}})

    monkeypatch.setattr("varden.runtime.mcp_host.httpx.Client", Client)
    host = VardenMcpHost(base_url="http://testserver", api_key="k")
    host.register_inprocess("crm", lambda tool, arguments: sentinel.write_text("ran", encoding="utf-8"))
    result = host.call_tool("crm", "delete", {"id": "1"})
    assert result.blocked is True
    assert not sentinel.exists()


def test_mcp_host_allow_calls_handler_once(monkeypatch, tmp_path):
    sentinel = tmp_path / "handler.txt"

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            return _Resp(200, {"decision": {"action": "allow"}, "action": {}})

    monkeypatch.setattr("varden.runtime.mcp_host.httpx.Client", Client)
    host = VardenMcpHost(base_url="http://testserver", api_key="k")
    host.register_inprocess("crm", lambda tool, arguments: sentinel.write_text(tool, encoding="utf-8") or {"ok": True})
    result = host.call_tool("crm", "search", {})
    assert result.blocked is False
    assert sentinel.read_text(encoding="utf-8") == "search"


# --- HTTP --------------------------------------------------------------------


class _Recorder(ThreadingHTTPServer):
    def __init__(self, host="127.0.0.1", family=socket.AF_INET):
        self.hits: list[dict] = []
        self.redirect_to = ""
        self.address_family = family
        super().__init__((host, 0), _Handler)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "cookie": self.headers.get("Cookie"),
            }
        )
        if self.path.startswith("/redir"):
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        return


def test_blocked_http_never_connects_under_fail_open(tmp_path):
    policy = {"block": [{"type": "http_request"}], "warn": [], "monitor": [], "allow": []}
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=policy)
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False, fail_mode="open")
        wire_guard_to_app(guard, client)
        server = _Recorder("127.0.0.1")
        thread_started = True
        import threading

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(VardenBlockedError):
                requests.get(server.url + "/secret", timeout=2)
            prepared = requests.Request("GET", server.url + "/direct").prepare()
            with pytest.raises(VardenBlockedError):
                requests.Session().send(prepared, timeout=2)
            assert server.hits == []
        finally:
            server.shutdown()
            server.server_close()
            assert thread_started


def test_allowed_http_connects_and_cross_host_redirect_drops_credentials(tmp_path):
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy={"block": [], "warn": [], "monitor": [], "allow": []})
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        first = _Recorder("127.0.0.1")
        second = _Recorder("::1", socket.AF_INET6)
        import threading

        for server in (first, second):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        # 127.0.0.1 and ::1 are different host identities, both loopback.
        second_url = f"http://[::1]:{second.server_address[1]}/landed"
        first.redirect_to = second_url
        try:
            response = requests.get(
                first.url + "/redir",
                headers={"Authorization": "Bearer SECRET", "Cookie": "sid=SECRET"},
                auth=("user", "password"),
                timeout=2,
            )
            assert response.status_code == 200
            assert len(first.hits) == 1
            assert first.hits[0]["authorization"]
            assert second.hits
            assert second.hits[0]["authorization"] is None
            assert second.hits[0]["cookie"] is None
            assert second.hits[0]["path"] == "/landed"
        finally:
            for server in (first, second):
                server.shutdown()
                server.server_close()


def test_redirect_to_blocked_host_does_not_connect(tmp_path):
    policy = {
        "block": [{"type": "http_request", "domain": "::1"}],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=policy)
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False, fail_mode="open")
        wire_guard_to_app(guard, client)
        first = _Recorder("127.0.0.1")
        second = _Recorder("::1", socket.AF_INET6)
        import threading

        for server in (first, second):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        first.redirect_to = f"http://[::1]:{second.server_address[1]}/nope"
        try:
            with pytest.raises(VardenBlockedError):
                requests.get(first.url + "/redir", timeout=2)
            assert len(first.hits) == 1
            assert second.hits == []
        finally:
            for server in (first, second):
                server.shutdown()
                server.server_close()


def test_unwrapping_session_send_downgrades_requests_coverage(tmp_path):
    from varden_sdk import sdk as sdk_mod

    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy={"block": [], "warn": [], "monitor": [], "allow": []})
        key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
        varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(varden.current_guard(), client)
        reg = get_coverage_registry()
        assert reg.get("http.requests").status == ENFORCED
        assert reg.get("http.httpx").status == ENFORCED
        requests.sessions.Session.send = sdk_mod._ORIGINALS["requests.sessions.Session.send"]
        reg.verify()
        assert reg.get("http.requests").status == UNCOVERED


def test_repeated_protect_still_blocks(tmp_path):
    sentinel = tmp_path / "nested.txt"
    guard = _protect()
    again = _protect()
    assert again is not guard
    _stub(again, 200, {"decision": {"action": "block"}, "action": {}})

    def tool():
        sentinel.write_text("ran", encoding="utf-8")

    with pytest.raises(VardenBlockedError):
        again.guard_tool(tool, name="delete_database")()
    assert not sentinel.exists()


def test_dns_rebinding_remains_an_open_residual():
    dest = canonicalize_destination("https://example.com/path")
    assert dest.rejection is None
    assert dest.dns_rebinding == "open"
    literal = canonicalize_destination("http://127.0.0.1/")
    assert literal.dns_rebinding == "not_applicable"


# --- Standalone SDK tree -----------------------------------------------------


def _load_standalone():
    path = Path(__file__).resolve().parents[3] / "sdks" / "python" / "varden_sdk" / "sdk.py"
    name = "varden_standalone_sdk_phase3"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_standalone_sdk_deny_under_fail_open_writes_nothing(tmp_path):
    standalone = _load_standalone()
    sentinel = tmp_path / "standalone.txt"
    guard = standalone.VardenGuard(
        base_url="http://127.0.0.1:9",
        api_key="k",
        mode="enforce",
        fail_mode="open",
        auto_instrument=False,
    )

    class Resp:
        status_code = 200
        content = b"{}"

        def __init__(self):
            self.headers = {"content-type": "application/json"}

        def json(self):
            return {"decision": {"action": "require_approval"}, "action": {}}

    guard.client._client.post = lambda *args, **kwargs: Resp()

    def tool():
        sentinel.write_text("ran", encoding="utf-8")

    with pytest.raises(standalone.VardenBlockedError):
        guard.guard_tool(tool, name="delete")()
    assert not sentinel.exists()


def test_standalone_sdk_transport_failure_still_fail_opens_when_asked(tmp_path):
    standalone = _load_standalone()
    sentinel = tmp_path / "open.txt"
    guard = standalone.VardenGuard(
        base_url="http://127.0.0.1:9",
        api_key="k",
        mode="enforce",
        fail_mode="open",
        auto_instrument=False,
    )

    def post(*args, **kwargs):
        raise ConnectionError("down")

    guard.client._client.post = post

    def tool():
        sentinel.write_text("ran", encoding="utf-8")
        return "ok"

    assert guard.guard_tool(tool, name="delete")() == "ok"
    assert sentinel.read_text(encoding="utf-8") == "ran"
