"""Decision-correctness gauntlet for pass 2 phase 2.

Proved against the pre-change tree before these fixes:

- ``requests`` and ``httpx`` parsed ``http://example.com%2eevil/a`` and
  ``http://evil.com\\@good.com/`` as different hosts.
- ``PolicyEngine`` trusted a caller ``domain`` and ``runtime.surface``.
- The MCP gateway forwarded methods outside its two lists without a decision.
- A missing or unknown action type became an implicit allow.
- ``fail_mode=open`` must not turn a delivered deny into execution. That path
  was already closed; these tests keep it closed for ``unsupported``.
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from varden.action_identity import ENFORCEMENT_OWNERS
from varden.app_factory import create_app
from varden.config import AppConfig
from varden.models import Action
from varden.policy import PolicyEngine
from varden.runtime.mcp_gateway import McpGatewaySession, classify_mcp_method
from varden.url_identity import canonicalize_destination, prepare_outbound_url, DestinationRejected
from varden_sdk.sdk import VardenBlockedError, _authorize_http, _follow_requests


def _engine(tmp_path, policy):
    return PolicyEngine(str(tmp_path / "p.db"), policy)


def _app(tmp_path, policy):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(tmp_path / "v.db"),
        auth_db_path=str(tmp_path / "a.db"),
        policy_file=str(path),
        signing_secret="dev-secret",
        rate_limit_per_minute=10_000,
    )
    client = TestClient(create_app(cfg))
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    return client, key


def _guard(client, key, action):
    return client.post("/sdk/guard", headers={"x-api-key": key}, json={"action": action, "payload": {}})


# --- P0-2 canonical identity -------------------------------------------------


def test_equivalent_urls_share_one_decision(tmp_path):
    engine = _engine(tmp_path, {"block": [{"type": "http_request", "domain": "example.com"}], "warn": [], "monitor": [], "allow": []})
    forms = [
        "https://Example.COM/a",
        "https://example.com./a",
        "https://example.com:443/a",
        "HTTPS://example.com/a",
    ]
    decisions = []
    for url in forms:
        action = Action(type="http_request", url=url, domain="Example.COM")
        decisions.append(engine.evaluate(action).action)
        assert action.domain == "example.com"
        assert action.metadata["identity"]["canonical_url"] == "https://example.com/a"
        assert action.metadata["identity"]["original_url"] == url
    assert decisions == ["block", "block", "block", "block"]


def test_caller_domain_cannot_override_the_url(tmp_path):
    engine = _engine(
        tmp_path,
        {
            "default": "block",
            "allow": [{"type": "http_request", "domain": "safe.example"}],
            "block": [],
            "warn": [],
            "monitor": [],
        },
    )
    action = Action(type="http_request", url="http://evil.example/steal", domain="safe.example")
    decision = engine.evaluate(action)
    assert decision.action == "block"
    assert decision.matched_rule["code"] == "conflicting_destination_identity"


def test_forged_server_identity_cannot_select_the_decision(tmp_path):
    engine = _engine(
        tmp_path,
        {"defaults": {"http": "block"}, "block": [], "warn": [], "monitor": [], "allow": []},
    )
    action = Action(
        type="http_request",
        url="https://evil.example/a",
        metadata={
            "identity": {
                "issuer": "varden",
                "surface": "llm",
                "type": "llm_call",
                "canonical_url": "https://safe.example/a",
            },
            "runtime": {"surface": "llm"},
            "execution_surface": "llm",
        },
    )
    decision = engine.evaluate(action)
    assert decision.action == "block"
    assert action.metadata["identity"]["host"] == "evil.example"
    assert action.metadata["identity"]["surface"] == "http"
    assert action.metadata["identity"]["canonical_url"] == "https://evil.example/a"


def test_unknown_type_case_is_one_identity(tmp_path):
    (tmp_path / "allow").mkdir()
    (tmp_path / "block").mkdir()
    allowed = _engine(
        tmp_path / "allow",
        {"allow": [{"type": "billing.charge"}], "block": [], "warn": [], "monitor": []},
    )
    action = Action(type="Billing.Charge", tool="charge")
    assert allowed.evaluate(action).action == "allow"
    assert action.type == "billing.charge"
    blocked = _engine(
        tmp_path / "block",
        {"defaults": {"billing.charge": "block"}, "block": [], "warn": [], "monitor": [], "allow": []},
    )
    denied = Action(type="BILLING.CHARGE", tool="charge")
    assert blocked.evaluate(denied).action == "block"


def test_caller_surface_cannot_select_a_permissive_default(tmp_path):
    engine = _engine(tmp_path, {"defaults": {"http": "block", "llm": "allow"}, "block": [], "warn": [], "monitor": [], "allow": []})
    action = Action(
        type="http_request",
        url="https://evil.example/x",
        metadata={"runtime": {"surface": "llm"}, "execution_surface": "llm"},
    )
    decision = engine.evaluate(action)
    assert decision.action == "block"
    assert action.metadata["identity"]["claimed_surface"] == "llm"
    assert action.metadata["identity"]["surface"] == "http"


def test_subprocess_surface_comes_from_the_tool_not_metadata(tmp_path):
    engine = _engine(tmp_path, {"defaults": {"subprocess": "block", "llm": "allow"}, "block": [], "warn": [], "monitor": [], "allow": []})
    action = Action(
        type="tool_call",
        tool="subprocess.run",
        args={"args": ["whoami"], "kwargs": {}},
        metadata={"execution_surface": "llm"},
    )
    assert engine.evaluate(action).action == "block"
    assert action.metadata["identity"]["surface"] == "subprocess"


def test_http_alias_and_case_match_the_same_rule(tmp_path):
    engine = _engine(tmp_path, {"block": [{"type": "http_request", "domain": "evil.example"}], "warn": [], "monitor": [], "allow": []})
    for raw_type in ("http_call", "HTTP_REQUEST", "https_request"):
        action = Action(type=raw_type, url="https://evil.example/a")
        assert engine.evaluate(action).action == "block"
        assert action.type == "http_request"


def test_lexical_paths_match_once(tmp_path):
    engine = _engine(tmp_path, {"block": [{"type": "filesystem", "field:args.path": "/tmp/foo"}], "warn": [], "monitor": [], "allow": []})
    action = Action(type="filesystem", tool="open", args={"path": "/tmp/./foo"})
    assert engine.evaluate(action).action == "block"
    assert action.metadata["identity"]["resource"] == "/tmp/foo"


def test_shell_alias_is_the_subprocess_tool_call(tmp_path):
    engine = _engine(tmp_path, {"block": [{"type": "tool_call", "tool": "subprocess.run"}], "warn": [], "monitor": [], "allow": []})
    action = Action(type="subprocess", tool="subprocess.run", args={"args": ["id"]})
    assert engine.evaluate(action).action == "block"
    assert action.metadata["identity"]["original_type"] == "subprocess"
    assert action.metadata["identity"]["surface"] == "subprocess"


# --- P0-4 / P1-5 URL and SSRF ------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "http://example.com%2eevil/a",
        "http://evil.com\\@good.com/",
        "http://user:pass@evil.example/",
        "http://2852039166/latest/meta-data",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://127.1/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:7f00:1]/",
    ],
)
def test_ambiguous_destinations_are_rejected(raw):
    dest = canonicalize_destination(raw)
    assert dest.rejection
    assert dest.canonical_url is None
    with pytest.raises(DestinationRejected):
        prepare_outbound_url(raw)


def test_metadata_forms_share_a_category(tmp_path):
    engine = _engine(
        tmp_path,
        {"block": [{"type": "http_request", "field:metadata.destination.category": "metadata"}], "warn": [], "monitor": [], "allow": []},
    )
    urls = [
        "http://169.254.169.254/latest/meta-data",
        "http://169.254.169.254./latest/meta-data",
        "http://[fd00:ec2::254]/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for url in urls:
        action = Action(type="http_request", url=url)
        decision = engine.evaluate(action)
        assert decision.action == "block", url
        assert action.metadata["destination"]["category"] == "metadata"
        assert action.metadata["destination"]["original_url"] == url


def test_substring_is_not_how_a_lookalike_host_is_trusted(tmp_path):
    engine = _engine(tmp_path, {"block": [{"type": "http_request", "domain": "169.254.169.254"}], "warn": [], "monitor": [], "allow": []})
    lookalike = Action(type="http_request", url="http://169.254.169.254.evil.example/latest/meta-data")
    assert engine.evaluate(lookalike).action == "allow"
    assert lookalike.domain == "169.254.169.254.evil.example"


def test_private_and_loopback_literals_are_classified_not_globally_blocked(tmp_path):
    engine = _engine(tmp_path, {"block": [], "warn": [], "monitor": [], "allow": []})
    loopback = Action(type="http_request", url="http://127.0.0.1:8080/health")
    private = Action(type="http_request", url="http://10.1.2.3/")
    link_local = Action(type="http_request", url="http://169.254.1.1/")
    assert engine.evaluate(loopback).action == "allow"
    assert loopback.metadata["destination"]["category"] == "loopback"
    assert engine.evaluate(private).action == "allow"
    assert private.metadata["destination"]["category"] == "private"
    assert engine.evaluate(link_local).action == "allow"
    assert link_local.metadata["destination"]["category"] == "link_local"
    assert loopback.metadata["identity"]["dns_rebinding"] == "not_applicable"


def test_hostname_records_dns_rebinding_as_open():
    dest = canonicalize_destination("https://example.com/a")
    assert dest.dns_rebinding == "open"
    assert dest.host == "example.com"


def test_ambiguous_url_is_not_a_fail_open_bypass():
    class Result:
        blocked = False
        decision = {"action": "allow"}

    class Guard:
        product_mode = "guarded"
        fail_mode = "open"
        calls = 0

        def guarded_action(self, **kwargs):
            self.calls += 1
            return Result()

    guard = Guard()
    with pytest.raises(VardenBlockedError):
        _authorize_http(guard, tool="requests", url="http://evil.com\\@good.com/", method="GET", args={}, payload={}, metadata={})
    assert guard.calls == 1

    class Open:
        product_mode = "guarded"
        fail_mode = "open"

        def guarded_action(self, **kwargs):
            return None

    with pytest.raises(VardenBlockedError):
        _authorize_http(Open(), tool="requests", url="http://127.1/", method="GET", args={}, payload={}, metadata={})


def test_redirect_target_is_authorized_before_connect():
    sent = []

    class Resp:
        def __init__(self, code, location=None, url="https://ok.example/"):
            self.status_code = code
            self.headers = {"Location": location} if location else {}
            self.is_redirect = code in {301, 302, 303, 307, 308}
            self.url = url

    def send(method, url, args, kwargs):
        sent.append(url)
        if url.startswith("https://ok.example"):
            return Resp(302, "http://169.254.169.254/latest/meta-data", url=url)
        raise AssertionError(f"unexpected connection to {url}")

    def authorize(url, method):
        dest = canonicalize_destination(url)
        if dest.rejection or (dest.category == "metadata"):
            raise VardenBlockedError("no", {"action": "block", "reason": "metadata"})
        return dest.canonical_url, SimpleNamespace(action={}, decision={"action": "allow"})

    with pytest.raises(VardenBlockedError):
        _follow_requests(send, method="GET", url="https://ok.example/start", follow=True, authorize=authorize, call_kwargs={}, args=())
    assert sent == ["https://ok.example/start"]


# --- P0-8 MCP default deny ---------------------------------------------------


def _session():
    session = McpGatewaySession(server_id="crm", command=["true"], base_url="http://testserver", api_key="k")
    written = []

    class Stdin:
        def write(self, data):
            written.append(data)

        def flush(self):
            pass

    session.proc = SimpleNamespace(stdin=Stdin(), stdout=SimpleNamespace(readline=lambda: ""))
    session._written = written
    return session


def test_unknown_mcp_method_requires_authorization(monkeypatch):
    session = _session()
    seen = []

    def guard(*, method, params):
        seen.append(method)
        return {"blocked": True, "detail": {"decision": {"action": "block", "reason": "no"}}}

    monkeypatch.setattr(session, "guard", guard)
    resp = session.exchange({"jsonrpc": "2.0", "id": 7, "method": "sampling/createMessage", "params": {}})
    assert resp["error"]["code"] == -32000
    assert seen == ["sampling/createMessage"]
    assert session._written == []


def test_method_alias_is_not_an_unguarded_forward(monkeypatch):
    session = _session()
    seen = []

    def guard(*, method, params):
        seen.append(method)
        return {"blocked": True, "detail": {"decision": {"reason": "no", "action": "block"}}}

    monkeypatch.setattr(session, "guard", guard)
    resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": "Tools/Call", "params": {"name": "delete", "arguments": {}}})
    assert seen == ["tools/call"]
    assert session._written == []
    assert "blocked" in resp["error"]["message"]


def test_malformed_tool_call_does_not_execute_even_if_policy_allows(monkeypatch):
    session = _session()

    monkeypatch.setattr(session, "guard", lambda **kwargs: {"blocked": False, "result": {}})
    resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "  delete  "}})
    assert resp["error"]["code"] == -32000
    assert session._written == []


def test_discovery_methods_still_forward_without_a_decision(monkeypatch):
    session = _session()

    def boom(**kwargs):
        raise AssertionError("discovery must not require a guard decision")

    monkeypatch.setattr(session, "guard", boom)

    class Stdout:
        def readline(self):
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}) + "\n"

    session.proc.stdout = Stdout()
    resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert resp["result"] == {"tools": []}
    assert session._written


def test_guard_outage_does_not_forward_an_unknown_method(monkeypatch):
    session = _session()

    def down(**kwargs):
        raise ConnectionError("control plane down")

    monkeypatch.setattr(session, "guard", down)
    resp = session.exchange({"jsonrpc": "2.0", "id": 3, "method": "resources/subscribe", "params": {}})
    assert resp["error"]["code"] == -32001
    assert session._written == []


def test_ambiguous_method_is_rejected():
    assert classify_mcp_method("tools/call ")[0] == "reject"
    assert classify_mcp_method("tools/list")[0] == "discovery"


def test_concurrent_denies_do_not_forward(monkeypatch):
    session = _session()
    monkeypatch.setattr(
        session,
        "guard",
        lambda **kwargs: {"blocked": True, "detail": {"decision": {"action": "block", "reason": "no"}}},
    )
    errors = []

    def once():
        resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "delete", "arguments": {}}})
        errors.append(resp["error"]["code"])

    threads = [threading.Thread(target=once) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == [-32000] * 8
    assert session._written == []


# --- P1-13 unknown types and fail-open --------------------------------------


def test_unknown_type_is_not_an_implicit_allow(tmp_path):
    client, key = _app(tmp_path, {"block": [], "warn": [], "monitor": [], "allow": []})
    missing = _guard(client, key, {"tool": "delete_database"})
    assert missing.status_code == 403
    assert missing.json()["detail"]["decision"]["action"] == "unsupported"
    weird = _guard(client, key, {"type": "not_a_real_type", "url": "https://evil.example"})
    assert weird.status_code == 403
    assert weird.json()["detail"]["decision"]["action"] == "unsupported"
    malformed = _guard(client, key, {"type": "http request"})
    assert malformed.status_code == 403
    assert malformed.json()["detail"]["decision"]["matched_rule"]["code"] == "malformed_action_type"


def test_explicit_rule_can_still_allow_a_custom_type(tmp_path):
    client, key = _app(
        tmp_path,
        {"block": [], "warn": [], "monitor": [], "allow": [{"type": "billing.charge", "tool": "invoice"}]},
    )
    allowed = _guard(client, key, {"type": "billing.charge", "tool": "invoice"})
    assert allowed.status_code == 200
    assert allowed.json()["decision"]["action"] == "allow"
    denied = _guard(client, key, {"type": "billing.charge", "tool": "refund"})
    assert denied.status_code == 403


def test_explicit_policy_deny_is_not_unsupported(tmp_path):
    client, key = _app(tmp_path, {"block": [{"type": "tool_call", "tool": "delete_database"}], "warn": [], "monitor": [], "allow": []})
    resp = _guard(client, key, {"type": "tool_call", "tool": "delete_database"})
    body = resp.json()["detail"]
    assert resp.status_code == 403
    assert body["decision"]["action"] == "block"
    assert body["decision"]["matched_rule"]["type"] == "action_identity" or body["decision"]["matched_rule"].get("tool") == "delete_database"


def test_fail_open_does_not_execute_an_unsupported_decision(monkeypatch):
    from varden_sdk.sdk import VardenGuard

    with pytest.warns(UserWarning, match="fail_mode=open"):
        guard = VardenGuard(
            base_url="http://127.0.0.1:9",
            api_key="k",
            mode="guarded",
            fail_mode="open",
            auto_instrument=False,
        )

    class Resp:
        status_code = 403
        content = b"{}"
        headers = {"content-type": "application/json"}

        def json(self):
            return {"decision": {"action": "unsupported", "reason": "unknown action type"}, "action": {}}

    monkeypatch.setattr(guard.client._client, "post", lambda *args, **kwargs: Resp())
    with pytest.raises(VardenBlockedError):
        guard.guarded_action(type="not_a_real_type", tool="x")


def test_enforcement_owners_cover_recognized_types():
    for name in ("http_request", "tool_call", "llm_call", "filesystem", "mcp_call", "webmcp.tool_invocation_requested"):
        assert ENFORCEMENT_OWNERS[name]


def test_identity_bind_is_stable_under_concurrency(tmp_path):
    engine = _engine(tmp_path, {"block": [{"type": "http_request", "domain": "evil.example"}], "warn": [], "monitor": [], "allow": []})
    results = []

    def once(url, expected):
        action = Action(type="HTTP_REQUEST", url=url)
        results.append((expected, engine.evaluate(action).action, action.domain))

    threads = []
    for _ in range(6):
        threads.append(threading.Thread(target=once, args=("https://evil.example/a", "block")))
        threads.append(threading.Thread(target=once, args=("https://ok.example/a", "allow")))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert ("block", "block", "evil.example") in results
    assert ("allow", "allow", "ok.example") in results
    assert all(item[0] == item[1] for item in results)


def test_guard_audit_keeps_original_url_and_canonical_host(tmp_path):
    client, key = _app(tmp_path, {"block": [], "warn": [], "monitor": [], "allow": []})
    resp = _guard(client, key, {"type": "http_request", "url": "https://Example.COM:443/a"})
    assert resp.status_code == 200
    action = resp.json()["action"]
    assert action["url"] == "https://Example.COM:443/a"
    assert action["domain"] == "example.com"
    assert action["metadata"]["identity"]["canonical_url"] == "https://example.com/a"
    assert action["metadata"]["identity"]["dns_rebinding"] == "open"
    stored = client.get(f"/events/{resp.json()['event_id']}", headers={"x-api-key": key}).json()["event"]
    assert stored["decision"]["action"] == "allow"
    assert stored["action"]["metadata"]["destination"]["host"] == "example.com"
