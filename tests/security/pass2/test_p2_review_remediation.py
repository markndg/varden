"""Independent-review regressions for destination parsing and MCP discovery.

Malformed authorities must reject with a code. They must not raise from the
URL parser, and they must not open a socket when fail_mode is open.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from varden.models import Action
from varden.policy import PolicyEngine
from varden.runtime.mcp_gateway import (
    OBSERVED_METHODS,
    PRIVILEGED_METHODS,
    McpGatewaySession,
    classify_mcp_method,
)
from varden.url_identity import canonicalize_destination, hosts_equivalent
from varden_sdk.sdk import VardenBlockedError, _authorize_http, _follow_requests


def _engine(tmp_path, policy):
    return PolicyEngine(str(tmp_path / "p.db"), policy)


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("http://[::1/", "malformed_authority"),
        ("http://[::1", "malformed_authority"),
        ("http://]/", "malformed_authority"),
        ("http://[/", "malformed_authority"),
        ("http://[::1]extra/", "malformed_authority"),
        ("http://::1/", "malformed_authority"),
        ("http://[v1.something]/", "malformed_ipv6"),
        ("http://[::1]:abc/", "malformed_port"),
        ("http://[::1]:99999/", "malformed_port"),
        ("http://[::1]:0/", "malformed_port"),
        ("http://[::1]:/", "malformed_port"),
        ("http://host:99999/", "malformed_port"),
        ("http://host:0/", "malformed_port"),
        ("http://host:/", "malformed_port"),
        ("http://user:secret@[::1/", "malformed_authority"),
        ("http://user:secret@[::1]/", "userinfo"),
        ("http://xn--.example/", "invalid_idna"),
        ("http://\ufffe.example/", "invalid_idna"),
        ("http://faß.de/", "ambiguous_idna"),
        ("http://example。com/", "ambiguous_idna"),
        ("http://ex\u200bample.com/", "ambiguous_idna"),
    ],
)
def test_malformed_authorities_reject_without_parser_exceptions(raw, code):
    dest = canonicalize_destination(raw)
    assert dest.rejection == code
    assert dest.canonical_url is None
    assert "secret" not in dest.evidence_url


def test_unicode_dns_names_canonicalize_to_a_labels():
    forms = [
        "http://bücher.example/a",
        "http://Bücher.EXAMPLE./a",
        "http://xn--bcher-kva.example/a",
    ]
    hosts = []
    for raw in forms:
        dest = canonicalize_destination(raw)
        assert dest.rejection is None
        assert dest.host == "xn--bcher-kva.example"
        assert dest.canonical_url == "http://xn--bcher-kva.example/a"
        assert dest.evidence_url == raw
        hosts.append(dest.host)
    assert hosts == ["xn--bcher-kva.example"] * 3
    assert hosts_equivalent("bücher.example", "xn--bcher-kva.example")
    assert hosts_equivalent("Bücher.EXAMPLE.", "xn--bcher-kva.example")


def test_rejected_destination_is_audited_as_a_block(tmp_path):
    engine = _engine(tmp_path, {"block": [], "warn": [], "monitor": [], "allow": []})
    raw = "http://user:secret@[::1/"
    action = Action(type="http_request", url=raw, domain="safe.example")
    decision = engine.evaluate(action)
    assert decision.action == "block"
    assert decision.matched_rule["code"] == "malformed_authority"
    stored = json.dumps(action.to_dict())
    assert "secret" not in stored
    assert action.metadata["identity"]["original_url"] == "http://[::1/"
    assert action.metadata["identity"]["canonical_url"] is None
    assert action.metadata["identity"]["rejection"] == "malformed_authority"


def test_idna_alias_and_punycode_share_a_policy_decision(tmp_path):
    engine = _engine(
        tmp_path,
        {
            "block": [{"type": "http_request", "domain": "xn--bcher-kva.example"}],
            "warn": [],
            "monitor": [],
            "allow": [],
        },
    )
    for raw in ("http://bücher.example/a", "http://xn--bcher-kva.example/a"):
        action = Action(type="http_request", url=raw)
        assert engine.evaluate(action).action == "block"
        assert action.domain == "xn--bcher-kva.example"
    ambiguous = Action(type="http_request", url="http://faß.de/")
    decision = engine.evaluate(ambiguous)
    assert decision.action == "block"
    assert decision.matched_rule["code"] == "ambiguous_idna"
    assert "destination" not in ambiguous.metadata


def test_rejected_destination_does_not_connect_when_fail_open():
    sent = []

    class Guard:
        product_mode = "guarded"
        fail_mode = "open"

        def guarded_action(self, **kwargs):
            return None

    def send(verb, canonical, send_args, send_kwargs):
        sent.append(canonical)
        raise AssertionError(f"connected to {canonical}")

    def authorize(target, verb):
        return _authorize_http(
            Guard(), tool="requests", url=str(target), method=verb, args={}, payload={}, metadata={}
        )

    with pytest.raises(VardenBlockedError):
        _follow_requests(
            send,
            method="GET",
            url="http://user:secret@[::1/",
            follow=False,
            authorize=authorize,
            call_kwargs={},
            args=(),
        )
    assert sent == []


def test_allow_decision_does_not_connect_to_a_rejected_destination():
    sent = []

    class Result:
        blocked = False
        decision = {"action": "allow"}
        action = {}

    class Guard:
        product_mode = "guarded"
        fail_mode = "open"

        def guarded_action(self, **kwargs):
            return Result()

    def send(verb, canonical, send_args, send_kwargs):
        sent.append((verb, canonical))
        response = SimpleNamespace(
            status_code=302,
            headers={"Location": "http://[::1/"},
            is_redirect=True,
            url=canonical,
        )
        return response

    def authorize(target, verb):
        return _authorize_http(
            Guard(), tool="requests", url=str(target), method=verb, args={}, payload={}, metadata={}
        )

    with pytest.raises(VardenBlockedError):
        _follow_requests(
            send,
            method="POST",
            url="https://ok.example/start",
            follow=True,
            authorize=authorize,
            call_kwargs={"headers": {"Authorization": "secret"}},
            args=(),
        )
    assert sent == [("POST", "https://ok.example/start")]


def test_discovery_set_is_disjoint_from_privileged_execution():
    assert OBSERVED_METHODS.isdisjoint(PRIVILEGED_METHODS)
    for method in OBSERVED_METHODS:
        kind, canonical, rejection = classify_mcp_method(method)
        assert kind == "discovery"
        assert canonical == method
        assert canonical not in PRIVILEGED_METHODS
        assert rejection is None
        kind_upper, canonical_upper, _rejection = classify_mcp_method(method.upper())
        assert kind_upper == "discovery"
        assert canonical_upper == method
    for method in PRIVILEGED_METHODS:
        kind, canonical, _rejection = classify_mcp_method(method.upper())
        assert kind == "privileged"
        assert canonical == method


def test_discovery_params_are_not_forwarded_as_a_privileged_call(monkeypatch):
    session = McpGatewaySession(server_id="crm", command=["true"], base_url="http://testserver", api_key="k")
    written = []

    class Stdin:
        def write(self, data):
            written.append(data)

        def flush(self):
            pass

    class Stdout:
        def readline(self):
            return json.dumps({"jsonrpc": "2.0", "id": 4, "result": {"tools": []}}) + "\n"

    session.proc = SimpleNamespace(stdin=Stdin(), stdout=Stdout())

    def boom(**kwargs):
        raise AssertionError("discovery must not consult the guard")

    monkeypatch.setattr(session, "guard", boom)
    params = {"method": "tools/call", "params": {"name": "delete_database", "arguments": {"target": "prod"}}}
    resp = session.exchange({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": params})
    assert resp["result"] == {"tools": []}
    outbound = json.loads(written[0])
    assert outbound["method"] == "tools/list"
    assert outbound["method"] not in PRIVILEGED_METHODS
    assert outbound["params"]["method"] == "tools/call"

    written.clear()
    session.proc.stdout = SimpleNamespace(readline=lambda: "")
    note = session.exchange(
        {
            "jsonrpc": "2.0",
            "method": "Notifications/Initialized",
            "params": {"name": "delete", "arguments": {"cmd": "rm"}},
        }
    )
    assert note is None
    outbound = json.loads(written[0])
    assert outbound["method"] == "notifications/initialized"
    assert outbound["method"] not in PRIVILEGED_METHODS


def test_notification_lookalikes_still_require_authorization(monkeypatch):
    session = McpGatewaySession(server_id="crm", command=["true"], base_url="http://testserver", api_key="k")
    written = []

    class Stdin:
        def write(self, data):
            written.append(data)

        def flush(self):
            pass

    session.proc = SimpleNamespace(stdin=Stdin(), stdout=SimpleNamespace(readline=lambda: ""))
    seen = []

    def guard(*, method, params):
        seen.append(method)
        return {"blocked": True, "detail": {"decision": {"action": "block", "reason": "no"}}}

    monkeypatch.setattr(session, "guard", guard)
    for method in ("notifications/tools/call", "tools/list/../call", "TOOLS/CALL"):
        resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": method, "params": {"name": "delete", "arguments": {}}})
        assert resp["error"]["code"] == -32000
    assert seen == ["notifications/tools/call", "tools/list/../call", "tools/call"]
    assert written == []
