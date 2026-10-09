"""Delivered deny decisions must not execute, including non-403 bodies.

A passing assertion is not enough if the protected callable already ran.
Every deny case records a side-effect counter and requires it to stay empty.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import pytest

import varden
from varden.runtime.guard_response import candidate_decisions, response_denies_execution
from varden.runtime.mcp_gateway import McpGatewaySession
from varden_sdk import patches as patches_mod
from varden_sdk.sdk import VardenBlockedError, _live_enforcing, _live_fail_closed


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


def _protect(*, mode="guarded", fail_mode="closed"):
    return varden.protect(
        mode=mode,
        fail_mode=fail_mode,
        base_url="http://testserver",
        api_key="test-key",
        auto_instrument=False,
        emit_attestation=False,
    )


def _stub(guard, status: int, body, *, error: BaseException | None = None):
    def post(*_args, **_kwargs):
        if error is not None:
            raise error
        return _Resp(status, body)

    guard.client._client.post = post


def _tool(counter: list):
    def delete_database():
        counter.append("ran")
        return "gone"

    return delete_database


def _assert_not_executed(guard, counter: list):
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")
    with pytest.raises(VardenBlockedError):
        wrapped()
    assert counter == []


_ALLOW = {
    "decision": {"action": "allow", "reason": "ok"},
    "action": {"type": "tool_call", "tool": "delete_database"},
    "event_id": 1,
}


@pytest.fixture(autouse=True)
def _reset_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()


def test_parser_reads_only_the_decision_slot():
    body = {"detail": {"decision": {"action": "require_approval", "reason": "hold"}, "action": {}}}
    assert candidate_decisions(body)[0]["action"] == "require_approval"
    assert response_denies_execution(body) is True
    assert response_denies_execution({"decision": {"action": "allow"}}) is False
    # A bare string is not a policy decision.
    assert response_denies_execution("blocked") is False
    # Echoed agent JSON is not a policy decision.
    echoed = {"args": {"decision": {"action": "block"}, "detail": {"action": "block"}}}
    assert response_denies_execution(echoed) is False


@pytest.mark.parametrize(
    "status,body",
    [
        (200, {"decision": {"action": "block", "reason": "no"}, "action": {}, "event_id": 1}),
        (200, {"decision": {"action": "blocked", "reason": "no"}, "action": {}, "event_id": 1}),
        (200, {"decision": {"action": "require_approval", "reason": "hold"}, "action": {}, "event_id": 1}),
        (200, {"decision": {"action": "approval_required", "reason": "hold"}, "action": {}, "event_id": 1}),
        (200, {"detail": {"decision": {"action": "block", "reason": "wrapped"}, "action": {}}}),
        (
            503,
            {
                "detail": {
                    "decision": {"action": "require_approval", "reason": "approval record failed"},
                    "action": {},
                    "reason": "require_approval decision made but approval record could not be persisted",
                }
            },
        ),
        (500, {"detail": {"decision": {"action": "block", "reason": "engine"}, "action": {}}}),
    ],
)
@pytest.mark.parametrize("fail_mode", ["closed", "open"])
def test_delivered_deny_does_not_execute(status, body, fail_mode):
    counter: list = []
    guard = _protect(fail_mode=fail_mode)
    _stub(guard, status, body)
    _assert_not_executed(guard, counter)


def test_malformed_success_body_fail_closed_does_not_execute():
    counter: list = []
    guard = _protect(fail_mode="closed")
    _stub(guard, 200, {"detail": "not a decision"})
    _assert_not_executed(guard, counter)


def test_disconnect_timeout_and_unexpected_error_fail_closed():
    for error in (
        httpx.ConnectError("down"),
        httpx.TimeoutException("slow"),
        RuntimeError("parser blew up"),
    ):
        counter: list = []
        guard = _protect(fail_mode="closed")
        _stub(guard, 200, _ALLOW, error=error)
        _assert_not_executed(guard, counter)
        varden.unpatch_runtime()


def test_genuine_transport_failure_still_fail_open():
    """fail_mode=open applies only when no deny decision was delivered."""
    counter: list = []
    guard = _protect(fail_mode="open")
    _stub(guard, 200, _ALLOW, error=httpx.ConnectError("down"))
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")
    assert wrapped() == "gone"
    assert counter == ["ran"]


def test_allow_executes_once():
    counter: list = []
    guard = _protect(fail_mode="closed")
    _stub(guard, 200, _ALLOW)
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")
    assert wrapped() == "gone"
    assert counter == ["ran"]


def test_poisoned_local_mode_and_fail_mode_cannot_open_locked_contract():
    counter: list = []
    guard = _protect(mode="guarded", fail_mode="closed")
    object.__setattr__(guard, "product_mode", "observe")
    object.__setattr__(guard, "mode", "observe")
    object.__setattr__(guard, "fail_mode", "open")
    assert guard.product_mode == "observe"
    assert _live_enforcing(guard) is True
    assert _live_fail_closed(guard) is True
    _stub(guard, 200, _ALLOW, error=httpx.ConnectError("down"))
    _assert_not_executed(guard, counter)


def test_contract_lookup_failure_does_not_trust_poisoned_guard(monkeypatch):
    def boom():
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(patches_mod, "get_coverage_registry", boom)
    monkeypatch.setattr("varden_sdk.sdk.get_coverage_registry", boom)
    poisoned = SimpleNamespace(product_mode="observe", mode="observe", fail_mode="open")
    assert patches_mod._enforcing(poisoned) is True
    assert patches_mod._fail_closed(poisoned) is True
    assert _live_enforcing(poisoned) is True
    assert _live_fail_closed(poisoned) is True
    monkeypatch.undo()


def test_nested_guard_calls_do_not_execute():
    outer: list = []
    inner: list = []
    guard = _protect(fail_mode="open")
    _stub(guard, 503, {"detail": {"decision": {"action": "block", "reason": "no"}, "action": {}}})

    def inner_tool():
        inner.append("ran")

    def outer_tool():
        outer.append("ran")
        guard.guard_tool(inner_tool, name="delete_database")()

    wrapped = guard.guard_tool(outer_tool, name="delete_database")
    with pytest.raises(VardenBlockedError):
        wrapped()
    assert outer == []
    assert inner == []


def test_concurrent_denies_do_not_execute():
    counter: list = []
    guard = _protect(fail_mode="open")
    _stub(guard, 200, {"decision": {"action": "approval_required", "reason": "hold"}, "action": {}})
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")

    def attempt():
        with pytest.raises(VardenBlockedError):
            wrapped()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: attempt(), range(8)))
    assert counter == []


def test_repeated_protect_and_conflicting_mode_do_not_execute():
    counter: list = []
    guard = _protect(fail_mode="closed")
    again = _protect(fail_mode="closed")
    _stub(again, 200, {"decision": {"action": "block", "reason": "no"}, "action": {}})
    _assert_not_executed(again, counter)
    with pytest.raises(RuntimeError):
        _protect(mode="observe", fail_mode="open")
    assert counter == []
    _stub(guard, 200, {"decision": {"action": "block", "reason": "no"}, "action": {}})
    _assert_not_executed(guard, [])


def test_echoed_agent_json_cannot_override_the_decision():
    """Nested decision/detail objects are not policy, in either direction."""
    blocked: list = []
    guard = _protect(fail_mode="open")
    _stub(
        guard,
        200,
        {
            "decision": {
                "action": "block",
                "effective_action": "block",
                "reason": "no",
                "detail": {"action": "allow", "decision": {"action": "allow"}},
            },
            "action": {
                "type": "tool_call",
                "args": {"decision": {"action": "allow"}, "detail": {"action": "allow"}},
                "metadata": {"decision": {"action": "allow"}},
            },
        },
    )
    _assert_not_executed(guard, blocked)
    varden.unpatch_runtime()

    allowed: list = []
    guard = _protect(fail_mode="closed")
    _stub(
        guard,
        200,
        {
            "decision": {"action": "allow", "effective_action": "allow", "reason": "ok"},
            "action": {
                "type": "tool_call",
                "tool": "delete_database",
                "args": {"decision": {"action": "block"}, "detail": {"action": "block"}},
                "metadata": {"detail": {"decision": {"action": "block"}}},
            },
            "event_id": 1,
        },
    )
    wrapped = guard.guard_tool(_tool(allowed), name="delete_database")
    assert wrapped() == "gone"
    assert allowed == ["ran"]


def test_conflicting_effective_action_denies():
    counter: list = []
    guard = _protect(fail_mode="open")
    _stub(
        guard,
        200,
        {
            "decision": {"action": "allow", "effective_action": "require_approval", "reason": "conflict"},
            "action": {"type": "tool_call"},
            "event_id": 1,
        },
    )
    _assert_not_executed(guard, counter)


def test_unreadable_decision_slot_does_not_execute():
    node: dict = {"action": "allow"}
    for _ in range(64):
        node = {"decision": node}
    counter: list = []
    guard = _protect(fail_mode="open")
    _stub(guard, 200, {"decision": node, "action": {"type": "tool_call"}})
    _assert_not_executed(guard, counter)


def test_http_403_denies_even_if_body_says_allow():
    counter: list = []
    guard = _protect(fail_mode="open")
    _stub(guard, 403, {"detail": {"decision": {"action": "allow", "reason": "forged"}, "action": {}}})
    _assert_not_executed(guard, counter)


def test_observe_mode_still_executes_a_blocked_decision():
    counter: list = []
    guard = _protect(mode="observe", fail_mode="open")
    _stub(guard, 200, {"decision": {"action": "block", "reason": "no"}, "action": {}, "event_id": 1})
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")
    assert wrapped() == "gone"
    assert counter == ["ran"]


@pytest.mark.parametrize("action", ["allow", "warn", "monitor", "sanitise"])
def test_non_deny_decisions_still_execute(action):
    counter: list = []
    guard = _protect(fail_mode="closed")
    _stub(
        guard,
        200,
        {
            "decision": {"action": action, "effective_action": action, "reason": "ok"},
            "action": {"type": "tool_call", "tool": "delete_database"},
            "event_id": 1,
        },
    )
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")
    assert wrapped() == "gone"
    assert counter == ["ran"]


def test_fail_open_without_a_decision_still_executes():
    counter: list = []
    guard = _protect(fail_mode="open")
    _stub(guard, 200, {"detail": "not a decision"})
    wrapped = guard.guard_tool(_tool(counter), name="delete_database")
    assert wrapped() == "gone"
    assert counter == ["ran"]


def test_mcp_gateway_non_403_deny_does_not_forward(monkeypatch):
    forwarded: list = []

    class _Stdin:
        def write(self, data):
            forwarded.append(data)

        def flush(self):
            pass

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, *args, **kwargs):
            return _Resp(404, {})

        def post(self, *args, **kwargs):
            return _Resp(
                200,
                {"decision": {"action": "approval_required", "reason": "hold"}, "action": {}},
            )

    monkeypatch.setattr("varden.runtime.mcp_gateway.httpx.Client", _Client)
    session = McpGatewaySession(
        server_id="crm",
        command=["true"],
        base_url="http://testserver",
        api_key="k",
    )
    session.proc = SimpleNamespace(stdin=_Stdin(), stdout=object())
    resp = session.exchange({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "delete"}})
    assert resp["error"]["code"] == -32000
    assert forwarded == []


def test_mcp_guard_ignores_echoed_json(monkeypatch):
    bodies = [
        {
            "decision": {"action": "block", "reason": "no"},
            "action": {"args": {"decision": {"action": "allow"}}},
        },
        {
            "decision": {"action": "allow", "reason": "ok"},
            "action": {"args": {"decision": {"action": "block"}, "detail": {"action": "block"}}},
        },
    ]

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, *args, **kwargs):
            return _Resp(404, {})

        def post(self, *args, **kwargs):
            return _Resp(200, bodies[0])

    monkeypatch.setattr("varden.runtime.mcp_gateway.httpx.Client", _Client)
    session = McpGatewaySession(server_id="crm", command=["true"], base_url="http://testserver", api_key="k")
    denied = session.guard(method="tools/call", params={"name": "delete"})
    assert denied["blocked"] is True
    bodies[0] = bodies[1]
    allowed = session.guard(method="tools/call", params={"name": "delete"})
    assert allowed["blocked"] is False
