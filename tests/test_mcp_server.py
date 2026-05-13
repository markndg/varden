from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from varden_mcp.server import (
    varden_get_events,
    varden_guard,
    varden_health,
    varden_validate_policy,
)


def test_health_returns_json():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"status": "ok"}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.get.return_value = mock_resp

        out = varden_health()

    assert "ok" in out
    inst.get.assert_called_once_with("/health")


def test_get_events_passes_limit():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"items": [], "total": 0}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.get.return_value = mock_resp

        varden_get_events(limit=15, offset=3)

    inst.get.assert_called_once_with("/events", params={"limit": 15, "offset": 3})


def test_guard_returns_decision():
    guard_resp = MagicMock()
    guard_resp.status_code = 200
    guard_resp.json.return_value = {
        "decision": {"action": "block", "reason": "rule", "matched_rule": {"tool": "delete_database"}},
        "action": {"type": "tool_call", "tool": "delete_database", "args": {}},
        "event_id": 42,
    }
    guard_resp.text = ""

    log_resp = MagicMock()
    log_resp.raise_for_status = MagicMock()
    log_resp.json.return_value = {"logged": True, "event_id": 99}

    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.post.side_effect = [guard_resp, log_resp]

        out = varden_guard(
            {
                "type": "tool_call",
                "tool": "delete_database",
                "args": {},
            }
        )

    assert "block" in out
    assert inst.post.call_count == 2
    guard_call = inst.post.call_args_list[0]
    log_call = inst.post.call_args_list[1]
    assert guard_call[0][0] == "/sdk/guard"
    assert guard_call[1]["json"]["action"]["type"] == "tool_call"
    assert guard_call[1]["json"]["action"]["agent_name"] == "mcp"
    assert log_call[0][0] == "/sdk/log"
    assert log_call[1]["json"]["decision"]["action"] == "block"
    assert log_call[1]["json"]["status"] == "blocked"
    assert log_call[1]["json"]["action"]["agent_name"] == "mcp"


def test_guard_replaces_placeholder_agent_name():
    guard_resp = MagicMock()
    guard_resp.status_code = 200
    guard_resp.json.return_value = {
        "decision": {"action": "allow", "reason": "ok"},
        "action": {"type": "tool_call", "tool": "list_files", "args": {}, "agent_name": "unknown_agent"},
        "event_id": 1,
    }
    guard_resp.text = ""
    log_resp = MagicMock()
    log_resp.raise_for_status = MagicMock()
    log_resp.json.return_value = {"logged": True, "event_id": 2}

    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.post.side_effect = [guard_resp, log_resp]

        varden_guard({"type": "tool_call", "tool": "list_files", "args": {}, "agent_name": "unknown_agent"})

    guard_call = inst.post.call_args_list[0]
    log_call = inst.post.call_args_list[1]
    assert guard_call[1]["json"]["action"]["agent_name"] == "mcp"
    assert log_call[1]["json"]["action"]["agent_name"] == "mcp"


def test_guard_respects_varden_mcp_agent_name_env(monkeypatch):
    monkeypatch.setenv("VARDEN_MCP_AGENT_NAME", "cursor-mcp")

    guard_resp = MagicMock()
    guard_resp.status_code = 200
    guard_resp.json.return_value = {
        "decision": {"action": "allow", "reason": "ok"},
        "action": {"type": "tool_call", "tool": "list_files", "args": {}},
        "event_id": 1,
    }
    guard_resp.text = ""
    log_resp = MagicMock()
    log_resp.raise_for_status = MagicMock()
    log_resp.json.return_value = {"logged": True, "event_id": 2}

    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.post.side_effect = [guard_resp, log_resp]

        varden_guard({"type": "tool_call", "tool": "list_files", "args": {}})

    guard_call = inst.post.call_args_list[0]
    assert guard_call[1]["json"]["action"]["agent_name"] == "cursor-mcp"


def test_validate_policy_invalid():
    req = httpx.Request("POST", "http://127.0.0.1:8000/policy/validate")
    bad = httpx.Response(400, content=b'{"valid":false,"errors":["bad rule"]}', request=req)

    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.post.return_value = bad

        out = varden_validate_policy({"block": [], "warn": [], "monitor": [], "allow": []})

    assert isinstance(out, str)
    assert "error" in out.lower()


def test_unreachable_varden():
    with patch("httpx.Client") as mock_cls:
        inst = MagicMock()
        mock_cls.return_value.__enter__ = MagicMock(return_value=inst)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        inst.get.side_effect = httpx.ConnectError("connection refused")

        out = varden_health()

    assert isinstance(out, str)
    lowered = out.lower()
    assert "error" in lowered or "unreachable" in lowered
