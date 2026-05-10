"""Tests for Varden Monitor CLI and shell.execute payloads."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from varden.models import Action
from varden.policy import PolicyEngine
from varden_monitor.cli import _guard_and_run
from varden_monitor.payload import argv_join_for_policy, build_host_exec_action, redact_argv


def test_redact_argv_truncates_long_args():
    argv = ["a" * 3000, "b"]
    out = redact_argv(argv, max_each=100, max_total=5000)
    assert len(out[0]) <= 100
    assert "…" in out[0] or len(out[0]) == 100


def test_build_host_exec_action_shape():
    a = build_host_exec_action(
        ["railway", "up"],
        cwd="/tmp/proj",
        agent_name="cursor-terminal",
        trace_id="t-1",
        workflow_id="w-1",
        tenant_id="default",
    )
    assert a["type"] == "tool_call"
    assert a["tool"] == "shell.execute"
    assert a["args"]["argv"] == ["railway", "up"]
    assert "railway" in a["args"]["argv_join"]
    assert a["metadata"]["execution_surface"] == "varden_monitor"
    assert a["agent_name"] == "cursor-terminal"


def test_host_shell_policy_pack_blocks_rm_rf(tmp_path: Path):
    pack = Path(__file__).resolve().parents[1] / "policy-packs" / "host-shell-safety.json"
    doc = json.loads(pack.read_text(encoding="utf-8"))["template"]
    eng = PolicyEngine(str(tmp_path / "host.db"))
    eng.update_policy(doc)
    join = argv_join_for_policy(["/bin/sh", "-c", "rm -rf /tmp/x"])
    action = Action(
        type="tool_call",
        tool="shell.execute",
        args={"argv": ["rm", "-rf", "/tmp/x"], "argv_join": join, "cwd": "/", "env_keys": []},
    )
    d = eng.evaluate(action)
    assert d.action == "block"


def test_guard_and_run_blocked_before_subprocess(monkeypatch):
    from varden_sdk.sdk import VardenBlockedError

    import varden_monitor.protect_run as pr_mod

    ran: list[bool] = []

    def fake_run(*_a, **_k):
        ran.append(True)
        raise AssertionError("subprocess should not run when blocked")

    def fake_call(*_a, **_k):
        ran.append(True)
        raise AssertionError("subprocess should not run when blocked")

    monkeypatch.setattr(pr_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(pr_mod.subprocess, "call", fake_call)

    mock_guard = MagicMock()
    mock_guard.activate.return_value = mock_guard
    mock_guard.guarded_action.side_effect = VardenBlockedError("blocked", {"action": "block", "reason": "policy"})
    mock_guard.record_result = MagicMock()

    with patch.object(pr_mod, "VardenGuard", return_value=mock_guard):
        with patch.object(pr_mod, "trace_agent") as m_trace:
            m_trace.return_value.__enter__ = MagicMock()
            m_trace.return_value.__exit__ = MagicMock(return_value=False)
            code = _guard_and_run(
                ["python", "-c", "print(1)"],
                cwd="/",
                base_url="http://127.0.0.1:8000",
                api_key=None,
                bearer_token=None,
                timeout=5.0,
                agent_name="t",
                trace_id=None,
                workflow_id=None,
                tenant_id="default",
                fail_mode="open",
                mode="enforce",
                stdout_cap=1000,
                stderr_cap=1000,
            )
    assert code == 125
    assert not ran
    mock_guard.record_result.assert_not_called()


def test_guard_and_run_executes_when_allowed(monkeypatch):
    from varden_sdk.sdk import GuardResult

    import varden_monitor.protect_run as pr_mod

    pr = MagicMock()
    pr.returncode = 0
    pr.stdout = b"ok\n"
    pr.stderr = b""

    monkeypatch.setattr(pr_mod.subprocess, "run", lambda *_a, **_k: pr)

    mock_guard = MagicMock()
    mock_guard.activate.return_value = mock_guard
    mock_guard.guarded_action.return_value = GuardResult(
        decision={"action": "allow", "reason": "ok"},
        action={"type": "tool_call", "tool": "shell.execute"},
        event_id=1,
    )
    mock_guard.record_result = MagicMock()

    with patch.object(pr_mod, "VardenGuard", return_value=mock_guard):
        with patch.object(pr_mod, "trace_agent") as m_trace:
            m_trace.return_value.__enter__ = MagicMock()
            m_trace.return_value.__exit__ = MagicMock(return_value=False)
            code = _guard_and_run(
                ["echo", "hi"],
                cwd="/",
                base_url="http://127.0.0.1:8000",
                api_key=None,
                bearer_token=None,
                timeout=5.0,
                agent_name="t",
                trace_id=None,
                workflow_id=None,
                tenant_id="default",
                fail_mode="open",
                mode="enforce",
                stdout_cap=1000,
                stderr_cap=1000,
            )
    assert code == 0
    mock_guard.record_result.assert_called_once()


def test_intelligence_shell_execute_high_risk_argv():
    from varden.intelligence import DecisionIntelligence

    intel = DecisionIntelligence()
    action = Action(
        type="tool_call",
        tool="shell.execute",
        args={"argv_join": "rm -rf /tmp/foo", "argv": [], "cwd": "/", "env_keys": []},
    )
    intel.enrich(action)
    assert action.risk_score >= 40
    assert "host_exec_high_risk_argv" in (action.risk_reasons or [])
