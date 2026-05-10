"""
Run a subprocess through the same path as ``VardenGuard.guard_tool``:
``guarded_action`` → execute → ``record_result`` (no ``auto_instrument`` / no monkey-patches).

This matches a ``protect(...)`` + ``executor`` style flow using the existing SDK: one guard
instance, ``trace_agent`` for correlation, then the same policy engine and logging as the rest
of the SDK (dashboard, traces).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

try:
    from varden_sdk.sdk import VardenBlockedError, VardenGuard, trace_agent
except ModuleNotFoundError:  # pragma: no cover
    from varden_sdk import VardenBlockedError, VardenGuard, trace_agent  # type: ignore

from varden_monitor.payload import build_shell_execute_action, raw_payload_for_enrich

SHELL_EXECUTE_TOOL = "shell.execute"


def _status_from_decision(action: str | None) -> str:
    text = str(action or "").strip().lower()
    if text in {"block", "blocked"}:
        return "blocked"
    if text in {"warn", "warned"}:
        return "warned"
    if text == "monitor":
        return "monitor"
    return "allowed"


def _cap_bytes(data: bytes | None, limit: int) -> str | None:
    if not data:
        return None
    try:
        s = data.decode("utf-8", errors="replace")
    except Exception:
        return None
    if len(s) > limit:
        return s[: limit - 20] + "\n…(truncated)"
    return s


def run_shell_execute_protected(
    exec_argv: list[str],
    *,
    cwd: str,
    base_url: str,
    api_key: str | None,
    bearer_token: str | None,
    timeout: float,
    fail_mode: str,
    mode: str,
    agent_name: str,
    trace_id: str | None,
    workflow_id: str | None,
    tenant_id: str,
    app_name: str,
    execution_surface: str,
    stdout_cap: int,
    stderr_cap: int,
) -> int:
    if not exec_argv:
        return 2

    action_dict = build_shell_execute_action(
        exec_argv,
        cwd=cwd,
        agent_name=agent_name,
        trace_id=trace_id,
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        app_name=app_name,
        execution_surface=execution_surface,
    )
    raw = raw_payload_for_enrich(exec_argv, cwd)
    args_payload = action_dict.get("args") or {}
    meta = dict(action_dict.get("metadata") or {})

    guard = VardenGuard(
        base_url=base_url,
        api_key=api_key,
        bearer_token=bearer_token,
        timeout=timeout,
        app_name=app_name,
        tenant=tenant_id,
        mode=mode,
        fail_mode=fail_mode,
        auto_instrument=False,
    )
    guard.activate()

    result = None
    guard_error: str | None = None
    try:
        with trace_agent(agent_name, workflow_id=workflow_id, trace_id=trace_id):
            result = guard.guarded_action(
                type="tool_call",
                tool=SHELL_EXECUTE_TOOL,
                args=args_payload,
                payload=raw,
                metadata=meta,
                agent_name=agent_name,
                workflow_id=workflow_id,
            )
    except VardenBlockedError as e:
        print(str(e), file=sys.stderr)
        if isinstance(e.decision, dict):
            print(e.decision.get("reason", ""), file=sys.stderr)
        return 125
    except Exception as exc:
        guard_error = str(exc)
        if fail_mode == "closed":
            print(f"varden-monitor: guard failed ({exc}); fail_mode=closed aborts.", file=sys.stderr)
            return 126
        result = None

    if result is not None:
        decision = result.decision
        action_out = result.action
    else:
        decision = {
            "action": "allow",
            "reason": f"guard unreachable: {guard_error or 'unknown'}",
            "effective_action": "allow",
        }
        action_out = action_dict

    t0 = time.perf_counter()
    inherit_stdio = bool(sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty())
    if inherit_stdio:
        rc = subprocess.call(exec_argv, cwd=cwd, env=os.environ.copy())
        proc = subprocess.CompletedProcess(exec_argv, rc, b"", b"")
    else:
        proc = subprocess.run(
            exec_argv,
            cwd=cwd,
            env=os.environ.copy(),
            capture_output=True,
            timeout=None,
        )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    out_payload: dict[str, Any] = {
        "exit_code": proc.returncode,
        "duration_ms": elapsed_ms,
        "stdout": _cap_bytes(proc.stdout, stdout_cap) if proc.stdout else None,
        "stderr": _cap_bytes(proc.stderr, stderr_cap) if proc.stderr else None,
    }

    try:
        guard.record_result(
            action=action_out,
            decision=decision,
            input_payload=raw,
            output_payload=out_payload,
            error=None,
        )
    except Exception as exc:
        if fail_mode == "closed":
            print(f"varden-monitor: log failed ({exc}); fail_mode=closed.", file=sys.stderr)
            return 127

    return int(proc.returncode if proc.returncode is not None else 1)


__all__ = ["run_shell_execute_protected", "SHELL_EXECUTE_TOOL", "_cap_bytes", "_status_from_decision"]
