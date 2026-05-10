"""Stable ``shell.execute`` action payloads for POST /sdk/guard (see SCHEMA.md)."""

from __future__ import annotations

import os
import shlex
from typing import Any

SHELL_EXECUTE_TOOL = "shell.execute"


def _truncate_str(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def redact_argv(argv: list[str], *, max_each: int = 2048, max_total: int = 12000) -> list[str]:
    """Truncate argv elements for transport and logs (secrets may appear in args)."""
    out: list[str] = []
    total = 0
    for i, a in enumerate(argv):
        piece = _truncate_str(str(a), max_each)
        if total + len(piece) > max_total:
            out.append(f"…({len(argv) - i} more args omitted)")
            break
        out.append(piece)
        total += len(piece) + 1
    return out


def argv_join_for_policy(argv: list[str]) -> str:
    """Single string for policy `contains` / `field:args.argv_join` rules."""
    try:
        return " ".join(shlex.quote(str(a)) for a in argv)
    except Exception:
        return " ".join(str(a) for a in argv)


def collect_env_keys(*, max_keys: int = 200) -> list[str]:
    """Variable names only (no values) for policy metadata."""
    keys = sorted(os.environ.keys())
    return keys[:max_keys]


def build_shell_execute_action(
    argv: list[str],
    *,
    cwd: str,
    agent_name: str,
    trace_id: str | None,
    workflow_id: str | None,
    tenant_id: str,
    app_name: str = "varden-monitor",
    env_keys: list[str] | None = None,
    execution_surface: str = "varden_monitor",
    tool: str = SHELL_EXECUTE_TOOL,
) -> dict[str, Any]:
    """Build ``tool_call`` + ``shell.execute`` (or override ``tool``) for /sdk/guard."""
    safe_argv = redact_argv(argv)
    keys = env_keys if env_keys is not None else collect_env_keys()
    return {
        "type": "tool_call",
        "tool": tool,
        "args": {
            "argv": safe_argv,
            "argv_join": _truncate_str(argv_join_for_policy(argv), 8000),
            "cwd": _truncate_str(cwd, 4096),
            "env_keys": keys,
        },
        "metadata": {
            "app_name": app_name,
            "execution_surface": execution_surface,
            "tenant": tenant_id,
        },
        "agent_name": agent_name,
        "workflow_id": workflow_id,
        "trace_id": trace_id or workflow_id,
        "tenant_id": tenant_id,
    }


def build_host_exec_action(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Deprecated alias; use ``build_shell_execute_action``."""
    return build_shell_execute_action(*args, **kwargs)


def raw_payload_for_enrich(argv: list[str], cwd: str) -> dict[str, Any]:
    """Payload passed to classifier / intelligence (may be further redacted server-side)."""
    return {"argv": redact_argv(argv, max_each=1024, max_total=6000), "cwd": cwd}
