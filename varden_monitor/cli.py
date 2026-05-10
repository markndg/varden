"""CLI: `varden monitor run|exec -- <command>...` and `varden-monitor` entrypoint."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from varden_monitor.protect_run import run_shell_execute_protected


def _split_on_double_dash(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    i = argv.index("--")
    return argv[:i], argv[i + 1 :]


def _guard_and_run(
    exec_argv: list[str],
    *,
    cwd: str,
    base_url: str,
    api_key: str | None,
    bearer_token: str | None,
    timeout: float,
    agent_name: str,
    trace_id: str | None,
    workflow_id: str | None,
    tenant_id: str,
    fail_mode: str,
    mode: str,
    stdout_cap: int,
    stderr_cap: int,
) -> int:
    """Delegate to SDK-style guard → run → record (see ``protect_run``)."""
    return run_shell_execute_protected(
        exec_argv,
        cwd=cwd,
        base_url=base_url,
        api_key=api_key,
        bearer_token=bearer_token,
        timeout=timeout,
        fail_mode=fail_mode,
        mode=mode,
        agent_name=agent_name,
        trace_id=trace_id,
        workflow_id=workflow_id,
        tenant_id=tenant_id,
        app_name="varden-monitor",
        execution_surface="varden_monitor",
        stdout_cap=stdout_cap,
        stderr_cap=stderr_cap,
    )


def main(argv: list[str] | None = None) -> int:
    raw = list(argv if argv is not None else sys.argv[1:])
    if not raw or raw[0] in ("-h", "--help"):
        print("Usage: varden-monitor run|exec [options] -- <command> [args...]", file=sys.stderr)
        return 0 if raw and raw[0] in ("-h", "--help") else 2

    sub = raw[0]
    if sub not in ("run", "exec"):
        print("varden-monitor: first argument must be 'run' or 'exec'", file=sys.stderr)
        return 2

    pre, remainder = _split_on_double_dash(raw[1:])
    if not remainder:
        print("varden-monitor: missing '-- <command>'; example: varden-monitor run -- python -V", file=sys.stderr)
        return 2

    parser = argparse.ArgumentParser(prog="varden-monitor", description="Wrap host commands with Varden (guard → exec → log)")
    parser.add_argument("--base-url", default=os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.environ.get("VARDEN_API_KEY"))
    parser.add_argument("--bearer", default=os.environ.get("VARDEN_BEARER_TOKEN"))
    parser.add_argument("--agent", default=os.environ.get("VARDEN_AGENT_NAME", "varden-monitor"))
    parser.add_argument("--trace", default=os.environ.get("VARDEN_TRACE_ID"))
    parser.add_argument("--workflow", default=os.environ.get("VARDEN_WORKFLOW_ID"))
    parser.add_argument("--tenant", default=os.environ.get("VARDEN_TENANT_ID", "default"))
    parser.add_argument("--mode", choices=("enforce", "observe"), default=os.environ.get("VARDEN_MODE", "enforce"))
    parser.add_argument("--fail-mode", choices=("open", "closed"), default=os.environ.get("VARDEN_MONITOR_FAIL_MODE", "open"))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("VARDEN_MONITOR_TIMEOUT", "15")))
    parser.add_argument("--stdout-cap", type=int, default=int(os.environ.get("VARDEN_MONITOR_STDOUT_CAP", "8000")))
    parser.add_argument("--stderr-cap", type=int, default=int(os.environ.get("VARDEN_MONITOR_STDERR_CAP", "8000")))
    args = parser.parse_args(pre)

    cwd = os.getcwd()
    return _guard_and_run(
        remainder,
        cwd=cwd,
        base_url=args.base_url,
        api_key=args.api_key,
        bearer_token=args.bearer,
        timeout=args.timeout,
        agent_name=args.agent,
        trace_id=args.trace,
        workflow_id=args.workflow,
        tenant_id=args.tenant,
        fail_mode=args.fail_mode,
        mode=args.mode,
        stdout_cap=args.stdout_cap,
        stderr_cap=args.stderr_cap,
    )


def monitor_argv(argv: list[str] | None) -> int:
    """Entry for `varden monitor ...` (optional leading 'monitor')."""
    raw = list(argv if argv is not None else [])
    if raw and raw[0] == "monitor":
        raw = raw[1:]
    if raw == ["."] or (len(raw) == 1 and raw[0] == "."):
        from varden_monitor.session import start_session

        return start_session(".", passive=True, command=None)
    return main(raw)


__all__ = ["main", "monitor_argv", "_guard_and_run"]
