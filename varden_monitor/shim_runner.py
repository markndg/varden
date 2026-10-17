"""Invoked by PATH shims: resolve real binary, guard (or passive log), execute."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from varden_sdk.sdk import VardenClient
except ModuleNotFoundError:  # pragma: no cover
    from varden_sdk import VardenClient  # type: ignore

from varden_monitor.payload import build_shell_execute_action, raw_payload_for_enrich
from varden_monitor.protect_run import _cap_bytes, _status_from_decision, run_shell_execute_protected


def _client_from_env() -> VardenClient:
    return VardenClient(
        base_url=os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000").rstrip("/"),
        api_key=os.environ.get("VARDEN_API_KEY"),
        bearer_token=os.environ.get("VARDEN_BEARER_TOKEN"),
        timeout=float(os.environ.get("VARDEN_MONITOR_TIMEOUT", "15")),
    )


def _darwin_cursor_cli_candidates() -> tuple[Path, ...]:
    """Cursor IDE ships a CLI inside the .app; users often lack it on PATH."""
    return (
        Path("/Applications/Cursor.app/Contents/Resources/app/bin/cursor"),
        Path.home() / "Applications/Cursor.app/Contents/Resources/app/bin/cursor",
    )


def _resolve_real_binary(tool_name: str) -> str | None:
    orig = os.environ.get("VARDEN_SESSION_ORIG_PATH") or os.environ.get("PATH", "")
    found = shutil.which(tool_name, path=orig)
    if found:
        return found
    if tool_name == "cursor" and sys.platform == "darwin":
        for candidate in _darwin_cursor_cli_candidates():
            if candidate.is_file():
                return str(candidate)
    return None


def _run_child(exec_argv: list[str], cwd: str) -> subprocess.CompletedProcess:
    if sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty():
        rc = subprocess.call(exec_argv, cwd=cwd, env=os.environ.copy())
        return subprocess.CompletedProcess(exec_argv, rc, b"", b"")
    return subprocess.run(exec_argv, cwd=cwd, env=os.environ.copy(), capture_output=True, timeout=None)


def _post_log(
    client: VardenClient,
    *,
    action_out: dict[str, Any],
    decision: dict[str, Any],
    raw: dict[str, Any],
    proc: subprocess.CompletedProcess,
    elapsed_ms: float,
    stdout_cap: int,
    stderr_cap: int,
    fail_mode: str,
) -> None:
    out_payload: dict[str, Any] = {
        "exit_code": proc.returncode,
        "duration_ms": elapsed_ms,
        "stdout": _cap_bytes(proc.stdout, stdout_cap) if proc.stdout else None,
        "stderr": _cap_bytes(proc.stderr, stderr_cap) if proc.stderr else None,
    }
    log_body = {
        "action": action_out,
        "decision": decision,
        "input_payload": raw,
        "output_payload": out_payload,
        "status": _status_from_decision(decision.get("action")),
        "error": None,
    }
    try:
        client.ensure_credentials()
        r = client._client.post(
            f"{client.base_url}/sdk/log",
            headers=client.headers(),
            json=log_body,
            timeout=client._client.timeout,
        )
        r.raise_for_status()
    except Exception as exc:
        if fail_mode == "closed":
            raise
        print(f"varden-monitor: log failed ({exc})", file=sys.stderr)


def _record_override(contract: dict[str, Any], asserted_mode: str | None, asserted_fail: str | None) -> None:
    dest = os.environ.get("VARDEN_SESSION_AUDIT")
    if not dest:
        return
    line = {
        "event": "override_rejected",
        "contract_mode": contract.get("mode"),
        "contract_fail_mode": contract.get("fail_mode"),
        "asserted_mode": asserted_mode,
        "asserted_fail_mode": asserted_fail,
        "authoritative_decision": None,
    }
    with open(dest, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")


def _control_plane_confirms(contract: dict[str, Any]) -> bool:
    import httpx

    base = os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    headers = {"content-type": "application/json"}
    api_key = os.environ.get("VARDEN_API_KEY")
    if api_key:
        headers["x-api-key"] = api_key
    try:
        response = httpx.post(
            f"{base}/runtime/session/contract/confirm",
            headers=headers,
            json=contract,
            timeout=2.0,
        )
    except Exception:
        return False
    return response.status_code == 200


def _session_contract() -> dict[str, Any]:
    """Enforcement values come from the signed contract, never from env overrides.

    The verification key is in this process's environment. A same-user process
    can replace the key, the contract file, and ``VARDEN_BASE_URL``. This check
    is not an operating-system boundary.
    """
    import json as _json

    from varden_monitor.session_contract import ContractError, verify_contract, weaker_mode

    path = os.environ.get("VARDEN_SESSION_CONTRACT")
    key_hex = os.environ.get("VARDEN_SESSION_VERIFY_KEY")
    session_id = os.environ.get("VARDEN_SESSION_ID", "")
    if not path or not key_hex:
        raise ContractError("contract is missing")
    try:
        document = _json.loads(Path(path).read_text(encoding="utf-8"))
        verified = verify_contract(document, raw_key=bytes.fromhex(key_hex), session_id=session_id)
    except ContractError:
        raise
    except Exception as exc:
        raise ContractError("contract is unreadable") from exc
    asserted_mode = os.environ.get("VARDEN_MODE")
    asserted_fail = os.environ.get("VARDEN_MONITOR_FAIL_MODE")
    passive_downgrade = os.environ.get("VARDEN_SESSION_PASSIVE") == "1" and verified["mode"] != "observe"
    downgraded = passive_downgrade or weaker_mode(asserted_mode, str(verified["mode"])) or (
        verified.get("fail_mode") == "closed" and asserted_fail == "open"
    )
    if downgraded:
        _record_override(verified, asserted_mode, asserted_fail)
        raise ContractError("weaker enforcement assertion rejected")
    if verified["mode"] != "observe" and not _control_plane_confirms(verified):
        raise ContractError("control plane unavailable")
    return verified


def main() -> int:
    if len(sys.argv) < 2:
        print("shim_runner: missing tool name", file=sys.stderr)
        return 2
    tool_name = sys.argv[1]
    forwarded = sys.argv[2:]
    real = _resolve_real_binary(tool_name)
    if not real:
        print(
            f"varden-monitor: could not resolve real '{tool_name}' on PATH "
            "(VARDEN_SESSION_ORIG_PATH should exclude session shims).",
            file=sys.stderr,
        )
        return 127
    exec_argv = [real] + forwarded
    cwd = os.getcwd()
    try:
        contract = _session_contract()
    except Exception as exc:
        print(f"varden-monitor: session contract rejected ({exc})", file=sys.stderr)
        return 126
    fail_mode = contract["fail_mode"]
    mode = contract["mode"]
    timeout = float(os.environ.get("VARDEN_MONITOR_TIMEOUT", "15"))
    stdout_cap = int(os.environ.get("VARDEN_MONITOR_STDOUT_CAP", "8000"))
    stderr_cap = int(os.environ.get("VARDEN_MONITOR_STDERR_CAP", "8000"))
    agent = os.environ.get("VARDEN_AGENT_NAME", "varden-session")
    trace = os.environ.get("VARDEN_TRACE_ID")
    workflow = os.environ.get("VARDEN_WORKFLOW_ID")
    tenant = os.environ.get("VARDEN_TENANT_ID", "default")
    execution_surface = os.environ.get("VARDEN_EXECUTION_SURFACE", "varden_monitor")

    client = _client_from_env()

    if mode == "observe":
        action = build_shell_execute_action(
            exec_argv,
            cwd=cwd,
            agent_name=agent,
            trace_id=trace,
            workflow_id=workflow,
            tenant_id=tenant,
            app_name="varden-session",
            execution_surface=execution_surface,
        )
        raw = raw_payload_for_enrich(exec_argv, cwd)
        t0 = time.perf_counter()
        proc = _run_child(exec_argv, cwd)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        decision: dict[str, Any] = {"action": "allow", "reason": "passive_session", "effective_action": "allow"}
        _post_log(
            client,
            action_out=action,
            decision=decision,
            raw=raw,
            proc=proc,
            elapsed_ms=elapsed_ms,
            stdout_cap=stdout_cap,
            stderr_cap=stderr_cap,
            fail_mode=fail_mode,
        )
        return int(proc.returncode if proc.returncode is not None else 1)

    return run_shell_execute_protected(
        exec_argv,
        cwd=cwd,
        base_url=client.base_url,
        api_key=client.api_key,
        bearer_token=client.bearer_token,
        timeout=timeout,
        fail_mode=fail_mode,
        mode=mode,
        agent_name=agent,
        trace_id=trace,
        workflow_id=workflow,
        tenant_id=tenant,
        app_name="varden-session",
        execution_surface=execution_surface,
        stdout_cap=stdout_cap,
        stderr_cap=stderr_cap,
    )


if __name__ == "__main__":
    raise SystemExit(main())
