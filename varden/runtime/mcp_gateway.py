"""Varden MCP Gateway — proxy that owns downstream MCP sessions and enforces policy."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

# Methods that must pass through the runtime boundary before forwarding.
PRIVILEGED_METHODS = frozenset(
    {
        "tools/call",
        "resources/read",
        "prompts/get",
    }
)

# Methods we observe/fingerprint but typically allow after recording.
OBSERVED_METHODS = frozenset(
    {
        "initialize",
        "tools/list",
        "resources/list",
        "prompts/list",
        "notifications/initialized",
        "notifications/tools/list_changed",
    }
)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except Exception:
        return str(value)


class McpGatewaySession:
    """One downstream MCP server session over stdio."""

    def __init__(
        self,
        *,
        server_id: str,
        command: list[str],
        env: dict[str, str] | None = None,
        base_url: str,
        api_key: str | None,
        mode: str = "guarded",
        cwd: str | None = None,
    ):
        self.server_id = server_id
        self.command = command
        self.env = env or {}
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.mode = mode
        self.cwd = cwd
        self.proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self.tool_fingerprints: dict[str, str] = {}
        self.trace_id = os.environ.get("VARDEN_TRACE_ID") or str(uuid.uuid4())
        self.provenance_chain: list[dict[str, Any]] = []

    def start(self) -> None:
        env = os.environ.copy()
        env.update(self.env)
        # Correlation only — never client-authoritative trust claims.
        env.setdefault("VARDEN_TRACE_ID", self.trace_id)
        env.setdefault("VARDEN_SESSION_ID", os.environ.get("VARDEN_SESSION_ID", ""))
        env.setdefault("VARDEN_BOUNDARY_URL", self.base_url)
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=self.cwd,
            env=env,
        )

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def guard(self, *, method: str, params: dict[str, Any]) -> dict[str, Any]:
        tool_name = None
        if method == "tools/call":
            tool_name = (params or {}).get("name")
        # Merge local chain + control-plane session provenance (cross-server continuity).
        session_sources = self._fetch_session_provenance()
        merged = list(session_sources)
        for item in self.provenance_chain:
            if item not in merged:
                merged.append(item)
        action = {
            "type": "mcp_call",
            "tool": tool_name or method,
            "args": {
                "method": method,
                "params": _json_safe(params or {}),
                "server_id": self.server_id,
            },
            "metadata": {
                "runtime": {
                    "boundary": True,
                    "surface": "mcp",
                    "mode": self.mode,
                    "pre_execution": True,
                    "gateway": True,
                    "server_id": self.server_id,
                },
                "mcp": {"server_id": self.server_id, "method": method},
                "provenance_sources": merged,
                "provenance_complete": bool(merged),
            },
            "agent_name": os.environ.get("VARDEN_AGENT_NAME", "mcp-gateway"),
            "trace_id": self.trace_id,
            "tenant_id": os.environ.get("VARDEN_TENANT", "default"),
        }
        payload = {"action": action, "payload": params or {}}
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(f"{self.base_url}/sdk/guard", headers=self._headers(), json=payload)
            data = resp.json() if resp.content else {}
            if resp.status_code == 403:
                detail = data.get("detail") if isinstance(data, dict) else data
                return {"blocked": True, "status_code": 403, "detail": detail}
            resp.raise_for_status()
            return {"blocked": False, "result": data}

    def _fetch_session_provenance(self) -> list[dict[str, Any]]:
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    f"{self.base_url}/runtime/session/provenance",
                    headers=self._headers(),
                    params={"trace_id": self.trace_id},
                )
                if resp.status_code == 200:
                    return list((resp.json() or {}).get("sources") or [])
        except Exception:
            return []
        return []

    def observe_result(self, *, method: str, result: Any) -> None:
        """Taint downstream results into gateway + control-plane session provenance."""
        tool = None
        if isinstance(result, dict):
            tool = result.get("name")
        origin = f"mcp://{self.server_id}/{tool}" if tool else f"mcp://{self.server_id}"
        entry = {
            "source_type": "mcp_tool_result" if method == "tools/call" else "mcp_server",
            "origin": origin,
            "trust_level": "untrusted",
            "integrity": "unverified",
            "principal": self.server_id,
            "metadata": {"method": method, "server_id": self.server_id, "tool": tool},
        }
        self.provenance_chain.append(entry)
        try:
            with httpx.Client(timeout=5.0) as client:
                client.post(
                    f"{self.base_url}/runtime/session/provenance",
                    headers=self._headers(),
                    json={
                        "trace_id": self.trace_id,
                        "session_id": os.environ.get("VARDEN_SESSION_ID"),
                        "source": entry,
                    },
                )
        except Exception:
            pass

    def fingerprint_tools(self, tools: list[dict[str, Any]]) -> None:
        for tool in tools or []:
            name = str(tool.get("name") or "")
            body = json.dumps(tool, sort_keys=True, default=str)
            import hashlib

            fp = hashlib.sha256(body.encode("utf-8")).hexdigest()
            prev = self.tool_fingerprints.get(name)
            self.tool_fingerprints[name] = fp
            if prev and prev != fp:
                # Drift is recorded via guard metadata on next call; stderr for operators.
                print(
                    f"Varden MCP gateway: tool definition drift on {self.server_id}/{name}",
                    file=sys.stderr,
                )

    def exchange(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("gateway session not started")
        method = message.get("method")
        params = message.get("params") or {}
        msg_id = message.get("id")

        if method in PRIVILEGED_METHODS or method in OBSERVED_METHODS:
            if method in PRIVILEGED_METHODS:
                decision = self.guard(method=str(method), params=params if isinstance(params, dict) else {"value": params})
                if decision.get("blocked"):
                    detail = decision.get("detail") or {}
                    reason = detail
                    if isinstance(detail, dict):
                        reason = (detail.get("decision") or {}).get("reason") or detail
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32000,
                            "message": f"blocked by Varden MCP gateway: {reason}",
                            "data": detail,
                        },
                    }

        line = json.dumps(message, ensure_ascii=False)
        with self._lock:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
            if msg_id is None:
                return None  # notification — no response expected
            # Read until matching id (simple line-delimited JSON-RPC).
            while True:
                raw = self.proc.stdout.readline()
                if not raw:
                    raise RuntimeError("downstream MCP server closed stdout")
                try:
                    resp = json.loads(raw)
                except Exception:
                    continue
                if resp.get("id") == msg_id:
                    if method == "tools/list":
                        result = resp.get("result") or {}
                        tools = result.get("tools") if isinstance(result, dict) else None
                        if isinstance(tools, list):
                            self.fingerprint_tools(tools)
                    if method in PRIVILEGED_METHODS and "result" in resp:
                        self.observe_result(method=str(method), result=params)
                    return resp


def load_mcp_config(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "mcpServers" not in data and "servers" in data:
        data = {"mcpServers": data["servers"]}
    return data


def wrap_mcp_config(config: dict[str, Any], *, gateway_cmd: list[str] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Rewrite mcpServers entries to route through Varden gateway.

    Returns (new_config, change_log).
    """
    servers = dict(config.get("mcpServers") or {})
    changes: list[dict[str, Any]] = []
    wrapped: dict[str, Any] = {}
    py = sys.executable
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            wrapped[name] = entry
            continue
        # Already wrapped?
        cmd = entry.get("command")
        args = list(entry.get("args") or [])
        if cmd == py and args and args[0] == "-m" and "varden.runtime.mcp_gateway" in args:
            wrapped[name] = entry
            changes.append({"server": name, "change": "already_wrapped"})
            continue
        downstream = {
            "command": entry.get("command"),
            "args": entry.get("args") or [],
            "env": entry.get("env") or {},
            "cwd": entry.get("cwd"),
        }
        new_entry = {
            "command": py,
            "args": [
                "-m",
                "varden.runtime.mcp_gateway",
                "--server-id",
                name,
                "--downstream-json",
                json.dumps(downstream),
            ],
            "env": {
                **(entry.get("env") or {}),
                "VARDEN_BASE_URL": os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000"),
                "VARDEN_API_KEY": os.environ.get("VARDEN_API_KEY", ""),
                "VARDEN_MODE": os.environ.get("VARDEN_MODE", "guarded"),
            },
        }
        wrapped[name] = new_entry
        changes.append(
            {
                "server": name,
                "change": "wrapped",
                "from": {"command": cmd, "args": args},
                "to": {"command": new_entry["command"], "args": new_entry["args"][:6] + ["…"]},
            }
        )
    return {"mcpServers": wrapped}, changes


def run_stdio_gateway(
    *,
    server_id: str,
    command: list[str],
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> int:
    base_url = os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.environ.get("VARDEN_API_KEY")
    mode = os.environ.get("VARDEN_MODE", "guarded")
    session = McpGatewaySession(
        server_id=server_id,
        command=command,
        env=env,
        base_url=base_url,
        api_key=api_key,
        mode=mode,
        cwd=cwd,
    )
    session.start()
    try:
        from varden.runtime.coverage import ENFORCED, get_coverage_registry

        get_coverage_registry().mark(
            "mcp",
            status=ENFORCED,
            interceptor="varden.runtime.mcp_gateway",
            active=True,
            applicable=True,
            enforcement_mode="enforced",
            evidence={"server_id": server_id},
            limitations=["Direct MCP connections outside the gateway remain uncovered."],
        )
    except Exception:
        pass
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except Exception:
                continue
            # Notifications without id
            if message.get("id") is None and message.get("method"):
                try:
                    session.exchange(message)
                except Exception as exc:
                    print(f"gateway notification error: {exc}", file=sys.stderr)
                continue
            try:
                resp = session.exchange(message)
            except Exception as exc:
                resp = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {"code": -32001, "message": f"gateway error: {exc}"},
                }
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
    finally:
        session.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="varden.runtime.mcp_gateway", description="Varden MCP Gateway")
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--downstream-json", default=None, help="JSON with command/args/env/cwd")
    parser.add_argument("--command", nargs=argparse.REMAINDER, help="Downstream command after --")
    args = parser.parse_args(argv)
    if args.downstream_json:
        downstream = json.loads(args.downstream_json)
        cmd = [downstream["command"], *list(downstream.get("args") or [])]
        return run_stdio_gateway(
            server_id=args.server_id,
            command=cmd,
            env=downstream.get("env"),
            cwd=downstream.get("cwd"),
        )
    command = list(args.command or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("downstream command required", file=sys.stderr)
        return 2
    return run_stdio_gateway(server_id=args.server_id, command=command)


if __name__ == "__main__":
    raise SystemExit(main())
