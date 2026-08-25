"""Supported Varden MCP host adapter — preserves cross-server provenance.

Architecture:
  Host process (this adapter)
       │  observe_provenance (contextvars) + POST session provenance
       ▼
  Per-server Varden gateway (optional) OR in-process mock transport
       │
       ▼
  Downstream MCP server

Causal continuity does NOT rely on manually stuffing provenance into the
second call's metadata in application code. The host adapter records every
untrusted MCP result into:
  1. SDK contextvars (same-process subsequent guards)
  2. Control-plane session provenance keyed by trace_id (cross-gateway)

Gateway processes with the same VARDEN_TRACE_ID merge session provenance
before each privileged guard.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx


@dataclass
class McpToolResult:
    server_id: str
    tool: str
    content: Any
    blocked: bool = False
    decision: dict[str, Any] = field(default_factory=dict)
    provenance_origin: str = ""
    trace_id: str = ""


class VardenMcpHost:
    """Realistic MCP host that uses Varden's supported provenance path."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None,
        trace_id: str | None = None,
        session_id: str | None = None,
        mode: str = "guarded",
        transport: str = "inprocess",
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.trace_id = trace_id or os.environ.get("VARDEN_TRACE_ID") or str(uuid.uuid4())
        self.session_id = session_id or os.environ.get("VARDEN_SESSION_ID") or str(uuid.uuid4())
        self.mode = mode
        self.transport = transport
        self._servers: dict[str, dict[str, Any]] = {}
        self._handlers: dict[str, Callable[[str, dict[str, Any]], Any]] = {}
        self._lock = threading.Lock()
        os.environ.setdefault("VARDEN_TRACE_ID", self.trace_id)
        os.environ.setdefault("VARDEN_SESSION_ID", self.session_id)

    def register_inprocess(self, server_id: str, handler: Callable[[str, dict[str, Any]], Any]) -> None:
        """Register an in-process mock MCP tool handler (no custom guard code)."""
        self._handlers[server_id] = handler
        self._servers[server_id] = {"transport": "inprocess"}

    def register_gateway(self, server_id: str, command: list[str], env: dict[str, str] | None = None) -> None:
        self._servers[server_id] = {"transport": "gateway", "command": command, "env": env or {}}

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.api_key:
            h["x-api-key"] = self.api_key
        return h

    def _observe_local(self, *, server_id: str, tool: str) -> str:
        origin = f"mcp://{server_id}/{tool}"
        try:
            from varden_sdk.sdk import observe_provenance

            observe_provenance(
                source_type="mcp_tool_result",
                origin=origin,
                trust_level="untrusted",
                principal=server_id,
                provenance_complete=True,
                metadata={"server_id": server_id, "tool": tool, "host": "VardenMcpHost"},
            )
        except Exception:
            pass
        # Control-plane session store — survives gateway process boundaries.
        entry = {
            "source_type": "mcp_tool_result",
            "origin": origin,
            "trust_level": "untrusted",
            "principal": server_id,
            "metadata": {"server_id": server_id, "tool": tool, "host": "VardenMcpHost"},
        }
        try:
            with httpx.Client(timeout=5.0) as client:
                client.post(
                    f"{self.base_url}/runtime/session/provenance",
                    headers=self._headers(),
                    json={
                        "trace_id": self.trace_id,
                        "session_id": self.session_id,
                        "source": entry,
                    },
                )
        except Exception:
            pass
        return origin

    def _session_sources(self) -> list[dict[str, Any]]:
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
            pass
        try:
            from varden_sdk.sdk import current_provenance_sources

            return list(current_provenance_sources() or [])
        except Exception:
            return []

    def call_tool(self, server_id: str, tool: str, arguments: dict[str, Any] | None = None) -> McpToolResult:
        arguments = dict(arguments or {})
        # Merge session + local provenance for the guard (supported path).
        sources = self._session_sources()
        try:
            from varden_sdk.sdk import current_provenance_sources

            local = list(current_provenance_sources() or [])
            for item in local:
                if item not in sources:
                    sources.append(item)
        except Exception:
            pass

        action = {
            "type": "mcp_call",
            "tool": tool,
            "args": {"method": "tools/call", "params": {"name": tool, "arguments": arguments}, "server_id": server_id},
            "metadata": {
                "runtime": {
                    "boundary": True,
                    "surface": "mcp",
                    "mode": self.mode,
                    "pre_execution": True,
                    "gateway": True,
                    "server_id": server_id,
                    "host": "VardenMcpHost",
                },
                "mcp": {"server_id": server_id, "method": "tools/call", "tool": tool},
                "provenance_sources": sources,
                "provenance_complete": bool(sources),
            },
            "agent_name": os.environ.get("VARDEN_AGENT_NAME", "mcp-host"),
            "trace_id": self.trace_id,
        }
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{self.base_url}/sdk/guard",
                headers=self._headers(),
                json={"action": action, "payload": arguments},
            )
            data = resp.json() if resp.content else {}
            if resp.status_code == 403:
                detail = data.get("detail") if isinstance(data, dict) else data
                decision = detail.get("decision") if isinstance(detail, dict) else {"action": "block"}
                return McpToolResult(
                    server_id=server_id,
                    tool=tool,
                    content=None,
                    blocked=True,
                    decision=decision if isinstance(decision, dict) else {"action": "block"},
                    trace_id=self.trace_id,
                )
            resp.raise_for_status()

        # Execute downstream only after allow.
        if server_id in self._handlers:
            content = self._handlers[server_id](tool, arguments)
        else:
            content = {"ok": True, "echo": arguments}

        origin = self._observe_local(server_id=server_id, tool=tool)
        return McpToolResult(
            server_id=server_id,
            tool=tool,
            content=content,
            blocked=False,
            decision=(data.get("decision") if isinstance(data, dict) else {}) or {},
            provenance_origin=origin,
            trace_id=self.trace_id,
        )
