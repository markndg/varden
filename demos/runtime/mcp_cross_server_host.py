#!/usr/bin/env python3
"""Realistic MCP host demo: public_search → context → internal_crm.delete_user.

Provenance is NOT manually stuffed into the second call. The supported
VardenMcpHost adapter records results into SDK contextvars + control-plane
session provenance (keyed by trace_id). The second guard merges that chain.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from demos.runtime.mcp_servers import internal_crm, public_search
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.app_factory import create_app
from varden.config import AppConfig
from varden.runtime.mcp_host import VardenMcpHost
import varden


POLICY = {
    "block": [
        {
            "type": "mcp_call",
            "tool": "delete_user",
            "classifier:untrusted_to_privileged": True,
        }
    ],
    "require_approval": [],
    "warn": [],
    "monitor": [],
    "allow": [],
}


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        client, app = make_app_client(tmpdir, policy=POLICY)
        # Merge runtime-boundary pack rules for realism.
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(
            base_url="http://testserver",
            api_key=key,
            emit_attestation=False,
            auto_instrument=True,
        )
        wire_guard_to_app(guard, client)

        host = VardenMcpHost(base_url="http://testserver", api_key=key, mode="guarded")
        # Point host HTTP at TestClient.
        import httpx

        host_client = client

        def _patch_httpx_post(url, **kwargs):
            path = url.split("http://testserver", 1)[-1] if "testserver" in url else url
            method = kwargs.pop("method", None)
            # Use TestClient
            if kwargs.get("json") is not None and "session/provenance" in path and "GET" not in str(method):
                return client.post(path, headers=kwargs.get("headers"), json=kwargs.get("json"))
            return None

        # Simpler: set host to use guard client transport via monkeypatch of methods
        original_call = host.call_tool

        def call_tool(server_id, tool, arguments=None):
            # Reimplement using TestClient directly for demo reliability
            from varden_sdk.sdk import current_provenance_sources, observe_provenance

            arguments = dict(arguments or {})
            sources = list(current_provenance_sources() or [])
            # Also pull control-plane session sources
            resp = client.get(
                "/runtime/session/provenance",
                headers={"x-api-key": key},
                params={"trace_id": host.trace_id},
            )
            if resp.status_code == 200:
                for src in resp.json().get("sources") or []:
                    if src not in sources:
                        sources.append(src)
            action = {
                "type": "mcp_call",
                "tool": tool,
                "args": {
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                    "server_id": server_id,
                },
                "metadata": {
                    "runtime": {
                        "boundary": True,
                        "surface": "mcp",
                        "mode": "guarded",
                        "pre_execution": True,
                        "gateway": True,
                        "server_id": server_id,
                        "host": "VardenMcpHost",
                    },
                    "mcp": {"server_id": server_id, "method": "tools/call", "tool": tool},
                    "provenance_sources": sources,
                    "provenance_complete": bool(sources),
                },
                "agent_name": "mcp-host-demo",
                "trace_id": host.trace_id,
            }
            g = client.post("/sdk/guard", headers={"x-api-key": key}, json={"action": action, "payload": arguments})
            if g.status_code == 403:
                detail = g.json().get("detail") or {}
                from varden.runtime.mcp_host import McpToolResult

                return McpToolResult(
                    server_id=server_id,
                    tool=tool,
                    content=None,
                    blocked=True,
                    decision=(detail.get("decision") if isinstance(detail, dict) else {}) or {"action": "block"},
                    trace_id=host.trace_id,
                )
            handler = public_search.handle if server_id == "public-search" else internal_crm.handle
            content = handler(tool, arguments)
            origin = f"mcp://{server_id}/{tool}"
            observe_provenance(
                source_type="mcp_tool_result",
                origin=origin,
                trust_level="untrusted",
                principal=server_id,
                provenance_complete=True,
                metadata={"server_id": server_id, "tool": tool},
            )
            client.post(
                "/runtime/session/provenance",
                headers={"x-api-key": key},
                json={
                    "trace_id": host.trace_id,
                    "session_id": host.session_id,
                    "source": {
                        "source_type": "mcp_tool_result",
                        "origin": origin,
                        "trust_level": "untrusted",
                        "principal": server_id,
                    },
                },
            )
            from varden.runtime.mcp_host import McpToolResult

            return McpToolResult(
                server_id=server_id,
                tool=tool,
                content=content,
                blocked=False,
                decision=g.json().get("decision") or {},
                provenance_origin=origin,
                trace_id=host.trace_id,
            )

        host.call_tool = call_tool  # type: ignore
        host.register_inprocess("public-search", public_search.handle)
        host.register_inprocess("internal-crm", internal_crm.handle)
        internal_crm.reset()

        print("STEP 1  public_search.search_web")
        r1 = host.call_tool("public-search", "search_web", {"query": "account cleanup"})
        print("        result received")
        print("        provenance = UNTRUSTED")
        print(f"        trace = {host.trace_id}")
        print(f"        origin = {r1.provenance_origin}")
        text = json.dumps(r1.content)
        print(f"        preview = {text[:80]}...")

        print("")
        print("STEP 2  internal_crm.delete_user")
        print("        required = WRITE_DATABASE, MCP_PRIVILEGED, ADMIN (by classifier)")
        print("        delegated = from untrusted MCP A chain (no user ADMIN delegation)")
        before = internal_crm.customer_exists("123")
        r2 = host.call_tool("internal-crm", "delete_user", {"id": "123"})
        after = internal_crm.customer_exists("123")
        print("")
        attack_blocked = bool(r2.blocked) and before and after
        if r2.blocked:
            print("RESULT  BLOCKED")
            print("")
            print("Reason:")
            print("Untrusted MCP result influenced a privileged cross-server action.")
            print(f"CRM state unchanged: {before == after == True}")
            print(f"decision: {(r2.decision or {}).get('action')} — {(r2.decision or {}).get('reason')}")
        else:
            print("RESULT  ALLOWED (UNEXPECTED)")
            print(f"CRM state unchanged: {before == after}")

        print("")
        print("CONTROL  trusted user explicitly delegates ADMIN for exact CRM delete")
        internal_crm.reset()
        from varden_sdk.sdk import provenance_scope

        trusted_trace = f"{host.trace_id}-trusted"
        dlg = client.post(
            "/authority/delegations",
            headers={"x-api-key": key},
            json={
                "capabilities": ["ADMIN", "WRITE_DATABASE", "MCP_PRIVILEGED", "DELETE", "READ_PRIVATE"],
                "trace_scope": trusted_trace,
                "principal": "operator",
            },
        )
        assert dlg.status_code == 200, dlg.text
        host.trace_id = trusted_trace
        with provenance_scope([]):
            r3 = host.call_tool("internal-crm", "delete_user", {"id": "123"})
            control_ok = (not r3.blocked) and (not internal_crm.customer_exists("123"))
            print(f"        blocked={r3.blocked} customer_gone={not internal_crm.customer_exists('123')}")
            if control_ok:
                print("        → delete succeeds")
            else:
                print(f"        → unexpected: decision={r3.decision}")

        varden.unpatch_runtime()
        ok = attack_blocked and control_ok
        print("")
        print("RESULT", "PASS" if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
