"""Hardening invariants: approval race, coverage forgery, tamper, MCP causality."""

from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import requests

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app
from varden.runtime.coverage import ENFORCED, UNCOVERED, get_coverage_registry
from varden.runtime.mcp_host import VardenMcpHost


def test_approval_race_exactly_one_consumes():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(
            tmpdir,
            policy={
                "require_approval": [{"type": "tool_call", "tool": "needs_approval"}],
                "block": [],
                "warn": [],
                "monitor": [],
                "allow": [],
            },
        )
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        action = {"type": "tool_call", "tool": "needs_approval", "args": {"t": 1}, "trace_id": "race"}
        first = client.post("/sdk/guard", headers=headers, json={"action": action, "payload": action["args"]})
        token = client.post(f"/approvals/{first.json()['detail']['approval_id']}/approve", headers=headers).json()["token"]

        def retry(_):
            r = client.post(
                "/sdk/guard",
                headers=headers,
                json={"action": {**action, "metadata": {"approval_token": token}}, "payload": action["args"]},
            )
            return r.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(retry, range(8)))
        assert codes.count(200) == 1
        assert codes.count(403) == 7


def test_coverage_forgery_ignored():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        action = {
            "type": "tool_call",
            "tool": "list_files",
            "args": {},
            "metadata": {
                "runtime": {
                    "coverage": "ENFORCED",
                    "status": "ENFORCED",
                    "interceptor_active": True,
                    "mode_claim": "strict",
                    "boundary": True,
                    "surface": "tools",
                }
            },
        }
        r = client.post("/sdk/guard", headers={"x-api-key": key}, json={"action": action, "payload": {}})
        assert r.status_code == 200
        meta = r.json()["action"]["metadata"]["runtime"]
        assert "coverage" not in meta or meta.get("coverage") is None
        assert meta.get("mode_claim") is None
        assert meta.get("interceptor_active") is None


def test_interceptor_tamper_downgrades_coverage():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        original = requests.sessions.Session.request
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        reg = get_coverage_registry()
        assert reg.get("http.requests").status == ENFORCED
        requests.sessions.Session.request = original
        changes = reg.verify()["changes"]
        assert any(c["surface"] == "http.requests" for c in changes)
        assert reg.get("http.requests").status == UNCOVERED
        varden.unpatch_runtime()


def test_mcp_host_cross_server_blocks_without_manual_provenance_injection():
    """Invariant A: supported host path preserves causality via session provenance."""
    from demos.runtime.mcp_servers import internal_crm, public_search

    with TemporaryDirectory() as tmpdir:
        policy = {
            "block": [{"type": "mcp_call", "tool": "delete_user", "classifier:untrusted_to_privileged": True}],
            "warn": [],
            "monitor": [],
            "allow": [],
        }
        client, _ = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)
        host = VardenMcpHost(base_url="http://testserver", api_key=key)
        # Use TestClient-backed calls like the demo
        # Record search via session store + observe
        varden.observe_provenance(
            source_type="mcp_tool_result",
            origin="mcp://public-search/search_web",
            trust_level="untrusted",
            principal="public-search",
            provenance_complete=True,
        )
        client.post(
            "/runtime/session/provenance",
            headers={"x-api-key": key},
            json={
                "trace_id": host.trace_id,
                "source": {
                    "source_type": "mcp_tool_result",
                    "origin": "mcp://public-search/search_web",
                    "trust_level": "untrusted",
                    "principal": "public-search",
                },
            },
        )
        # Second call: do NOT manually put provenance in metadata — rely on control-plane merge in sdk_guard
        action = {
            "type": "mcp_call",
            "tool": "delete_user",
            "args": {"method": "tools/call", "params": {"name": "delete_user", "arguments": {"id": "123"}}, "server_id": "internal-crm"},
            "metadata": {
                "runtime": {"boundary": True, "surface": "mcp", "gateway": True, "server_id": "internal-crm", "pre_execution": True},
                "mcp": {"server_id": "internal-crm"},
            },
            "trace_id": host.trace_id,
            "agent_name": "host",
        }
        r = client.post("/sdk/guard", headers={"x-api-key": key}, json={"action": action, "payload": {"id": "123"}})
        assert r.status_code == 403
        assert r.json()["detail"]["decision"]["action"] == "block"
        varden.unpatch_runtime()


def test_strict_discovered_mcp_not_ready():
    with TemporaryDirectory() as tmpdir:
        mcp = Path(tmpdir) / "mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}), encoding="utf-8")
        try:
            varden.protect(
                mode="strict",
                emit_attestation=False,
                mcp_config=str(mcp),
                base_url="http://127.0.0.1:9",
                api_key="x",
            )
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert "mcp" in str(exc).lower() or "discovered" in str(exc).lower()
        finally:
            varden.unpatch_runtime()


def test_strict_allow_uncovered_mcp():
    with TemporaryDirectory() as tmpdir:
        mcp = Path(tmpdir) / "mcp.json"
        mcp.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}), encoding="utf-8")
        try:
            g = varden.protect(
                mode="strict",
                emit_attestation=False,
                mcp_config=str(mcp),
                allow_uncovered=["mcp"],
                base_url="http://127.0.0.1:9",
                api_key="x",
            )
            ready = get_coverage_registry().strict_readiness()
            assert ready["status"] == "READY WITH EXCEPTIONS"
            assert "mcp" in ready["accepted_exceptions"]
        finally:
            varden.unpatch_runtime()


def test_mode_lock_rejects_silent_downgrade():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            varden.protect(
                mode="strict",
                emit_attestation=False,
                allow_uncovered=["mcp", "http.raw_sockets", "http.aiohttp", "http.urllib3"],
                base_url="http://testserver",
                api_key=key,
            )
            reg = get_coverage_registry()
            try:
                reg.set_session(mode="observe", fail_mode="open")
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "silent downgrade" in str(exc).lower() or "locked" in str(exc).lower()
            assert reg.attestation()["mode"] == "strict"
        finally:
            varden.unpatch_runtime()


def test_db_audit_failure_does_not_convert_block_to_allow():
    from unittest.mock import patch

    from varden.stores import EventStore

    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(
            tmpdir,
            policy={
                "block": [{"type": "tool_call", "tool": "must_block"}],
                "warn": [],
                "monitor": [],
                "allow": [],
            },
        )
        key = client.get("/health").json()["bootstrap_api_key"]
        with patch.object(EventStore, "log", side_effect=RuntimeError("db down")):
            r = client.post(
                "/sdk/guard",
                headers={"x-api-key": key},
                json={"action": {"type": "tool_call", "tool": "must_block", "args": {}}, "payload": {}},
            )
        assert r.status_code == 403
        assert r.json()["detail"]["decision"]["action"] == "block"
