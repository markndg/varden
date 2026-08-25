"""Tests for incident read model and provenance incident APIs."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.db import init_db
from varden.fsutil import atomic_write_json
from varden.policy_packs import load_policy_pack
from varden.provenance.authority import classify_mcp_tool
from varden.provenance.incidents import (
    FINDING_LABELS,
    build_attack_path_nodes,
    humanize_finding,
    incident_from_event,
    incident_metrics,
    list_incidents_from_events,
)


def _client(tmp_path: Path) -> TestClient:
    db = tmp_path / "t.db"
    auth = tmp_path / "a.db"
    policy = tmp_path / "policy.json"
    pack = load_policy_pack("provenance-authority-defense")
    atomic_write_json(policy, (pack or {"template": {}})["template"])
    init_db(str(db))
    cfg = AppConfig(db_path=str(db), auth_db_path=str(auth), policy_file=str(policy), signing_secret="test")
    return TestClient(create_app(cfg))


def _guard_secret(client: TestClient, key: str, trace_id: str = "inc-1") -> dict:
    home = str(Path.home())
    resp = client.post(
        "/sdk/guard",
        headers={"x-api-key": key},
        json={
            "action": {
                "type": "file_read",
                "tool": "read_file",
                "args": {"path": f"{home}/.ssh/id_rsa"},
                "trace_id": trace_id,
                "agent_name": "demo-agent",
                "metadata": {
                    "lineage": {"sources": ["https://evil.test"]},
                    "provenance_sources": [{
                        "source_id": "w",
                        "source_type": "web_page",
                        "origin": "https://evil.test",
                        "trust_level": "untrusted",
                    }],
                },
            },
            "payload": {"path": f"{home}/.ssh/id_rsa"},
        },
    )
    assert resp.status_code in {200, 403}
    body = resp.json()
    return body.get("detail") if isinstance(body.get("detail"), dict) else body


def test_humanize_finding_labels():
    assert humanize_finding("confused_deputy") == "Confused deputy"
    assert humanize_finding("untrusted_to_privileged") == "Untrusted source attempted privileged action"
    assert humanize_finding("delegation_violation") == "Missing delegated authority"
    assert humanize_finding("provenance_exfiltration_chain") == "Potential data exfiltration"
    for key in FINDING_LABELS:
        assert " " in humanize_finding(key) or humanize_finding(key)[0].isupper()


def test_admin_delete_user_does_not_require_read_secrets():
    req = classify_mcp_tool(
        "admin_delete_user",
        server="crm.internal",
        description="delete user admin",
        privileged_hint=True,
    )
    assert "ADMIN" in req.required
    assert "WRITE_DATABASE" in req.required
    assert "MCP_PRIVILEGED" in req.required
    assert "READ_SECRETS" not in req.required
    assert req.required_reasons["ADMIN"]
    assert req.required_reasons["WRITE_DATABASE"]
    assert "secret" not in req.required_reasons.get("MCP_PRIVILEGED", "").lower() or "privileged" in req.required_reasons["MCP_PRIVILEGED"].lower()


def test_secret_mcp_tool_still_requires_read_secrets():
    req = classify_mcp_tool("fetch_aws_secret", server="vault", description="read aws credential token")
    assert "READ_SECRETS" in req.required
    assert "READ_SECRETS" in req.required_reasons


def test_four_findings_one_incident():
    event = {
        "id": 42,
        "status": "blocked",
        "trace_id": "t1",
        "timestamp": 1.0,
        "agent_name": "agent",
        "decision": {"action": "block", "reason": "authority", "matched_rule": {"id": "provenance-authority-defense/r1"}},
        "action": {
            "type": "mcp_call",
            "tool": "admin_delete_user",
            "agent_name": "demo-agent",
            "metadata": {
                "mcp_server": "crm.internal",
                "enforcement": {
                    "surface": "sdk_guard",
                    "intercepted": True,
                    "pre_execution": True,
                    "side_effect_prevented": True,
                },
                "authority": {
                    "required": ["ADMIN", "MCP_PRIVILEGED", "WRITE_DATABASE"],
                    "granted": ["READ_PUBLIC", "READ_LOCAL"],
                    "missing": ["ADMIN", "MCP_PRIVILEGED", "WRITE_DATABASE"],
                    "violation": True,
                    "resource": "mcp://crm.internal/admin_delete_user",
                    "required_reasons": {
                        "ADMIN": "Administrative operation",
                        "MCP_PRIVILEGED": "Privileged MCP",
                        "WRITE_DATABASE": "Mutating records",
                    },
                },
                "provenance": {
                    "trust": "untrusted",
                    "complete": True,
                    "sources": [{
                        "source_id": "s1",
                        "source_type": "mcp_tool_response",
                        "origin": "mcp://search.example/search_web",
                        "principal": "search.example",
                        "trust_level": "untrusted",
                    }],
                },
                "findings": [
                    {"type": "confused_deputy", "severity": "critical", "explanation": "a"},
                    {"type": "untrusted_to_privileged", "severity": "critical", "explanation": "b"},
                    {"type": "authority_escalation", "severity": "critical", "explanation": "c"},
                    {"type": "delegation_violation", "severity": "critical", "explanation": "d"},
                ],
            },
        },
    }
    incident = incident_from_event(event)
    assert incident is not None
    assert incident["id"] == "evt-42"
    assert incident["finding_count"] == 4
    assert incident["decision"] == "blocked"
    assert len(list_incidents_from_events([event])) == 1
    metrics = incident_metrics([incident])
    assert metrics["incidents_total"] == 1
    assert metrics["findings_on_incidents"] == 4

    path = incident["attack_path"]
    kinds = [n["kind"] for n in path]
    assert "tool_result" in kinds or "source" in kinds or "web_content" in kinds
    assert "mcp_server" in kinds
    assert "tool" in kinds
    assert "enforcement" in kinds or "block" in kinds
    block = path[-1]
    assert block["kind"] in {"enforcement", "block"}
    assert block.get("trust") in (None, "")
    assert block.get("sensitivity") in (None, "")
    assert "HOSTILE" not in str(block.get("trust") or "").upper()

    assert incident["outcome"]["side_effect_prevented"] is True
    assert "THE USER WAS NOT DELETED" in incident["outcome"]["label"] or "DID NOT RUN" in incident["outcome"]["label"]
    assert "intercepted" in incident["outcome"]["detail"].lower() or "stopped" in incident["outcome"]["detail"].lower()
    assert incident["path_index"]["text"]
    assert "search.example" in incident["path_index"]["text"]
    assert incident["path_index"]["text"].count("search.example") == 1
    assert incident["authority"]["required_reasons"]["ADMIN"]
    assert "READ_SECRETS" not in incident["authority"]["required"]
    assert "CRM" in incident["title"] or "privileged" in incident["title"].lower()
    expl = incident["explanation"]
    assert expl["missing_authority"]
    assert expl["text"]

def test_block_node_never_hostile():
    event = {
        "id": 7,
        "status": "blocked",
        "decision": {"action": "block"},
        "action": {
            "type": "file_read",
            "tool": "read_file",
            "metadata": {
                "enforcement": {"surface": "sdk_guard", "side_effect_prevented": True, "pre_execution": True, "intercepted": True},
                "authority": {"required": ["READ_PRIVATE"], "granted": ["READ_PUBLIC"], "missing": ["READ_PRIVATE"], "violation": True, "resource": "/tmp/x"},
                "provenance": {"complete": True, "sources": [{"origin": "https://evil", "source_type": "web_page", "trust_level": "untrusted"}]},
                "findings": [{"type": "confused_deputy", "severity": "critical"}],
            },
        },
    }
    nodes, _ = build_attack_path_nodes(event)
    block = [n for n in nodes if n["kind"] in {"block", "enforcement"}][0]
    assert block.get("trust") is None
    assert block.get("sensitivity") is None


def test_minimal_path_collapses_structural_mcp_duplicates():
    event = {
        "id": 9,
        "status": "blocked",
        "decision": {"action": "block"},
        "action": {
            "type": "file_read",
            "tool": "read_file",
            "agent_name": "demo-agent",
            "metadata": {
                "enforcement": {"surface": "sdk_guard", "side_effect_prevented": True, "pre_execution": True, "intercepted": True},
                "authority": {
                    "required": ["READ_PRIVATE"],
                    "granted": ["READ_LOCAL"],
                    "missing": ["READ_PRIVATE"],
                    "violation": True,
                    "resource": "/Users/demo/Documents/notes.txt",
                },
                "provenance": {
                    "complete": True,
                    "sources": [
                        {
                            "source_id": "tool",
                            "source_type": "mcp_tool_response",
                            "origin": "mcp://search.example/search_web",
                            "principal": "search.example",
                            "trust_level": "untrusted",
                        },
                        {
                            "source_id": "server",
                            "source_type": "unknown",
                            "origin": "mcp://search.example",
                            "principal": "search.example",
                            "trust_level": "untrusted",
                            "legacy_lineage": True,
                        },
                    ],
                },
                "findings": [{"type": "confused_deputy", "severity": "critical"}],
            },
        },
    }
    minimal, _ = build_attack_path_nodes(event, full=False)
    full, _ = build_attack_path_nodes(event, full=True)
    from varden.provenance.incidents import path_preview_labels

    min_srcs = [n for n in minimal if n["kind"] in {"tool_result", "mcp_server", "source"}]
    assert len(min_srcs) == 1
    assert min_srcs[0]["kind"] == "tool_result"
    assert min_srcs[0]["label"] == "Search Web result"
    assert min_srcs[0]["subtitle"] == "search.example"
    full_srcs = [n for n in full if n["kind"] in {"tool_result", "mcp_server", "source"}]
    # Full lineage keeps distinct semantic roles (MCP server + tool result), not triplicate tool_results.
    assert any(n["kind"] == "mcp_server" for n in full_srcs)
    assert any(n["kind"] == "tool_result" for n in full_srcs)
    assert sum(1 for n in full_srcs if n["kind"] == "tool_result") == 1
    assert sum(1 for n in full_srcs if n["kind"] == "mcp_server" and n["label"] == "search.example") == 1
    preview = path_preview_labels(minimal)
    assert preview.count("search.example / Search Web") == 1 or sum(1 for p in preview if "search.example" in p) == 1
    incident = incident_from_event(event)
    assert incident["path_index"]["text"].count("search.example") == 1
    assert "THE REQUESTED FILE WAS NOT READ" in incident["outcome"]["label"]
    # Shared projection: preview string matches path_index.
    assert incident["path_index"]["text"] == " → ".join(incident["attack_path_preview"])


def test_distinct_mcp_servers_not_collapsed():
    event = {
        "id": 10,
        "status": "blocked",
        "decision": {"action": "block"},
        "action": {
            "type": "mcp_call",
            "tool": "admin_delete_user",
            "metadata": {
                "mcp_server": "crm.internal",
                "enforcement": {"surface": "sdk_guard", "side_effect_prevented": True, "pre_execution": True, "intercepted": True},
                "authority": {
                    "required": ["ADMIN", "MCP_PRIVILEGED"],
                    "granted": ["READ_LOCAL"],
                    "missing": ["ADMIN", "MCP_PRIVILEGED"],
                    "violation": True,
                    "resource": "mcp://crm.internal/admin_delete_user",
                },
                "provenance": {
                    "complete": True,
                    "sources": [
                        {
                            "source_id": "s1",
                            "source_type": "mcp_tool_response",
                            "origin": "mcp://search.example/search_web",
                            "principal": "search.example",
                            "trust_level": "untrusted",
                        },
                        {
                            "source_id": "s2",
                            "source_type": "mcp_tool_response",
                            "origin": "mcp://docs.example/get_doc",
                            "principal": "docs.example",
                            "trust_level": "untrusted",
                        },
                    ],
                },
                "findings": [{"type": "cross_server_authority_flow", "severity": "critical"}],
            },
        },
    }
    minimal, _ = build_attack_path_nodes(event, full=False)
    labels = {n["label"] for n in minimal if n["kind"] == "tool_result"}
    origins = {n.get("subtitle") for n in minimal if n["kind"] == "tool_result"}
    assert "Search Web result" in labels
    assert "Get Doc result" in labels
    assert "search.example" in origins
    assert "docs.example" in origins


def test_sanitised_display_decision():
    event = {
        "id": 11,
        "status": "allowed",
        "decision": {"action": "allow"},
        "action": {
            "type": "http_request",
            "tool": "http_get",
            "method": "GET",
            "metadata": {
                "sanitiser": "strict_integer_parser@1",
                "authority": {
                    "required": ["NETWORK_PUBLIC"],
                    "granted": ["NETWORK_PUBLIC", "READ_LOCAL"],
                    "missing": [],
                    "violation": False,
                    "resource": "https://api.weather.example/temp",
                },
                "provenance": {
                    "complete": True,
                    "sources": [{
                        "source_id": "api",
                        "source_type": "http_response",
                        "origin": "https://api.weather.example/feed",
                        "trust_level": "untrusted",
                    }],
                },
            },
        },
    }
    incident = incident_from_event(event)
    assert incident["decision"] == "allowed"
    assert incident["display_decision"] == "sanitised"
    assert "SANITISED" in incident["outcome"]["label"]
    assert any(n["kind"] == "sanitiser" for n in incident["attack_path"])


def test_authority_map_reachability_and_exposure_labels(tmp_path):
    client = _client(tmp_path)
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    _guard_secret(client, key)
    client.post(
        "/mcp/security/fingerprint",
        headers={"x-api-key": key},
        json={"server_id": "search.example", "tool_name": "search_web", "fingerprint": "abc123", "fields": {"trust": "untrusted"}},
    )
    client.post(
        "/mcp/security/fingerprint",
        headers={"x-api-key": key},
        json={"server_id": "crm.internal", "tool_name": "admin_delete_user", "fingerprint": "def456", "fields": {"trust": "unknown"}},
    )
    resp = client.get("/provenance/authority-map", headers={"x-api-key": key})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["layout"] == "lanes"
    assert payload["nodes"]
    assert payload["edges"]
    assert any(e.get("label") == "ARCHITECTURAL EXPOSURE" for e in payload.get("exposures") or [])
    assert "Potential attack path" not in str(payload.get("exposures"))
    # incident overlay
    items = client.get("/provenance/incidents", headers={"x-api-key": key}).json()["items"]
    assert items
    overlay = client.get(
        f"/provenance/authority-map?incident_id={items[0]['id']}",
        headers={"x-api-key": key},
    ).json()
    assert overlay.get("delegation_overlay") is not None or overlay.get("incident_route_node_ids") is not None


def test_authority_map_endpoint(tmp_path):
    client = _client(tmp_path)
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    _guard_secret(client, key)
    client.post(
        "/mcp/security/fingerprint",
        headers={"x-api-key": key},
        json={
            "server_id": "search.example",
            "tool_name": "search_web",
            "fingerprint": "abc123",
            "fields": {"trust": "untrusted"},
        },
    )
    resp = client.get("/provenance/authority-map", headers={"x-api-key": key})
    assert resp.status_code == 200
    payload = resp.json()
    assert any(s["server_id"] == "search.example" for s in payload["mcp_servers"])
    assert payload.get("nodes") is not None


def test_observational_log_does_not_claim_prevention(tmp_path):
    client = _client(tmp_path)
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    resp = client.post(
        "/sdk/log",
        headers={"x-api-key": key},
        json={
            "action": {"type": "file_read", "tool": "read_file", "args": {"path": "/tmp/x"}, "trace_id": "log1", "metadata": {"authority": {"required": ["READ_LOCAL"], "granted": ["READ_LOCAL"], "missing": [], "violation": False}}},
            "decision": {"action": "block", "reason": "client asserted"},
            "status": "blocked",
        },
    )
    assert resp.status_code == 200
    items = client.get("/provenance/incidents", headers={"x-api-key": key}).json()["items"]
    assert items
    top = items[0]
    assert top["outcome"]["side_effect_prevented"] is None
    assert top["outcome"]["label"] == "OBSERVED"


def test_incidents_api_groups_findings(tmp_path):
    client = _client(tmp_path)
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    body = _guard_secret(client, key, trace_id="api-inc-1")
    enf = ((body.get("action") or {}).get("metadata") or {}).get("enforcement") or {}
    assert enf.get("side_effect_prevented") is True

    listing = client.get("/provenance/incidents?limit=20", headers={"x-api-key": key})
    assert listing.status_code == 200
    data = listing.json()
    items = data["items"]
    assert items
    blocked = [i for i in items if i.get("decision") == "blocked"]
    assert blocked
    top = blocked[0]
    assert top["finding_count"] >= 2
    assert top["outcome"]["side_effect_prevented"] is True
    assert top["attack_path"][-1]["kind"] in {"block", "enforcement"}
    assert top["attack_path"][-1].get("trust") in (None, "")
    detail = client.get(f"/provenance/incidents/{top['id']}", headers={"x-api-key": key})
    assert detail.status_code == 200
    assert detail.json()["explanation"]["required_reasons"] or detail.json()["authority"].get("required_reasons") is not None


def test_allowed_workspace_title_and_explanation(tmp_path):
    client = _client(tmp_path)
    key = client.get("/sdk/bootstrap").json()["bootstrap_api_key"]
    workspace = "/tmp/varden-workspace"
    client.post(
        "/sdk/guard",
        headers={"x-api-key": key},
        json={
            "action": {
                "type": "file_read",
                "tool": "read_file",
                "args": {"path": f"{workspace}/README.md"},
                "trace_id": "ws1",
                "metadata": {"workspace": workspace},
            },
            "payload": {},
        },
    )
    items = client.get("/provenance/incidents", headers={"x-api-key": key}).json()["items"]
    allowed = [i for i in items if i["decision"] in {"allowed", "monitored", "warned"}]
    assert allowed
    assert "Workspace" in allowed[0]["title"] or "file read" in allowed[0]["title"].lower()
    assert allowed[0].get("quiet") is True or allowed[0]["finding_count"] == 0
