"""HTTP API for provenance / authority-flow inspection and delegation."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Header, HTTPException

from .delegation import server_issue_delegation
from .engine import explain_analysis
from .models import ProvenanceSource
from .store import ProvenanceStore


def register_provenance_routes(
    app,
    *,
    require: Callable[..., dict[str, Any]],
    provenance_store: ProvenanceStore,
    event_store: Any,
) -> None:
    @app.get("/provenance/summary")
    def provenance_summary(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return provenance_store.summary(tenant_id=record["tenant_id"])

    @app.get("/provenance/findings")
    def provenance_findings(
        finding_type: str | None = None,
        limit: int = 100,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        limit = max(1, min(int(limit or 100), 500))
        return {
            "items": provenance_store.list_findings(
                tenant_id=record["tenant_id"],
                finding_type=finding_type,
                limit=limit,
            )
        }

    @app.get("/authority/violations")
    def authority_violations(
        limit: int = 100,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        items = provenance_store.list_findings(tenant_id=record["tenant_id"], limit=max(1, min(limit, 500)))
        return {
            "items": [
                row for row in items
                if row["type"] in {
                    "delegation_violation", "authority_escalation", "confused_deputy",
                    "untrusted_to_privileged", "provenance_exfiltration_chain",
                    "unknown_provenance_sensitive_action", "cross_server_authority_flow",
                }
            ]
        }

    @app.get("/authority/delegations")
    def authority_delegations(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return {"items": provenance_store.list_delegations(tenant_id=record["tenant_id"])}

    @app.post("/authority/delegations")
    def create_delegation(
        payload: dict[str, Any],
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "admin", scope="write")
        caps = payload.get("capabilities") or []
        if not isinstance(caps, list) or not caps:
            raise HTTPException(status_code=400, detail="capabilities required")
        dlg = server_issue_delegation(
            caps,
            principal=str(payload.get("principal") or "agent"),
            resources=payload.get("resources") or ["*"],
            issued_by=str(record.get("subject") or "control-plane"),
            trace_scope=payload.get("trace_scope"),
            expires_at=payload.get("expires_at"),
        )
        provenance_store.save_delegation(dlg, tenant_id=record["tenant_id"])
        return {"status": "created", "delegation": dlg.to_dict()}

    @app.get("/provenance/sources")
    def provenance_sources(
        trace_id: str | None = None,
        limit: int = 100,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        if not trace_id:
            return {"items": []}
        sources = provenance_store.sources_for_trace(trace_id, tenant_id=record["tenant_id"], limit=max(1, min(limit, 500)))
        return {"items": [s.to_dict() for s in sources]}

    @app.get("/provenance/traces/{trace_id}")
    def provenance_trace(
        trace_id: str,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        events = event_store.list_trace_events(trace_id, tenant_id=record["tenant_id"], limit=200)
        sources = provenance_store.sources_for_trace(trace_id, tenant_id=record["tenant_id"])
        findings = [
            f for f in provenance_store.list_findings(tenant_id=record["tenant_id"], limit=200)
            if f.get("trace_id") == trace_id
        ]
        return {
            "trace_id": trace_id,
            "events": events,
            "sources": [s.to_dict() for s in sources],
            "findings": findings,
        }

    @app.get("/provenance/events/{event_id}")
    def provenance_event(
        event_id: int,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        event = event_store.get_event(event_id, tenant_id=record["tenant_id"])
        if not event:
            raise HTTPException(status_code=404, detail="event not found")
        action = event.get("action") or {}
        meta = action.get("metadata") or {}
        return {
            "event_id": event_id,
            "trace_id": event.get("trace_id"),
            "provenance": meta.get("provenance"),
            "taint": meta.get("taint"),
            "authority": meta.get("authority"),
            "flow": meta.get("flow"),
            "causal": meta.get("causal"),
            "findings": meta.get("findings") or [],
            "attack_path": meta.get("attack_path") or [],
            "explanation": meta.get("explanation") or [],
            "explain_text": explain_analysis(meta, decision=(event.get("decision") or {}).get("action")),
        }

    @app.get("/provenance/flows")
    def provenance_flows(
        limit: int = 50,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        findings = provenance_store.list_findings(tenant_id=record["tenant_id"], limit=max(1, min(limit, 200)))
        return {
            "items": [
                {
                    "type": f["type"],
                    "severity": f["severity"],
                    "trace_id": f["trace_id"],
                    "tool": f["tool"],
                    "resource": f["resource"],
                    "explanation": f["explanation"],
                    "attack_path": (f.get("evidence") or {}).get("attack_path")
                    or (f.get("evidence") or {}).get("path"),
                }
                for f in findings
                if f["type"] in {
                    "provenance_exfiltration_chain", "cross_server_authority_flow",
                    "untrusted_to_privileged", "confused_deputy",
                }
            ]
        }

    @app.get("/mcp/security/tools")
    def mcp_security_tools(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return {"items": provenance_store.list_tool_fingerprints(tenant_id=record["tenant_id"])}

    @app.post("/mcp/security/fingerprint")
    def mcp_security_fingerprint(
        payload: dict[str, Any],
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "analyst", scope="write")
        server_id = str(payload.get("server_id") or "")
        tool_name = str(payload.get("tool_name") or "")
        fingerprint = str(payload.get("fingerprint") or "")
        if not server_id or not tool_name or not fingerprint:
            raise HTTPException(status_code=400, detail="server_id, tool_name and fingerprint required")
        result = provenance_store.upsert_tool_fingerprint(
            tenant_id=record["tenant_id"],
            server_id=server_id,
            tool_name=tool_name,
            fingerprint=fingerprint,
            fields_json=payload.get("fields") or {},
        )
        return result
