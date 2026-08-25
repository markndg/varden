"""HTTP API for provenance / authority-flow inspection and delegation."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Header, HTTPException

from .delegation import server_issue_delegation
from .engine import explain_analysis
from .incidents import (
    authority_map_from_inventory,
    incident_from_event,
    incident_metrics,
    list_incidents_from_events,
)
from .store import ProvenanceStore


def register_provenance_routes(
    app,
    *,
    require: Callable[..., dict[str, Any]],
    provenance_store: ProvenanceStore,
    event_store: Any,
) -> None:
    def _incidents(tenant_id: str | None, *, limit: int = 100) -> list[dict[str, Any]]:
        events = event_store.list_events(limit=max(limit * 3, 150), tenant_id=tenant_id)
        return list_incidents_from_events(events, limit=limit)

    @app.get("/provenance/summary")
    def provenance_summary(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        base = provenance_store.summary(tenant_id=record["tenant_id"])
        incidents = _incidents(record["tenant_id"], limit=200)
        metrics = incident_metrics(incidents)
        base.update(metrics)
        # Prefer incident stories for overview.
        def _story(i: dict[str, Any]) -> dict[str, Any]:
            return {
                "id": i["id"],
                "title": i["title"],
                "summary": i["summary"],
                "decision": i.get("display_decision") or i["decision"],
                "canonical_decision": i["decision"],
                "severity": i["severity"],
                "attack_path_preview": i.get("attack_path_preview") or [],
                "path_index": i.get("path_index") or {},
                "timestamp": i.get("timestamp"),
                "finding_count": i.get("finding_count"),
            }

        stories = [
            _story(i)
            for i in incidents[:4]
            if i.get("decision") in {"blocked", "approval_required"}
            or i.get("severity") in {"critical", "high"}
        ]
        if not stories:
            stories = [_story(i) for i in incidents[:3]]
        exposures = []
        try:
            fingerprints = provenance_store.list_tool_fingerprints(tenant_id=record["tenant_id"], limit=200)
            amap = authority_map_from_inventory(fingerprints=fingerprints, incidents=incidents)
            exposures = (amap.get("exposures") or [])[:3]
        except Exception:
            exposures = []
        base["stories"] = stories
        base["architectural_exposures"] = exposures
        base["architectural_exposure_count"] = len(exposures)
        return base

    @app.get("/provenance/incidents")
    def provenance_incidents(
        limit: int = 50,
        decision: str | None = None,
        severity: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        limit = max(1, min(int(limit or 50), 200))
        items = _incidents(record["tenant_id"], limit=limit)
        if decision:
            items = [i for i in items if i.get("decision") == decision]
        if severity:
            items = [i for i in items if str(i.get("severity") or "").lower() == severity.lower()]
        return {"items": items, "metrics": incident_metrics(items)}

    @app.get("/provenance/incidents/{incident_id}")
    def provenance_incident_detail(
        incident_id: str,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        # incident_id format: evt-<event_id>
        if not str(incident_id).startswith("evt-"):
            raise HTTPException(status_code=404, detail="incident not found")
        try:
            event_id = int(str(incident_id).split("-", 1)[1])
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc
        event = event_store.get_event(event_id, tenant_id=record["tenant_id"])
        if not event:
            raise HTTPException(status_code=404, detail="incident not found")
        incident = incident_from_event(event)
        if not incident:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident

    @app.get("/provenance/authority-map")
    def provenance_authority_map(
        incident_id: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        incidents = _incidents(record["tenant_id"], limit=200)
        fingerprints = provenance_store.list_tool_fingerprints(tenant_id=record["tenant_id"], limit=200)
        selected = None
        if incident_id:
            selected = next((i for i in incidents if i.get("id") == incident_id), None)
        return authority_map_from_inventory(
            fingerprints=fingerprints,
            incidents=incidents,
            selected_incident=selected,
        )

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
        """Legacy findings list — prefer /provenance/incidents for UI."""
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
        """Issue a control-plane verified delegation.

        When ``trace_scope`` is set, also records a verified user provenance
        source for that trace. Client-asserted user trust is never accepted;
        this endpoint is the supported path for user-authorised workflows.
        """
        from .models import ProvenanceSource

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
        user_source = None
        if payload.get("trace_scope"):
            user_source = ProvenanceSource.user(
                principal=str(payload.get("principal") or "user"),
                origin="control-plane:/authority/delegations",
            )
            provenance_store.upsert_source(
                user_source,
                tenant_id=record["tenant_id"],
                trace_id=str(payload["trace_scope"]),
            )
        return {
            "status": "created",
            "delegation": dlg.to_dict(),
            "user_provenance": user_source.to_dict() if user_source else None,
        }

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
            "incidents": list_incidents_from_events(events, limit=50),
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
            "incident": incident_from_event(event),
        }

    @app.get("/provenance/flows")
    def provenance_flows(
        limit: int = 50,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        """Legacy flow findings list — prefer /provenance/incidents for attack paths."""
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
