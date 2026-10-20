"""HTTP API for threat intelligence. Read endpoints never activate a rule."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Body, Header, HTTPException

from .approval import ApprovalError
from .service import ThreatIntelService


def register_threat_intelligence_routes(app, *, require: Callable[..., dict[str, Any]], service: ThreatIntelService) -> None:
    app.state.threat_intel = service

    @app.get("/threat-intelligence/status")
    def ti_status(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        return service.status()

    @app.get("/threat-intelligence/sources")
    def ti_sources(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        return {"sources": service.source_views()}

    @app.post("/threat-intelligence/check")
    def ti_check(
        source: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        require(x_api_key, authorization, "analyst", scope="write")
        try:
            return service.check(source)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown threat intelligence source")

    @app.get("/threat-intelligence/items")
    def ti_items(
        source: str | None = None,
        severity: str | None = None,
        lifecycle: str | None = None,
        applicability: str | None = None,
        surface: str | None = None,
        since: float | None = None,
        until: float | None = None,
        q: str | None = None,
        mapping: str | None = None,
        view: str | None = None,
        sort: str = "priority",
        order: str = "asc",
        limit: int = 50,
        offset: int = 0,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        require(x_api_key, authorization, "viewer", scope="read")
        if mapping not in {None, "", "mapped", "unmapped"}:
            raise HTTPException(status_code=400, detail="mapping must be mapped or unmapped")
        if view not in {None, "", "actionable"}:
            raise HTTPException(status_code=400, detail="view must be actionable")
        return service.list_items(
            source=source,
            severity=severity,
            lifecycle=lifecycle,
            applicability=applicability,
            surface=surface,
            since=since,
            until=until,
            query=q,
            mapping=mapping or None,
            view=view or None,
            sort=sort,
            order=order,
            limit=min(max(limit, 1), 200),
            offset=max(offset, 0),
        )

    @app.post("/threat-intelligence/seen")
    def ti_seen(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        return service.mark_seen()

    @app.get("/threat-intelligence/items/{item_id}")
    def ti_show(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        try:
            return service.show(item_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="threat intelligence item not found")

    @app.get("/threat-intelligence/items/{item_id}/contract")
    def ti_contract(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        try:
            return service.contract_for(item_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="threat intelligence item not found")

    @app.get("/threat-intelligence/items/{item_id}/candidate")
    def ti_candidate(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "viewer", scope="read")
        try:
            return service.candidate_for(item_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="threat intelligence item not found")

    @app.post("/threat-intelligence/items/{item_id}/replay")
    def ti_replay(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        require(x_api_key, authorization, "analyst", scope="write")
        try:
            return service.replay(item_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="threat intelligence item not found")

    @app.post("/threat-intelligence/items/{item_id}/approve")
    def ti_approve(
        item_id: str,
        payload: dict[str, Any] | None = Body(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "admin", scope="write")
        actor = str(record.get("user_id") or record.get("role") or "api")
        body = payload or {}
        try:
            return service.approve(
                item_id,
                actor=actor,
                expected_content_hash=body.get("expected_content_hash"),
                expected_candidate_id=body.get("expected_candidate_id"),
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="threat intelligence item not found")
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=exc.message)

    @app.post("/threat-intelligence/items/{item_id}/dismiss")
    def ti_dismiss(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="write")
        return _decide(service, item_id, "dismiss", record)

    @app.post("/threat-intelligence/items/{item_id}/not-applicable")
    def ti_not_applicable(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="write")
        return _decide(service, item_id, "not_applicable", record)

    @app.post("/threat-intelligence/items/{item_id}/review")
    def ti_review(item_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="write")
        return _decide(service, item_id, "review", record)


def _decide(service: ThreatIntelService, item_id: str, action: str, record: dict[str, Any]) -> dict[str, Any]:
    actor = str(record.get("user_id") or record.get("role") or "api")
    try:
        return service.decide(item_id, action, actor=actor)
    except KeyError:
        raise HTTPException(status_code=404, detail="threat intelligence item not found")
    except ApprovalError as exc:
        raise HTTPException(status_code=409, detail=exc.message)
