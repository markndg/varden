"""HTTP API for Predictive Authority UI."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Header, HTTPException

from .persistence import load_historical_predictive_event
from .registry import DEMO_TENANT_ID, get_authority_registry, get_demo_registry
from .views import build_demo_fixture, build_event_view, build_session_view


def _scoped_registry(record: dict[str, Any], requested_tenant: str | None):
    """Resolve which tenant/registry a caller may read.

    The caller's own tenant comes from its credential. The only other value
    accepted is the fixed demo tenant, which reads the isolated demo store.
    Any other ``tenant_id`` is refused rather than silently honoured.
    """
    own = str(record.get("tenant_id") or "default")
    if requested_tenant in (None, "", own):
        return own, get_authority_registry()
    if requested_tenant == DEMO_TENANT_ID:
        return DEMO_TENANT_ID, get_demo_registry()
    raise HTTPException(status_code=403, detail="tenant_id does not match credential")


def register_predictive_authority_routes(
    app,
    *,
    require: Callable[..., dict[str, Any]],
    event_store: Any = None,
    db_path: str | None = None,
) -> None:
    @app.get("/predictive/status")
    def predictive_status(
        trace_id: str = "default",
        tenant_id: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        tid, reg = _scoped_registry(record, tenant_id)
        return build_session_view(tenant_id=str(tid), trace_id=str(trace_id), registry=reg)

    @app.get("/predictive/graph")
    def predictive_graph(
        trace_id: str = "default",
        tenant_id: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        tid, reg = _scoped_registry(record, tenant_id)
        view = build_session_view(tenant_id=str(tid), trace_id=str(trace_id), registry=reg)
        return view.get("graph") or {"nodes": [], "edges": [], "truncated": False}

    @app.get("/predictive/events")
    def predictive_events(
        trace_id: str = "default",
        tenant_id: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        tid, reg = _scoped_registry(record, tenant_id)
        view = build_session_view(tenant_id=str(tid), trace_id=str(trace_id), registry=reg)
        return {"items": view.get("events") or []}

    @app.get("/predictive/session/events/{index}")
    def predictive_session_event_detail(
        index: int,
        trace_id: str = "default",
        tenant_id: str | None = None,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        """Live session event by process-local index (not durable identity)."""
        record = require(x_api_key, authorization, "viewer", scope="read")
        tid, reg = _scoped_registry(record, tenant_id)
        row = build_event_view(tenant_id=str(tid), trace_id=str(trace_id), index=index, registry=reg)
        if row is None:
            raise HTTPException(status_code=404, detail="predictive event not found")
        row = dict(row)
        row["historical"] = False
        row["live"] = True
        row["view_kind"] = "live"
        return row

    @app.get("/predictive/events/{event_id}")
    def predictive_event_by_stable_id(
        event_id: int,
        trace_id: str | None = None,
        tenant_id: str | None = None,
        as_index: int = 0,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        """Canonical durable lookup by audit event_id.

        Compatibility: when ``as_index=1`` and ``trace_id`` is provided, treat
        ``event_id`` as a process-local session index (legacy UI).
        """
        record = require(x_api_key, authorization, "viewer", scope="read")
        tid, reg = _scoped_registry(record, tenant_id)

        if as_index and trace_id is not None:
            row = build_event_view(tenant_id=str(tid), trace_id=str(trace_id), index=int(event_id), registry=reg)
            if row is None:
                raise HTTPException(status_code=404, detail="predictive event not found")
            row = dict(row)
            row["historical"] = False
            row["live"] = True
            row["view_kind"] = "live"
            return row

        if db_path is None or event_store is None:
            raise HTTPException(status_code=503, detail="predictive store unavailable")

        view = load_historical_predictive_event(
            event_store=event_store,
            db_path=db_path,
            event_id=int(event_id),
            tenant_id=record["tenant_id"],
        )
        availability = view.get("availability")
        if availability == "missing_event":
            raise HTTPException(status_code=404, detail="event not found")
        if availability in {"integrity_failed", "malformed"}:
            raise HTTPException(
                status_code=409,
                detail=view.get("message") or "Predictive snapshot integrity verification failed.",
            )
        if availability in {"snapshot_removed", "no_predictive", "metadata_only"}:
            raise HTTPException(
                status_code=404,
                detail=view.get("message") or "Predictive analysis is not available for this event.",
            )
        return view

    @app.get("/predictive/from-event/{event_id}")
    def predictive_from_audit_event(
        event_id: int,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        """Deep-link: reconstruct predictive view from durable audit + snapshot."""
        record = require(x_api_key, authorization, "viewer", scope="read")
        if event_store is None or db_path is None:
            raise HTTPException(status_code=503, detail="event store unavailable")
        view = load_historical_predictive_event(
            event_store=event_store,
            db_path=db_path,
            event_id=int(event_id),
            tenant_id=record["tenant_id"],
        )
        availability = view.get("availability")
        if availability == "missing_event":
            raise HTTPException(status_code=404, detail="event not found")
        # Always return structured payload for UI (including unavailable / integrity failed).
        return view

    @app.post("/predictive/demo")
    def predictive_demo(
        mode: str = "enforce",
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        require(x_api_key, authorization, "viewer", scope="write")
        return build_demo_fixture(mode=mode if mode in {"observe", "enforce"} else "enforce")
