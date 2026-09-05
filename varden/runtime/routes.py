"""HTTP routes for runtime coverage, session provenance, and scoped approvals."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Header, HTTPException


def register_runtime_routes(
    app,
    *,
    require: Callable[..., Any],
    approval_store: Any,
    coverage_store: Any | None = None,
    get_live_coverage: Callable[[], dict[str, Any]] | None = None,
    session_provenance_store: Any | None = None,
    get_strict_readiness: Callable[[], dict[str, Any]] | None = None,
    get_posture: Callable[[], dict[str, Any]] | None = None,
) -> None:
    @app.get("/runtime/coverage")
    def runtime_coverage(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        live = get_live_coverage() if get_live_coverage else {}
        persisted = []
        if coverage_store is not None:
            try:
                persisted = coverage_store.list_attestations(record["tenant_id"], limit=5)
            except Exception:
                persisted = []
        return {
            "tenant_id": record["tenant_id"],
            "live": live,
            "recent_attestations": persisted,
            "note": (
                "Coverage statuses reflect active instrumentation where known. "
                "Clients cannot forge ENFORCED status — server/live registry is authoritative."
            ),
        }

    @app.get("/runtime/posture")
    def runtime_posture(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        require(x_api_key, authorization, "viewer", scope="read")
        if get_posture:
            return get_posture()
        from varden.runtime.posture import evaluate_posture

        live = get_live_coverage() if get_live_coverage else {}
        if live:
            return evaluate_posture(attestation=live, self_test="not_run").to_dict()
        return evaluate_posture(self_test="not_run").to_dict()

    @app.get("/runtime/status")
    def runtime_status(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        live = get_live_coverage() if get_live_coverage else {}
        return {
            "tenant_id": record["tenant_id"],
            "mode": (live or {}).get("mode"),
            "fail_mode": (live or {}).get("fail_mode"),
            "strict_readiness": (live or {}).get("strict_readiness"),
            "categories": (live or {}).get("categories") or [],
        }

    @app.get("/runtime/readiness")
    def runtime_readiness(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        require(x_api_key, authorization, "viewer", scope="read")
        if get_strict_readiness:
            return get_strict_readiness()
        live = get_live_coverage() if get_live_coverage else {}
        return live.get("strict_readiness") or {"status": "UNKNOWN"}

    @app.post("/runtime/session/provenance")
    def runtime_session_provenance_append(
        payload: dict,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        if session_provenance_store is None:
            raise HTTPException(status_code=503, detail="session provenance unavailable")
        trace_id = str(payload.get("trace_id") or "")
        source = payload.get("source") or {}
        if not trace_id or not isinstance(source, dict):
            raise HTTPException(status_code=400, detail="trace_id and source required")
        session_provenance_store.append(
            tenant_id=record["tenant_id"],
            trace_id=trace_id,
            session_id=payload.get("session_id"),
            source=source,
        )
        return {"recorded": True, "trace_id": trace_id}

    @app.get("/runtime/session/provenance")
    def runtime_session_provenance_list(
        trace_id: str,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="read")
        if session_provenance_store is None:
            return {"sources": []}
        sources = session_provenance_store.list_sources(tenant_id=record["tenant_id"], trace_id=trace_id)
        return {"trace_id": trace_id, "sources": sources}

    @app.get("/approvals/pending")
    def approvals_pending(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        limit: int = 50,
    ):
        record = require(x_api_key, authorization, "analyst", scope="read")
        items = approval_store.list_pending(record["tenant_id"], limit=limit)
        for item in items:
            item.pop("token_hash", None)
        return {"items": items}

    @app.post("/approvals/{approval_id}/approve")
    def approvals_approve(
        approval_id: str,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "admin", scope="write")
        try:
            out = approval_store.approve(
                record["tenant_id"],
                approval_id,
                resolved_by=record.get("username") or record.get("role") or "admin",
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="approval not found")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "approval_id": out.get("approval_id"),
            "status": out.get("status"),
            "token": out.get("token"),
            "expires_at": out.get("expires_at"),
            "retry_semantics": (
                "Original attempt was blocked. Retry the exact same operation "
                "with metadata.approval_token set to this token. The boundary "
                "validates and consumes the token on success."
            ),
        }

    @app.post("/approvals/{approval_id}/deny")
    def approvals_deny(
        approval_id: str,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "admin", scope="write")
        try:
            out = approval_store.deny(
                record["tenant_id"],
                approval_id,
                resolved_by=record.get("username") or record.get("role") or "admin",
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="approval not found")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        out.pop("token_hash", None)
        return out

    @app.get("/approvals/{approval_id}")
    def approvals_get(
        approval_id: str,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "analyst", scope="read")
        row = approval_store.get(record["tenant_id"], approval_id)
        if not row:
            raise HTTPException(status_code=404, detail="approval not found")
        row.pop("token_hash", None)
        return row
