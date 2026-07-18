from __future__ import annotations

import json
from typing import Any, Callable

from fastapi import FastAPI, Header, HTTPException

from varden.idempotency import IdempotencyConflict

from .models import WebMCPToolDefinition
from .store import WebShieldStore

MAX_PAYLOAD_BYTES = 200_000


def _check_payload_size(payload: Any, *, max_bytes: int = MAX_PAYLOAD_BYTES) -> None:
    """Structural, post-parse defence in depth.

    By the time this runs, FastAPI has already buffered and JSON-decoded the
    request body — the earliest, pre-parse rejection (before any bytes are
    parsed as JSON) is ``RequestBodySizeLimitMiddleware``
    (``varden/middleware.py``), installed on the whole app in
    ``varden/app_factory.py``. This check exists to (a) bound the decoded
    structure specifically, independent of exact wire-format byte count, and
    (b) still fail safe for any caller of these functions that isn't sitting
    behind that middleware (e.g. direct unit tests of route logic). See
    docs/web-shield-hardening-review.md #8.
    """
    try:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    except Exception:
        size = 0
    if size > max_bytes:
        raise HTTPException(
            status_code=413,
            detail={"error_code": "PAYLOAD_TOO_LARGE", "message": f"payload exceeds {max_bytes} byte limit ({size} bytes)"},
        )


def _require_str(payload: dict, key: str) -> str:
    value = payload.get(key)
    if not value or not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"'{key}' is required and must be a string")
    return value


def register_webshield_routes(
    app: FastAPI,
    *,
    require: Callable,
    webshield_store: WebShieldStore,
    idem,
) -> None:
    """Register all Web Shield API routes onto the existing FastAPI app.

    Uses exactly the same conventions as the rest of ``varden/app_factory.py``
    (``require(x_api_key, authorization, role, scope)``, ``Header(default=None)``
    params, idempotency-key replay protection like ``PUT /policy``). Kept in
    a dedicated module rather than inline in ``app_factory.py`` purely
    because of the size of this subsystem — the wiring itself is identical.
    """

    def _idempotent(
        idempotency_key: str | None, compute: Callable[[], dict], *,
        tenant_id: str | None, principal: str | None, route: str, body: Any,
    ) -> dict:
        if idempotency_key:
            try:
                cached = idem.get(idempotency_key, tenant_id=tenant_id, principal=principal, method="POST", route=route, body=body)
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail={"error_code": exc.error_code, "message": str(exc)})
            if cached is not None:
                return cached
        response = compute()
        if idempotency_key:
            idem.put(idempotency_key, response, tenant_id=tenant_id, principal=principal, method="POST", route=route, body=body)
        return response

    def _principal(record: dict) -> str:
        # API-key auth records carry key_hash; bearer-token auth records
        # carry user_id. Either uniquely identifies the authenticated caller
        # without ever storing/comparing raw credentials.
        return str(record.get("key_hash") or record.get("user_id") or "unknown")

    def _maybe_raise_block(result: dict) -> dict:
        decision = ((result.get("event") or {}).get("decision") or {}).get("action")
        if decision == "block":
            raise HTTPException(status_code=403, detail=result)
        return result

    # ------------------------------------------------------------ registration

    @app.post("/webshield/registrations")
    def webshield_register(
        payload: dict,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        _check_payload_size(payload)
        session_id = _require_str(payload, "session_id")
        tool_raw = payload.get("tool")
        if not isinstance(tool_raw, dict) or not tool_raw.get("name"):
            raise HTTPException(status_code=400, detail="'tool' is required and must include a 'name'")
        owner_origin = _require_str(payload, "owner_origin")

        def compute():
            tool = WebMCPToolDefinition.from_raw(
                tool_raw,
                owner_origin=owner_origin,
                top_origin=payload.get("top_origin") or owner_origin,
                api_surface=payload.get("api_surface") or "document_model_context",
                registration_source=payload.get("registration_source"),
            )
            outcome = webshield_store.register_tool(
                record["tenant_id"],
                session_id=session_id,
                tool=tool,
                tab_id=payload.get("tab_id"),
                frame_id=payload.get("frame_id"),
                is_third_party_frame=bool(payload.get("is_third_party_frame", False)),
                script_source_origin=payload.get("script_source_origin"),
                session_started_at=payload.get("session_started_at"),
                session_already_active=bool(payload.get("session_already_active", False)),
                extension_version=payload.get("extension_version"),
                sdk_version=payload.get("sdk_version"),
                enforcement_capable=bool(payload.get("enforcement_capable", True)),
            )
            requested = ((outcome.get("event") or {}).get("action") or {}).get("metadata", {}).get("requested_enforcement")
            if requested == "require_approval":
                approval = webshield_store.create_approval(
                    record["tenant_id"], session_id=session_id, identity_key=outcome["identity_key"],
                    tool_name=tool.name, owner_origin=tool.owner_origin, args=None,
                    risk_score=outcome["scan"]["risk"]["score"], risk_band=outcome["scan"]["risk"]["band"],
                    reason="Policy requires approval before this tool is exposed to the agent.",
                )
                outcome["approval"] = approval
            return outcome

        result = _idempotent(idempotency_key, compute, tenant_id=record["tenant_id"], principal=_principal(record), route="POST /webshield/registrations", body=payload)
        return _maybe_raise_block(result)

    # ------------------------------------------------------------ lifecycle

    @app.post("/webshield/lifecycle")
    def webshield_lifecycle(
        payload: dict,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        _check_payload_size(payload)
        session_id = _require_str(payload, "session_id")
        event = _require_str(payload, "event")

        def compute():
            if event == "unregister":
                identity_key = _require_str(payload, "identity_key")
                return webshield_store.unregister_tool(
                    record["tenant_id"], session_id=session_id, identity_key=identity_key,
                    frame_id=payload.get("frame_id"),
                    enforcement_capable=bool(payload.get("enforcement_capable", True)),
                )
            if event == "context_replaced":
                return webshield_store.record_context_replaced(
                    record["tenant_id"], session_id=session_id, top_origin=payload.get("top_origin", ""), details=payload.get("details"),
                )
            if event == "surface_changed":
                return webshield_store.record_surface_changed(
                    record["tenant_id"], session_id=session_id, owner_origin=payload.get("owner_origin", ""), details=payload.get("details"),
                )
            if event == "extension_tamper_detected":
                return webshield_store.record_tamper_detected(
                    record["tenant_id"], session_id=session_id, top_origin=payload.get("top_origin"), details=payload.get("details"),
                )
            raise HTTPException(status_code=400, detail=f"unknown lifecycle event: {event}")

        result = _idempotent(idempotency_key, compute, tenant_id=record["tenant_id"], principal=_principal(record), route="POST /webshield/lifecycle", body=payload)
        return _maybe_raise_block(result)

    # ---------------------------------------------------------- invocations

    @app.post("/webshield/invocations")
    def webshield_invocation(
        payload: dict,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        _check_payload_size(payload)
        session_id = _require_str(payload, "session_id")
        identity_key = _require_str(payload, "identity_key")
        phase = payload.get("phase") or "requested"

        def compute():
            if phase == "requested":
                result = webshield_store.record_invocation_request(
                    record["tenant_id"], session_id=session_id, identity_key=identity_key,
                    args=payload.get("args"), extension_version=payload.get("extension_version"),
                    sdk_version=payload.get("sdk_version"), enforcement_capable=bool(payload.get("enforcement_capable", True)),
                )
                enforcement = ((result.get("event") or {}).get("action") or {}).get("metadata", {}).get("requested_enforcement")
                if enforcement == "require_approval":
                    tool = webshield_store.get_tool_by_identity(record["tenant_id"], identity_key)
                    approval = webshield_store.create_approval(
                        record["tenant_id"], session_id=session_id, identity_key=identity_key,
                        tool_name=tool["tool_name"] if tool else identity_key,
                        owner_origin=tool["owner_origin"] if tool else "",
                        args=payload.get("args"), risk_score=result["risk_score"], risk_band=result["risk_band"],
                        reason="Policy requires approval for this invocation.",
                    )
                    result["approval"] = approval
                return result
            if phase == "completed":
                return webshield_store.record_invocation_completed(
                    record["tenant_id"], session_id=session_id, identity_key=identity_key,
                    status=payload.get("status", "success"), latency_ms=payload.get("latency_ms"), error=payload.get("error"),
                )
            raise HTTPException(status_code=400, detail="phase must be 'requested' or 'completed'")

        result = _idempotent(idempotency_key, compute, tenant_id=record["tenant_id"], principal=_principal(record), route="POST /webshield/invocations", body=payload)
        return _maybe_raise_block(result)

    # ---------------------------------------------------------- cross-origin

    @app.post("/webshield/cross-origin")
    def webshield_cross_origin(
        payload: dict,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ):
        """Record a single observed hop in a cross-origin data flow (e.g. "tool on
        origin A produced data that was passed to a tool on origin B"). This
        records one hop per call; reconstructing a full multi-hop chain across
        many tools/origins is not implemented — see docs/web-shield-limitations.md.
        """
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        _check_payload_size(payload)
        session_id = _require_str(payload, "session_id")
        from_origin = _require_str(payload, "from_origin")
        to_origin = _require_str(payload, "to_origin")

        def compute():
            return webshield_store.record_cross_origin_flow(
                record["tenant_id"], session_id=session_id, from_origin=from_origin, to_origin=to_origin,
                tool_name=payload.get("tool_name"), reason=payload.get("reason"),
            )

        result = _idempotent(idempotency_key, compute, tenant_id=record["tenant_id"], principal=_principal(record), route="POST /webshield/cross-origin", body=payload)
        return _maybe_raise_block(result)

    # --------------------------------------------------------------- outputs

    @app.post("/webshield/outputs")
    def webshield_output(
        payload: dict,
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        _check_payload_size(payload, max_bytes=400_000)
        session_id = _require_str(payload, "session_id")
        identity_key = _require_str(payload, "identity_key")
        output_text = payload.get("output_text") or ""
        if len(output_text) > 400_000:
            raise HTTPException(status_code=413, detail="output_text exceeds safe size limit")

        def compute():
            return webshield_store.scan_tool_output(
                record["tenant_id"], session_id=session_id, identity_key=identity_key, output_text=output_text,
                contains_user_generated_content=bool(payload.get("contains_user_generated_content", False)),
                enforcement_capable=bool(payload.get("enforcement_capable", True)),
            )

        result = _idempotent(idempotency_key, compute, tenant_id=record["tenant_id"], principal=_principal(record), route="POST /webshield/outputs", body=payload)
        if result.get("outcome") == "block":
            raise HTTPException(status_code=403, detail=result)
        return result

    # --------------------------------------------------------------- health

    @app.post("/webshield/extension/health")
    def webshield_extension_health(payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="ingest")
        _check_payload_size(payload)
        session_id = _require_str(payload, "session_id")
        return webshield_store.record_extension_health(
            record["tenant_id"], session_id=session_id,
            extension_version=payload.get("extension_version", "unknown"),
            connected=bool(payload.get("connected", True)),
            protection_mode=payload.get("protection_mode", "connected"),
            tab_id=payload.get("tab_id"), top_origin=payload.get("top_origin"),
        )

    @app.get("/webshield/config")
    def webshield_config(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "viewer", scope="read")
        return webshield_store.config(record["tenant_id"])

    # ------------------------------------------------------------- read model

    @app.get("/webshield/sessions")
    def webshield_list_sessions(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None), limit: int = 200):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return {"items": webshield_store.list_sessions(record["tenant_id"], limit=limit)}

    @app.get("/webshield/sessions/{session_id}")
    def webshield_session_detail(session_id: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="read")
        summary = webshield_store.session_summary(record["tenant_id"], session_id)
        if summary is None:
            raise HTTPException(status_code=404, detail="session not found")
        return summary

    @app.get("/webshield/tools")
    def webshield_list_tools(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None), limit: int = 200):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return {"items": webshield_store.list_tools(record["tenant_id"], limit=limit)}

    @app.get("/webshield/tools/detail")
    def webshield_tool_detail(identity_key: str, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="read")
        detail = webshield_store.tool_detail(record["tenant_id"], identity_key)
        if detail is None:
            raise HTTPException(status_code=404, detail="tool not found")
        return detail

    @app.get("/webshield/events")
    def webshield_list_events(
        x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None),
        session_id: str | None = None, identity_key: str | None = None, event_type: str | None = None,
        owner_origin: str | None = None, limit: int = 200,
    ):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return {"items": webshield_store.list_events(
            record["tenant_id"], session_id=session_id, identity_key=identity_key,
            event_type=event_type, owner_origin=owner_origin, limit=limit,
        )}

    @app.get("/webshield/overview")
    def webshield_overview(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return webshield_store.overview(record["tenant_id"])

    # -------------------------------------------------------------- approvals

    @app.get("/webshield/approvals")
    def webshield_list_approvals(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None), status: str | None = None, limit: int = 100):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return {"items": webshield_store.list_approvals(record["tenant_id"], status=status, limit=limit)}

    @app.post("/webshield/approvals/{request_id}/resolve")
    def webshield_resolve_approval(request_id: str, payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="write")
        decision = _require_str(payload, "decision")
        try:
            return webshield_store.resolve_approval(record["tenant_id"], request_id, decision, resolved_by=payload.get("resolved_by") or record.get("user_id"))
        except KeyError:
            raise HTTPException(status_code=404, detail="approval not found")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # ----------------------------------------------------------------- trust

    @app.get("/webshield/trust")
    def webshield_list_trust(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "analyst", scope="read")
        return {"items": webshield_store.list_trust(record["tenant_id"])}

    @app.post("/webshield/trust")
    def webshield_set_trust(payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin", scope="write")
        origin = _require_str(payload, "origin")
        state = payload.get("state")
        if state not in {"trusted", "blocked"}:
            raise HTTPException(status_code=400, detail="state must be 'trusted' or 'blocked'")
        return webshield_store.set_trust(record["tenant_id"], origin, state, created_by=payload.get("created_by") or record.get("user_id"), expires_at=payload.get("expires_at"))

    @app.post("/webshield/trust/remove")
    def webshield_remove_trust(payload: dict, x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)):
        record = require(x_api_key, authorization, "admin", scope="write")
        origin = _require_str(payload, "origin")
        removed = webshield_store.remove_trust(record["tenant_id"], origin)
        return {"removed": removed, "origin": origin}
