from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from varden_mcp._client import get_client

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
mcp = FastMCP(
    "varden",
    instructions=(
        "Tools for the Varden AI agent security control plane. "
        "Use varden_health to check connectivity before other calls."
    ),
)


def _http_error_message(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None:
        try:
            body = exc.response.text
        except Exception:
            body = ""
        return f"Varden HTTP error {exc.response.status_code}: {body or exc!s}"
    if isinstance(exc, httpx.ConnectError):
        return f"Varden unreachable (connection error): {exc!s}"
    return f"Varden request error ({type(exc).__name__}): {exc!s}"


def _json_response_body(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False)


def _status_from_decision(decision_action: str | None) -> str:
    text = str(decision_action or "").strip().lower()
    if text in {"block", "blocked"}:
        return "blocked"
    if text in {"warn", "warned"}:
        return "warned"
    if text == "monitor":
        return "monitor"
    return "allowed"


def _default_mcp_agent_name() -> str:
    return os.environ.get("VARDEN_MCP_AGENT_NAME", "mcp")


def _normalized_agent_token(name: object) -> str:
    return str(name or "").strip().lower().replace(" ", "_").replace("-", "_")


# Hosts often send placeholder agent names; treat like missing so the UI shows a stable MCP label.
_AGENT_NAME_PLACEHOLDERS = frozenset(
    {
        "unknown",
        "unknown_agent",
        "unknownagent",
        "anonymous",
        "default",
        "unnamed",
        "none",
        "null",
    }
)


def _needs_default_agent_name(name: object) -> bool:
    token = _normalized_agent_token(name)
    if not token:
        return True
    return token in _AGENT_NAME_PLACEHOLDERS


def _ensure_action_agent_name(action: dict[str, Any]) -> dict[str, Any]:
    """Set agent_name when missing or placeholder so dashboard agent scope and labels stay useful."""
    merged = dict(action)
    if _needs_default_agent_name(merged.get("agent_name")):
        merged["agent_name"] = _default_mcp_agent_name()
    return merged


@mcp.tool()
def varden_health() -> str:
    """Check whether the Varden control plane is reachable and return health/bootstrap info."""
    try:
        with get_client() as client:
            r = client.get("/health")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_events(limit: int = 20, offset: int = 0) -> str:
    """Return recent Varden decision events (allow / warn / block) with rules, classifiers, and trace IDs."""
    try:
        with get_client() as client:
            r = client.get("/events", params={"limit": limit, "offset": offset})
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_alerts() -> str:
    """Return active Varden alerts raised when policy thresholds are breached or behaviour is anomalous."""
    try:
        with get_client() as client:
            r = client.get("/alerts")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_dashboard() -> str:
    """Return the Varden dashboard overview: KPIs, event counts, classifier rates, and recent activity."""
    try:
        with get_client() as client:
            r = client.get("/dashboard/overview")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_policy() -> str:
    """Return the current active Varden policy (block, warn, monitor, and allow rule lists)."""
    try:
        with get_client() as client:
            r = client.get("/policy")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_validate_policy(policy: dict[str, Any]) -> str:
    """Validate a proposed Varden policy document without applying it; returns validation errors if malformed."""
    try:
        with get_client() as client:
            r = client.post("/policy/validate", json=policy)
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_put_policy(policy: dict[str, Any]) -> str:
    """Replace the active Varden policy immediately; validate first with varden_validate_policy."""
    try:
        with get_client() as client:
            r = client.put("/policy", json=policy)
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_policy_versions() -> str:
    """Return the policy version history to review recent policy changes before editing."""
    try:
        with get_client() as client:
            r = client.get("/policy/versions")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_guard(action: dict[str, Any]) -> str:
    """Submit an action for an allow/warn/block decision, persist it via /sdk/log, and return the decision (guard plus log in one step)."""
    try:
        action_payload = _ensure_action_agent_name(dict(action))
        guard_request = {"action": action_payload, "payload": action_payload.get("args") or {}}
        with get_client() as client:
            r = client.post("/sdk/guard", json=guard_request)
            try:
                data = r.json()
            except Exception:
                return r.text or f"Varden guard returned HTTP {r.status_code} with non-JSON body"

            if r.status_code == 403 and isinstance(data, dict) and isinstance(data.get("detail"), dict):
                guard_body = data["detail"]
            elif isinstance(data, dict):
                guard_body = data
            else:
                return _json_response_body(data)

            decision = guard_body.get("decision")
            action_out = guard_body.get("action")
            if not isinstance(decision, dict) or not isinstance(action_out, dict):
                return _json_response_body(data)

            action_for_log = _ensure_action_agent_name(dict(action_out))
            log_body = {
                "action": action_for_log,
                "decision": decision,
                "status": _status_from_decision(decision.get("action")),
                "input_payload": guard_request["payload"],
                "output_payload": {
                    "source": "varden_mcp",
                    "guard_event_id": guard_body.get("event_id"),
                },
            }
            log_result: Any
            try:
                lr = client.post("/sdk/log", json=log_body)
                lr.raise_for_status()
                try:
                    log_result = lr.json()
                except Exception:
                    log_result = lr.text
            except httpx.HTTPError as log_exc:
                log_result = {"log_failed": _http_error_message(log_exc)}

            return _json_response_body(
                {
                    "decision": decision,
                    "action": action_for_log,
                    "event_id": guard_body.get("event_id"),
                    "guard_http_status": r.status_code,
                    "log": log_result,
                }
            )
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_log_event(event: dict[str, Any]) -> str:
    """Log a completed action outcome to the Varden event store after execution (type, outcome, and context)."""
    try:
        if "action" in event:
            body = dict(event)
            body["action"] = _ensure_action_agent_name(dict(body.get("action") or {}))
        else:
            outcome = event.get("outcome", "allowed")
            decision_action = {"allowed": "allow", "warned": "warn", "blocked": "block"}.get(outcome, "allow")
            reserved = {
                "outcome",
                "decision",
                "status",
                "input_payload",
                "output_payload",
                "error",
            }
            action = _ensure_action_agent_name({k: v for k, v in event.items() if k not in reserved})
            body = {
                "action": action,
                "decision": event.get("decision") or {"action": decision_action, "reason": "mcp log"},
                "status": event.get("status") or outcome,
                "input_payload": event.get("input_payload"),
                "output_payload": event.get("output_payload"),
                "error": event.get("error"),
            }
        with get_client() as client:
            r = client.post("/sdk/log", json=body)
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_workflows() -> str:
    """Return configured Varden workflows that automate responses to policy events."""
    try:
        with get_client() as client:
            r = client.get("/workflows")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


@mcp.tool()
def varden_get_jobs() -> str:
    """Return recent Varden background jobs and their status."""
    try:
        with get_client() as client:
            r = client.get("/jobs")
            r.raise_for_status()
            return _json_response_body(r.json())
    except httpx.HTTPError as exc:
        return _http_error_message(exc)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
