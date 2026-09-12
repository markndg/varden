"""Immutable Predictive Authority event snapshots.

Historical truth at decision time — never mutates when live authority changes.
Secrets are redacted before persistence. Content hash is stamped into the
chained audit event so side-store blobs cannot silently disagree.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

from .resource import sanitize_identifier

SNAPSHOT_SCHEMA_VERSION = 1

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|authorization|private[_-]?key|credential_value)"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|authorization|credential|private[_-]?key)\s*[:=]\s*\S+"
)
SENTINEL_SECRET = "VARDEN_TEST_SECRET_DO_NOT_PERSIST"


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def redact_value(value: Any) -> Any:
    """Recursively redact secret-like material from snapshot payloads."""
    if isinstance(value, str):
        if SENTINEL_SECRET in value:
            return "[REDACTED]"
        text = sanitize_identifier(value, max_len=400)
        if SENTINEL_SECRET in text:
            return "[REDACTED]"
        if _SECRET_VALUE_RE.search(text):
            if "=" in text:
                left, sep, _ = text.partition("=")
                return f"{left}{sep}<redacted>"
            if ":" in text:
                left, sep, _ = text.partition(":")
                return f"{left}{sep}<redacted>"
            return "[REDACTED]"
        return text
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if _SECRET_KEY_RE.search(key):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact_value(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value


def snapshot_body_for_hash(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Fields included in integrity hash (excludes retrieval/integrity wrappers)."""
    skip = {"content_hash", "retrieved_at", "integrity", "event_id", "error"}
    return {k: v for k, v in snapshot.items() if k not in skip}


def snapshot_content_hash(snapshot: dict[str, Any]) -> str:
    """SHA-256 of canonical snapshot body (schema fields included, hash excluded)."""
    return hashlib.sha256(_stable_json(snapshot_body_for_hash(snapshot)).encode("utf-8")).hexdigest()


def build_historical_snapshot(
    *,
    result: Any,
    graph: dict[str, Any] | None,
    session_key: str | None = None,
    trace_id: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Build a versioned immutable snapshot from a PredictiveResult."""
    recommendation = result.recommendation.to_dict() if result.recommendation else None
    explanation = result.explanation.to_dict() if result.explanation else None
    delta = result.delta.to_dict() if result.delta else None
    findings = [f.to_dict() for f in (result.findings or [])]
    final = result.final_decision.action if result.final_decision else result.existing_decision
    pred_action = (recommendation or {}).get("action") if recommendation else None
    raw = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "timestamp": time.time(),
        "session_key": session_key,
        "trace_id": trace_id,
        "tenant_id": tenant_id,
        "mode": result.config.mode if result.config else None,
        "action_summary": result.facts.summary if result.facts else None,
        "existing_decision": result.existing_decision,
        "predictive_recommendation": pred_action,
        "recommendation": recommendation,
        "final_decision": final,
        "analysis_status": result.analysis_status,
        "analysis_incomplete_reason": result.analysis_incomplete_reason,
        "safe_conclusion": bool(
            result.analysis_status == "complete" and not result.findings and not result.error
        ),
        "before": result.before_snapshot,
        "after": result.after_snapshot,
        "delta": delta,
        "graph": graph or {"nodes": [], "edges": [], "truncated": False},
        "hazardous_paths": findings,
        "explanation": explanation,
        "budget": result.budget.to_dict() if result.budget else None,
        "error": result.error,
        "elapsed_ms": result.elapsed_ms,
        "enforcement_point": {
            "existing": result.existing_decision,
            "predictive": pred_action,
            "final": final,
            "mode": result.config.mode if result.config else None,
        },
    }
    snapshot = redact_value(raw)
    assert isinstance(snapshot, dict)
    snapshot["content_hash"] = snapshot_content_hash(snapshot)
    return snapshot


def historical_view_from_snapshot(snapshot: dict[str, Any], *, event_id: int | None = None) -> dict[str, Any]:
    """UI/API view model reconstructed solely from a durable snapshot."""
    integrity = snapshot.get("integrity") or "ok"
    rec = snapshot.get("recommendation")
    rec_action = None
    if isinstance(rec, dict):
        rec_action = rec.get("action")
    elif isinstance(rec, str):
        rec_action = rec
    rec_action = rec_action or snapshot.get("predictive_recommendation")

    view = {
        "event_id": event_id if event_id is not None else snapshot.get("event_id"),
        "historical": True,
        "live": False,
        "view_kind": "historical",
        "integrity": integrity,
        "schema_version": snapshot.get("schema_version", SNAPSHOT_SCHEMA_VERSION),
        "timestamp": snapshot.get("timestamp"),
        "session_key": snapshot.get("session_key"),
        "trace_id": snapshot.get("trace_id"),
        "tenant_id": snapshot.get("tenant_id"),
        "mode": snapshot.get("mode"),
        "action_summary": snapshot.get("action_summary"),
        "existing_decision": snapshot.get("existing_decision"),
        "recommendation": rec_action,
        "predictive_recommendation": rec_action,
        "final_decision": snapshot.get("final_decision"),
        "analysis_status": snapshot.get("analysis_status"),
        "analysis_incomplete_reason": snapshot.get("analysis_incomplete_reason"),
        "safe_conclusion": snapshot.get("safe_conclusion"),
        "before": snapshot.get("before"),
        "after": snapshot.get("after"),
        "delta": snapshot.get("delta"),
        "graph": snapshot.get("graph") or {"nodes": [], "edges": [], "truncated": False},
        "hazardous_paths": snapshot.get("hazardous_paths") or [],
        "explanation": snapshot.get("explanation"),
        "budget": snapshot.get("budget"),
        "error": snapshot.get("error"),
        "elapsed_ms": snapshot.get("elapsed_ms"),
        "enforcement_point": snapshot.get("enforcement_point"),
        "content_hash": snapshot.get("content_hash"),
        "observed_vs_predicted": {
            "before_is_observed": True,
            "after_is_predicted_or_committed": True,
            "warning": "Predicted authority must not be read as an action that already occurred.",
        },
    }
    if integrity != "ok":
        view["trusted"] = False
        view["error"] = snapshot.get("error") or "Predictive snapshot integrity verification failed."
    else:
        view["trusted"] = True
    return view


def assert_no_sentinel(payload: Any, sentinel: str = SENTINEL_SECRET) -> None:
    blob = _stable_json(payload)
    if sentinel in blob:
        raise AssertionError("sentinel secret leaked into predictive snapshot")
