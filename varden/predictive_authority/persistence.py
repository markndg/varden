"""Load historical Predictive views from durable audit + snapshot store."""

from __future__ import annotations

from typing import Any

from .snapshot import historical_view_from_snapshot
from .snapshot_store import PredictiveSnapshotStore
from .views import safe_label


def _sanitize_graph(graph: dict[str, Any] | None) -> dict[str, Any]:
    g = dict(graph or {"nodes": [], "edges": [], "truncated": False})
    for n in g.get("nodes") or []:
        if isinstance(n, dict) and "label" in n:
            n["label"] = safe_label(n.get("label"))
    for e in g.get("edges") or []:
        if isinstance(e, dict) and "label" in e:
            e["label"] = safe_label(e.get("label"))
    return g


def load_historical_predictive_event(
    *,
    event_store: Any,
    db_path: str,
    event_id: int,
    tenant_id: str | None,
) -> dict[str, Any]:
    """Reconstruct historical PA view from durable storage (no process registry).

    Returns a view dict. Callers should inspect ``availability`` /
    ``integrity`` / ``trusted`` rather than assuming success.
    """
    row = event_store.get_event(event_id, tenant_id=tenant_id) if event_store is not None else None
    if not row:
        return {
            "event_id": int(event_id),
            "availability": "missing_event",
            "trusted": False,
            "historical": True,
            "live": False,
            "error": "Predictive analysis is not available for this event.",
            "message": "Predictive analysis is not available for this event.",
        }

    action = row.get("action") or {}
    meta = (action.get("metadata") or {}).get("predictive_authority") or {}
    expected_hash = meta.get("snapshot_content_hash") if isinstance(meta, dict) else None
    has_pa = bool(isinstance(meta, dict) and meta)

    store = PredictiveSnapshotStore(db_path)
    snapshot = store.get(int(event_id), tenant_id=tenant_id)

    if snapshot is None:
        if has_pa and expected_hash:
            return {
                "event_id": int(event_id),
                "availability": "snapshot_removed",
                "trusted": False,
                "historical": True,
                "live": False,
                "predictive_metadata": meta,
                "error": "Predictive snapshot is no longer available.",
                "message": "Predictive snapshot is no longer available.",
                "decision": (row.get("decision") or {}).get("action"),
                "status": row.get("status"),
                "trace_id": row.get("trace_id") or action.get("trace_id"),
            }
        if has_pa:
            # Legacy PA metadata without durable snapshot — honest, no fake graph.
            return {
                "event_id": int(event_id),
                "availability": "metadata_only",
                "trusted": False,
                "historical": True,
                "live": False,
                "predictive": meta,
                "error": "Predictive analysis is not available for this event.",
                "message": "Predictive analysis is not available for this event.",
                "decision": (row.get("decision") or {}).get("action"),
                "status": row.get("status"),
                "trace_id": row.get("trace_id") or action.get("trace_id"),
            }
        return {
            "event_id": int(event_id),
            "availability": "no_predictive",
            "trusted": False,
            "historical": True,
            "live": False,
            "error": "Predictive analysis is not available for this event.",
            "message": "Predictive analysis is not available for this event.",
            "decision": (row.get("decision") or {}).get("action"),
            "status": row.get("status"),
            "trace_id": row.get("trace_id") or action.get("trace_id"),
        }

    if snapshot.get("integrity") in {"malformed", "failed"}:
        return {
            "event_id": int(event_id),
            "availability": "integrity_failed",
            "trusted": False,
            "historical": True,
            "live": False,
            "integrity": snapshot.get("integrity"),
            "error": "Predictive snapshot integrity verification failed.",
            "message": "Predictive snapshot integrity verification failed.",
            "decision": (row.get("decision") or {}).get("action"),
            "status": row.get("status"),
            "trace_id": row.get("trace_id") or action.get("trace_id"),
        }

    stored_hash = str(snapshot.get("content_hash") or "")
    if expected_hash and stored_hash and str(expected_hash) != stored_hash:
        return {
            "event_id": int(event_id),
            "availability": "integrity_failed",
            "trusted": False,
            "historical": True,
            "live": False,
            "integrity": "failed",
            "error": "Predictive snapshot integrity verification failed.",
            "message": "Predictive snapshot integrity verification failed.",
            "decision": (row.get("decision") or {}).get("action"),
            "status": row.get("status"),
            "trace_id": row.get("trace_id") or action.get("trace_id"),
        }

    view = historical_view_from_snapshot(snapshot, event_id=int(event_id))
    view["graph"] = _sanitize_graph(view.get("graph") if isinstance(view.get("graph"), dict) else None)
    view["availability"] = "ok"
    view["decision"] = (row.get("decision") or {}).get("action") or view.get("final_decision")
    view["status"] = row.get("status")
    view["audit_event"] = {
        "id": row.get("id"),
        "timestamp": row.get("timestamp"),
        "status": row.get("status"),
        "tool": action.get("tool"),
        "trace_id": row.get("trace_id") or action.get("trace_id"),
    }
    return view


def persist_predictive_snapshot(
    *,
    db_path: str,
    event_id: int,
    action: Any,
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Persist pending snapshot from action side-channel after audit log."""
    snapshot = getattr(action, "_varden_pa_snapshot", None)
    if not isinstance(snapshot, dict) or not snapshot:
        # Fallback: metadata may include hash but no full blob to persist.
        return None
    meta = ((getattr(action, "metadata", None) or {}) if action is not None else {}) or {}
    pa = meta.get("predictive_authority") if isinstance(meta, dict) else None
    expected = (pa or {}).get("snapshot_content_hash") if isinstance(pa, dict) else None
    content_hash = expected or snapshot.get("content_hash")
    store = PredictiveSnapshotStore(db_path)
    tid = tenant_id or getattr(action, "tenant_id", None)
    return store.save(
        event_id=int(event_id),
        tenant_id=str(tid) if tid is not None else None,
        snapshot=snapshot,
        content_hash=str(content_hash) if content_hash else None,
    )
