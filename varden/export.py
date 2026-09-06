from __future__ import annotations
import csv, json, hashlib
from pathlib import Path

from .audit_integrity import verify_event_chain


class EvidenceExporter:
    def __init__(self, event_store):
        self.event_store = event_store

    def export_events_csv(self, path: str, tenant_id: str | None = None, limit: int = 500):
        rows = self.event_store.list_events(limit=limit, tenant_id=tenant_id)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["id", "timestamp", "status", "workflow_id", "agent_name", "tenant_id", "event_hash", "prev_hash"],
            )
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k) for k in writer.fieldnames})
        return str(p)

    def export_bundle(self, path: str, tenant_id: str | None = None, limit: int = 500):
        payload = {
            "events": self.event_store.list_events(limit=limit, tenant_id=tenant_id),
            "alerts": self.event_store.list_alerts(limit=limit, tenant_id=tenant_id),
            "metrics": self.event_store.metrics(tenant_id=tenant_id),
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"bundle": payload, "sha256": digest}, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"path": str(p), "sha256": digest}

    def verify_chain(self, tenant_id: str | None = None, limit: int | None = None):
        """Verify the persistent event hash chain (write/verify parity)."""
        if hasattr(self.event_store, "verify_integrity"):
            return self.event_store.verify_integrity(tenant_id=tenant_id, limit=limit)
        events = list(reversed(self.event_store.list_events(limit=limit or 1000, tenant_id=tenant_id)))
        return verify_event_chain(events)
