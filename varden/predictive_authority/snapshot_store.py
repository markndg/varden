"""Durable Predictive snapshot store bound to audit event_id.

Retention follows the events table: snapshots share the same SQLite database
and are removed when operators delete the corresponding event rows (or the DB).
Snapshots are integrity-bound via content_hash stamped into chained event metadata.
"""

from __future__ import annotations

import json
import time
from typing import Any

from ..db import connect, init_db
from .snapshot import SNAPSHOT_SCHEMA_VERSION, snapshot_content_hash


class PredictiveSnapshotStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def save(
        self,
        *,
        event_id: int,
        tenant_id: str | None,
        snapshot: dict[str, Any],
        content_hash: str | None = None,
    ) -> dict[str, Any]:
        payload = dict(snapshot)
        digest = content_hash or str(payload.get("content_hash") or "") or snapshot_content_hash(payload)
        payload["content_hash"] = digest
        payload.setdefault("schema_version", SNAPSHOT_SCHEMA_VERSION)
        now = time.time()
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO predictive_snapshots(
                  event_id, tenant_id, created_at, schema_version, content_hash, snapshot_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                  tenant_id=excluded.tenant_id,
                  created_at=excluded.created_at,
                  schema_version=excluded.schema_version,
                  content_hash=excluded.content_hash,
                  snapshot_json=excluded.snapshot_json
                """,
                (
                    int(event_id),
                    tenant_id,
                    now,
                    int(payload.get("schema_version") or SNAPSHOT_SCHEMA_VERSION),
                    digest,
                    json.dumps(payload, ensure_ascii=False, default=str),
                ),
            )
            conn.commit()
        return {
            "event_id": int(event_id),
            "content_hash": digest,
            "schema_version": payload.get("schema_version"),
        }

    def get(self, event_id: int, *, tenant_id: str | None = None) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            if tenant_id:
                row = conn.execute(
                    """
                    SELECT * FROM predictive_snapshots
                    WHERE event_id = ? AND (tenant_id IS NULL OR tenant_id = ?)
                    """,
                    (int(event_id), tenant_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM predictive_snapshots WHERE event_id = ?",
                    (int(event_id),),
                ).fetchone()
        if not row:
            return None
        try:
            snapshot = json.loads(row["snapshot_json"])
        except json.JSONDecodeError:
            return {
                "event_id": int(event_id),
                "integrity": "malformed",
                "error": "corrupt snapshot_json",
                "schema_version": row["schema_version"],
                "content_hash": row["content_hash"],
                "trusted": False,
            }
        if not isinstance(snapshot, dict):
            return {
                "event_id": int(event_id),
                "integrity": "malformed",
                "error": "snapshot is not an object",
                "content_hash": row["content_hash"],
                "trusted": False,
            }

        stored_hash = str(row["content_hash"] or "")
        recomputed = snapshot_content_hash(snapshot)
        embedded = str(snapshot.get("content_hash") or "")
        ok = bool(stored_hash) and stored_hash == recomputed and (not embedded or embedded == stored_hash)

        out = dict(snapshot)
        out["event_id"] = int(event_id)
        out["retrieved_at"] = time.time()
        out["integrity"] = "ok" if ok else "failed"
        out["trusted"] = bool(ok)
        if not ok:
            out["error"] = "snapshot content hash mismatch"
        return out

    def delete(self, event_id: int) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM predictive_snapshots WHERE event_id = ?", (int(event_id),))
            conn.commit()

    def exists(self, event_id: int, *, tenant_id: str | None = None) -> bool:
        with connect(self.db_path) as conn:
            if tenant_id:
                row = conn.execute(
                    """
                    SELECT 1 FROM predictive_snapshots
                    WHERE event_id = ? AND (tenant_id IS NULL OR tenant_id = ?)
                    """,
                    (int(event_id), tenant_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT 1 FROM predictive_snapshots WHERE event_id = ?",
                    (int(event_id),),
                ).fetchone()
        return row is not None
