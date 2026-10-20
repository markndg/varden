"""Durable Predictive snapshot store bound to audit event_id.

Retention follows the events table: snapshots share the same SQLite database
and are removed when operators delete the corresponding event rows (or the DB).
Snapshots are integrity-bound via content_hash stamped into chained event metadata.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ..db import connect, init_db
from ..redaction import redact, sensitive_key, value_label
from .snapshot import (
    HISTORICAL_SCHEMA_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
    canonical_snapshot_bytes,
    snapshot_content_hash,
)


def _already_redacted(value: Any) -> bool:
    return isinstance(value, str) and (
        value == "[REDACTED]" or value.startswith("[REDACTED:") or value.endswith("<redacted>")
    )


def _contains_plaintext_secret(value: Any, depth: int = 0) -> bool:
    if depth > 32:
        return False
    if isinstance(value, dict):
        for key, item in value.items():
            if sensitive_key(str(key)) and not _already_redacted(item):
                return True
            if _contains_plaintext_secret(item, depth + 1):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_plaintext_secret(item, depth + 1) for item in value)
    if isinstance(value, str) and not _already_redacted(value):
        return value_label(value) is not None
    return False


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
        schema_version = int(payload.get("schema_version") or SNAPSHOT_SCHEMA_VERSION)
        payload["schema_version"] = schema_version
        if schema_version >= SNAPSHOT_SCHEMA_VERSION:
            blob = canonical_snapshot_bytes(payload).decode("utf-8")
            digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
            supplied = content_hash or str(payload.get("content_hash") or "")
            if supplied and supplied != digest:
                raise ValueError("snapshot content_hash does not match canonical body")
        else:
            digest = content_hash or str(payload.get("content_hash") or "") or snapshot_content_hash(payload)
            payload["content_hash"] = digest
            blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
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
                    schema_version,
                    digest,
                    blob,
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
        schema_version = int(row["schema_version"] or snapshot.get("schema_version") or HISTORICAL_SCHEMA_VERSION)
        if schema_version >= SNAPSHOT_SCHEMA_VERSION:
            recomputed = hashlib.sha256(str(row["snapshot_json"]).encode("utf-8")).hexdigest()
            ok = bool(stored_hash) and stored_hash == recomputed
        else:
            recomputed = snapshot_content_hash(snapshot)
            embedded = str(snapshot.get("content_hash") or "")
            ok = bool(stored_hash) and stored_hash == recomputed and (not embedded or embedded == stored_hash)

        display = dict(snapshot)
        redaction_status = "current"
        if ok and _contains_plaintext_secret(snapshot):
            projected = redact(snapshot, tenant_id=str(tenant_id or snapshot.get("tenant_id") or "default"))
            if isinstance(projected, dict):
                display = projected
            display["redaction_status"] = "historical_plaintext_withheld"
            redaction_status = "historical_plaintext_withheld"
        display["content_hash"] = stored_hash
        out = dict(display)
        out["event_id"] = int(event_id)
        out["retrieved_at"] = time.time()
        out["integrity"] = "ok" if ok else "failed"
        out["trusted"] = bool(ok)
        out["schema_version"] = schema_version
        out["redaction_status"] = redaction_status
        if not ok:
            out["error"] = "snapshot content hash mismatch"
        return out

    def migration_links(self, event_id: int, *, original_hash: str, replacement_hash: str) -> bool:
        with connect(self.db_path) as conn:
            self._ensure_migration_table(conn)
            row = conn.execute(
                """
                SELECT 1 FROM predictive_snapshot_migrations
                WHERE event_id = ? AND original_hash = ? AND replacement_hash = ?
                """,
                (int(event_id), original_hash, replacement_hash),
            ).fetchone()
        return row is not None

    def migrate_plaintext(self, *, tenant_id: str | None = None) -> dict[str, int]:
        """Replace verified plaintext snapshots with a redacted body.

        The audit event's original hash is kept in ``predictive_snapshot_migrations``.
        This does not erase SQLite free pages or backups.
        """
        migrated = 0
        skipped = 0
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._ensure_migration_table(conn)
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM predictive_snapshots WHERE tenant_id IS NULL OR tenant_id = ?",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM predictive_snapshots").fetchall()
            for row in rows:
                try:
                    snapshot = json.loads(row["snapshot_json"])
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                if not isinstance(snapshot, dict):
                    skipped += 1
                    continue
                schema_version = int(row["schema_version"] or 1)
                stored_hash = str(row["content_hash"] or "")
                if schema_version >= SNAPSHOT_SCHEMA_VERSION:
                    recomputed = hashlib.sha256(str(row["snapshot_json"]).encode("utf-8")).hexdigest()
                else:
                    recomputed = snapshot_content_hash(snapshot)
                if recomputed != stored_hash or not _contains_plaintext_secret(snapshot):
                    skipped += 1
                    continue
                projected = redact(snapshot, tenant_id=str(row["tenant_id"] or tenant_id or "default"))
                if not isinstance(projected, dict):
                    skipped += 1
                    continue
                projected.pop("content_hash", None)
                projected["schema_version"] = SNAPSHOT_SCHEMA_VERSION
                blob = canonical_snapshot_bytes(projected).decode("utf-8")
                digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
                projected["content_hash"] = digest
                conn.execute(
                    """
                    UPDATE predictive_snapshots
                    SET snapshot_json = ?, content_hash = ?, schema_version = ?
                    WHERE event_id = ?
                    """,
                    (blob, digest, SNAPSHOT_SCHEMA_VERSION, int(row["event_id"])),
                )
                conn.execute(
                    """
                    INSERT INTO predictive_snapshot_migrations(
                      event_id, original_hash, replacement_hash, migrated_at, note
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        int(row["event_id"]),
                        stored_hash,
                        digest,
                        time.time(),
                        "redacted replacement; original hash remains the audit commitment; free pages may retain plaintext",
                    ),
                )
                migrated += 1
            conn.commit()
        return {"migrated": migrated, "skipped": skipped}

    @staticmethod
    def _ensure_migration_table(conn: Any) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS predictive_snapshot_migrations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id INTEGER NOT NULL,
              original_hash TEXT NOT NULL,
              replacement_hash TEXT NOT NULL,
              migrated_at REAL NOT NULL,
              note TEXT NOT NULL
            )
            """
        )

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
