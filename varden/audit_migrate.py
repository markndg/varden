"""Rewrite historical audit rows so plaintext secrets leave the logical record.

The hash chain is rebuilt from the first rewritten row. A signed manifest
links the original chain head to the replacement head and records that
history was rewritten.

This does not erase secrets from SQLite WAL files, rollback journals,
free pages, backups, or filesystem snapshots. Logical row replacement is
not secure deletion.
"""

from __future__ import annotations

import json
from typing import Any

from varden.audit_integrity import GENESIS_PREV_HASH, compute_event_hash
from varden.db import connect
from varden.key_derivation import PURPOSE_AUDIT_MIGRATION, purpose_hmac
from varden.redaction import redact

REMANENCE_NOTE = (
    "Logical event rows were rewritten and the hash chain was rebuilt. "
    "SQLite WAL files, rollback journals, free pages, backups and "
    "filesystem snapshots may still contain the previous plaintext. "
    "This command does not provide secure erasure."
)


def _loads(text: str | None, default: Any) -> Any:
    if text is None or text == "":
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _changed(before: Any, after: Any) -> bool:
    return json.dumps(before, sort_keys=True, default=str) != json.dumps(after, sort_keys=True, default=str)


def redact_migrate(db_path: str, *, master_secret: str) -> dict[str, Any]:
    if not master_secret or len(master_secret) < 16:
        raise ValueError("a signing secret of at least 16 characters is required")
    with connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
            original_head = rows[-1]["event_hash"] if rows else None
            affected = 0
            prev: str | None = None
            updates: list[tuple] = []
            for row in rows:
                tenant = str(row["tenant_id"] or "default")
                action = redact(_loads(row["action_json"], {}), tenant_id=tenant, master_secret=master_secret)
                decision = redact(_loads(row["decision_json"], {}), tenant_id=tenant, master_secret=master_secret)
                input_payload = redact(_loads(row["input_payload_json"], None), tenant_id=tenant, master_secret=master_secret)
                output_payload = redact(_loads(row["output_payload_json"], None), tenant_id=tenant, master_secret=master_secret)
                error_raw = row["error"]
                error = redact(error_raw, tenant_id=tenant, master_secret=master_secret) if error_raw else error_raw
                if any(
                    _changed(before, after)
                    for before, after in (
                        (_loads(row["action_json"], {}), action),
                        (_loads(row["decision_json"], {}), decision),
                        (_loads(row["input_payload_json"], None), input_payload),
                        (_loads(row["output_payload_json"], None), output_payload),
                        (error_raw, error),
                    )
                ):
                    affected += 1
                hash_event = {
                    "timestamp": row["timestamp"],
                    "action": action,
                    "decision": decision,
                    "status": row["status"],
                    "input_payload": input_payload,
                    "output_payload": output_payload,
                    "error": error,
                    "replayable": bool(row["replayable"]),
                    "replay_key": row["replay_key"],
                    "workflow_id": row["workflow_id"],
                    "agent_name": row["agent_name"],
                    "parent_event_id": row["parent_event_id"],
                    "trace_id": row["trace_id"],
                    "tenant_id": row["tenant_id"],
                }
                event_hash = compute_event_hash(hash_event, prev)
                stored_prev = prev if prev is not None else GENESIS_PREV_HASH
                updates.append(
                    (
                        json.dumps(action, ensure_ascii=False),
                        json.dumps(decision, ensure_ascii=False),
                        json.dumps(input_payload, ensure_ascii=False),
                        json.dumps(output_payload, ensure_ascii=False),
                        error,
                        event_hash,
                        stored_prev,
                        row["id"],
                    )
                )
                prev = event_hash
            for item in updates:
                conn.execute(
                    """UPDATE events SET action_json=?, decision_json=?, input_payload_json=?,
                       output_payload_json=?, error=?, event_hash=?, prev_hash=? WHERE id=?""",
                    item,
                )
            replacement_head = prev
            manifest = {
                "kind": "redact-migrate",
                "rewritten": True,
                "affected_records": affected,
                "original_head": original_head,
                "replacement_head": replacement_head,
                "remanence": REMANENCE_NOTE,
            }
            payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
            signature = purpose_hmac(master_secret, PURPOSE_AUDIT_MIGRATION, payload.encode("utf-8"))
            conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_migration_manifests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    signature TEXT NOT NULL
                )"""
            )
            conn.execute(
                "INSERT INTO audit_migration_manifests(created_at, payload_json, signature) VALUES (strftime('%s','now'), ?, ?)",
                (payload, signature),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return {**manifest, "signature": signature}


def verify_manifest(db_path: str, *, master_secret: str) -> bool:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT payload_json, signature FROM audit_migration_manifests ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return False
    expected = purpose_hmac(master_secret, PURPOSE_AUDIT_MIGRATION, row["payload_json"].encode("utf-8"))
    return expected == row["signature"]
