"""Persisted runtime sessions and coverage attestations."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from varden.db import connect, init_db


class RuntimeCoverageStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def save_attestation(self, tenant_id: str, attestation: dict[str, Any]) -> str:
        attestation_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO runtime_coverage_attestations(
                  attestation_id, tenant_id, session_id, mode, fail_mode, created_at, payload_json
                ) VALUES (?,?,?,?,?,?,?)
                """,
                (
                    attestation_id,
                    tenant_id,
                    attestation.get("session_id"),
                    attestation.get("mode"),
                    attestation.get("fail_mode"),
                    time.time(),
                    json.dumps(
                        {
                            "categories": attestation.get("categories"),
                            "strict_readiness": attestation.get("strict_readiness"),
                            "known_bypass_surfaces": [
                                {"name": s.get("name"), "status": s.get("status")}
                                for s in (attestation.get("known_bypass_surfaces") or [])
                            ],
                        },
                        default=str,
                    ),
                ),
            )
            conn.commit()
        return attestation_id

    def list_attestations(self, tenant_id: str, *, limit: int = 10) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT attestation_id, tenant_id, session_id, mode, fail_mode, created_at, payload_json
                FROM runtime_coverage_attestations
                WHERE tenant_id=?
                ORDER BY created_at DESC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["payload"] = json.loads(item.pop("payload_json") or "{}")
            except Exception:
                item["payload"] = {}
            out.append(item)
        return out

    def save_session(self, tenant_id: str, *, mode: str, fail_mode: str, metadata: dict[str, Any] | None = None) -> str:
        session_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO runtime_sessions(session_id, tenant_id, mode, fail_mode, created_at, metadata_json)
                VALUES (?,?,?,?,?,?)
                """,
                (session_id, tenant_id, mode, fail_mode, time.time(), json.dumps(metadata or {}, default=str)),
            )
            conn.commit()
        return session_id
