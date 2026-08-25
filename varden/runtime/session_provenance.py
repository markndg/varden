"""Control-plane session provenance — survives host/model and cross-gateway boundaries.

Gateway processes are per-server. Causal continuity for MCP A → agent → MCP B
is preserved by storing observed sources under (tenant_id, trace_id) on the
control plane. Gateways and the host adapter merge this list into every guard.
"""

from __future__ import annotations

import json
import time
from typing import Any

from varden.db import connect, init_db


class SessionProvenanceStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def append(
        self,
        *,
        tenant_id: str,
        trace_id: str,
        source: dict[str, Any],
        session_id: str | None = None,
    ) -> None:
        if not trace_id:
            raise ValueError("trace_id required")
        # Never accept client-asserted trusted/delegated.
        trust = str(source.get("trust_level") or "untrusted")
        if trust in {"trusted", "delegated"}:
            trust = "unknown"
        entry = {
            "source_type": source.get("source_type") or "unknown",
            "origin": source.get("origin") or "unknown",
            "principal": source.get("principal") or "",
            "trust_level": trust,
            "integrity": "unverified",
            "metadata": source.get("metadata") or {},
            "observed_at": time.time(),
        }
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO runtime_session_provenance(
                  tenant_id, trace_id, session_id, created_at, source_json
                ) VALUES (?,?,?,?,?)
                """,
                (tenant_id, trace_id, session_id, time.time(), json.dumps(entry, default=str)),
            )
            conn.commit()

    def list_sources(self, *, tenant_id: str, trace_id: str, limit: int = 200) -> list[dict[str, Any]]:
        if not trace_id:
            return []
        with connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT source_json FROM runtime_session_provenance
                WHERE tenant_id=? AND trace_id=?
                ORDER BY id ASC LIMIT ?
                """,
                (tenant_id, trace_id, limit),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                out.append(json.loads(row["source_json"]))
            except Exception:
                continue
        return out
