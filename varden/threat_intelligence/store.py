"""SQLite persistence for threat intelligence.

Raw feeds are not stored. Rows keep bounded normalised records, hashes,
cursors, assessments, candidates, replays, and an append-only audit trail.
Schema version is recorded so later migrations have a place to start.
"""

from __future__ import annotations

import json
import time
from typing import Any

from varden.db import connect, init_db

from . import SCHEMA_VERSION

_MAPPED_SQL = (
    "json_extract(item_json, '$.contract.id') IS NOT NULL "
    "AND json_extract(item_json, '$.contract.id') != ''"
)
_ACTIONABLE_SQL = (
    "json_extract(item_json, '$.candidate.possible') = 1 "
    "OR lifecycle IN ('APPROVED', 'OBSERVE', 'ENFORCED')"
)
_ITEM_SORTS = {
    "priority": (
        "CASE "
        "WHEN lifecycle = 'AWAITING_APPROVAL' AND json_extract(item_json, '$.candidate.possible') = 1 THEN 0 "
        "WHEN json_extract(item_json, '$.candidate.possible') = 1 THEN 1 "
        "WHEN applicability = 'EXPOSED' THEN 2 "
        "WHEN json_extract(item_json, '$.contract.id') IS NOT NULL "
        " AND json_extract(item_json, '$.contract.id') != '' THEN 3 "
        "ELSE 4 END"
    ),
    "updated_at": "updated_at",
    "title": "lower(COALESCE(json_extract(item_json, '$.title'), source_id))",
    "source_id": "source_id",
    "severity": "severity",
    "applicability": "applicability",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ti_schema (
  version INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS ti_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ti_sources (
  source_id TEXT PRIMARY KEY,
  state_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ti_items (
  item_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  severity TEXT,
  published_at REAL,
  lifecycle TEXT NOT NULL,
  applicability TEXT,
  baseline INTEGER NOT NULL DEFAULT 0,
  item_json TEXT NOT NULL,
  updated_at REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ti_source_record ON ti_items(source, source_id);
CREATE INDEX IF NOT EXISTS idx_ti_items_updated ON ti_items(updated_at);
CREATE TABLE IF NOT EXISTS ti_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at REAL NOT NULL,
  item_id TEXT,
  kind TEXT NOT NULL,
  actor TEXT,
  previous_state TEXT,
  new_state TEXT,
  detail_json TEXT NOT NULL
);
"""


class ThreatIntelStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        init_db(db_path)
        with connect(db_path) as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM ti_schema ORDER BY version DESC LIMIT 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO ti_schema(version) VALUES (?)", (SCHEMA_VERSION,))
            elif int(row["version"]) > SCHEMA_VERSION:
                raise RuntimeError(f"threat intelligence schema {row['version']} is newer than this build")
            elif int(row["version"]) < SCHEMA_VERSION:
                conn.execute("INSERT INTO ti_schema(version) VALUES (?)", (SCHEMA_VERSION,))

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT value FROM ti_meta WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO ti_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def save_source(self, source_id: str, state: dict[str, Any]) -> None:
        payload = json.dumps(state, sort_keys=True, default=str)
        with connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO ti_sources(source_id, state_json) VALUES (?, ?) "
                "ON CONFLICT(source_id) DO UPDATE SET state_json = excluded.state_json",
                (source_id, payload),
            )

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT state_json FROM ti_sources WHERE source_id = ?", (source_id,)).fetchone()
            return json.loads(row["state_json"]) if row else None

    def list_sources(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute("SELECT state_json FROM ti_sources ORDER BY source_id").fetchall()
            return [json.loads(row["state_json"]) for row in rows]

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT item_json FROM ti_items WHERE item_id = ?", (item_id,)).fetchone()
            return json.loads(row["item_json"]) if row else None

    def get_by_source(self, source: str, source_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT item_json FROM ti_items WHERE source = ? AND source_id = ?",
                (source, source_id),
            ).fetchone()
            return json.loads(row["item_json"]) if row else None

    def save_item(self, doc: dict[str, Any]) -> None:
        payload = json.dumps(doc, sort_keys=True, default=str)
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO ti_items(item_id, source, source_id, content_hash, severity, published_at, lifecycle, applicability, baseline, item_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(item_id) DO UPDATE SET
                  content_hash = excluded.content_hash,
                  severity = excluded.severity,
                  published_at = excluded.published_at,
                  lifecycle = excluded.lifecycle,
                  applicability = excluded.applicability,
                  baseline = excluded.baseline,
                  item_json = excluded.item_json,
                  updated_at = excluded.updated_at
                """,
                (
                    doc["id"],
                    doc.get("source"),
                    doc.get("source_id"),
                    doc.get("raw_content_hash") or "",
                    doc.get("severity"),
                    doc.get("published_at"),
                    doc.get("lifecycle") or "DISCOVERED",
                    doc.get("applicability"),
                    1 if doc.get("baseline") else 0,
                    payload,
                    float(doc.get("updated_at") or time.time()),
                ),
            )

    def list_items(
        self,
        *,
        source: str | None = None,
        severity: str | None = None,
        lifecycle: str | None = None,
        applicability: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 200,
        offset: int = 0,
        query: str | None = None,
        mapping: str | None = None,
        actionable: bool = False,
        surface: str | None = None,
        sort: str = "updated_at",
        order: str = "desc",
    ) -> list[dict[str, Any]]:
        page = self.query_items(
            source=source,
            severity=severity,
            lifecycle=lifecycle,
            applicability=applicability,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
            query=query,
            mapping=mapping,
            actionable=actionable,
            surface=surface,
            sort=sort,
            order=order,
        )
        return page["items"]

    def query_items(
        self,
        *,
        source: str | None = None,
        severity: str | None = None,
        lifecycle: str | None = None,
        applicability: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 200,
        offset: int = 0,
        query: str | None = None,
        mapping: str | None = None,
        actionable: bool = False,
        surface: str | None = None,
        sort: str = "updated_at",
        order: str = "desc",
    ) -> dict[str, Any]:
        clauses, params = _item_filters(
            source=source,
            severity=severity,
            lifecycle=lifecycle,
            applicability=applicability,
            since=since,
            until=until,
            query=query,
            mapping=mapping,
            actionable=actionable,
            surface=surface,
        )
        where = " AND ".join(clauses)
        sort_sql = _ITEM_SORTS.get(sort, _ITEM_SORTS["priority"])
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        bounded_limit = min(max(int(limit), 1), 500)
        bounded_offset = min(max(int(offset), 0), 100_000)
        with connect(self.db_path) as conn:
            total = int(conn.execute(f"SELECT COUNT(*) AS n FROM ti_items WHERE {where}", params).fetchone()["n"])
            rows = conn.execute(
                f"SELECT item_json FROM ti_items WHERE {where} ORDER BY {sort_sql} {direction}, item_id ASC LIMIT ? OFFSET ?",
                [*params, bounded_limit, bounded_offset],
            ).fetchall()
        return {
            "items": [json.loads(row["item_json"]) for row in rows],
            "total": total,
            "offset": bounded_offset,
            "limit": bounded_limit,
        }

    def inventory(self) -> dict[str, int]:
        mapped = _MAPPED_SQL
        with connect(self.db_path) as conn:
            row = conn.execute(
                f"""
                SELECT
                  COUNT(*) AS total,
                  SUM(CASE WHEN {mapped} THEN 1 ELSE 0 END) AS mapped,
                  SUM(CASE WHEN applicability = 'PROTECTED' THEN 1 ELSE 0 END) AS protected,
                  SUM(CASE WHEN applicability = 'EXPOSED' THEN 1 ELSE 0 END) AS exposed,
                  SUM(CASE WHEN applicability = 'REVIEW' THEN 1 ELSE 0 END) AS review,
                  SUM(CASE WHEN applicability = 'NOT_APPLICABLE' THEN 1 ELSE 0 END) AS not_applicable,
                  SUM(CASE WHEN {mapped} AND applicability = 'NOT_APPLICABLE' THEN 1 ELSE 0 END) AS mapped_not_applicable,
                  SUM(CASE WHEN {mapped} AND applicability = 'EXPOSED' THEN 1 ELSE 0 END) AS mapped_exposed,
                  SUM(CASE WHEN {mapped} AND applicability = 'REVIEW' THEN 1 ELSE 0 END) AS mapped_review,
                  SUM(CASE WHEN json_extract(item_json, '$.candidate.possible') = 1
                            AND lifecycle = 'AWAITING_APPROVAL' THEN 1 ELSE 0 END) AS candidates_awaiting,
                  SUM(CASE WHEN {_ACTIONABLE_SQL} THEN 1 ELSE 0 END) AS actionable,
                  SUM(CASE WHEN lifecycle = 'ENFORCED' THEN 1 ELSE 0 END) AS enforced
                FROM ti_items
                """
            ).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def counts_by_source(self) -> dict[str, dict[str, int]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                f"""
                SELECT source,
                       COUNT(*) AS stored,
                       SUM(CASE WHEN {_MAPPED_SQL} THEN 1 ELSE 0 END) AS mapped
                FROM ti_items
                GROUP BY source
                """
            ).fetchall()
        return {
            str(row["source"]): {"stored": int(row["stored"] or 0), "mapped": int(row["mapped"] or 0)}
            for row in rows
        }

    def count_by_applicability(self) -> dict[str, int]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT applicability, COUNT(*) AS n FROM ti_items GROUP BY applicability"
            ).fetchall()
            return {str(row["applicability"] or "unknown"): int(row["n"]) for row in rows}

    def items_updated_since(self, since: float) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT item_json FROM ti_items WHERE baseline = 0 AND updated_at > ? ORDER BY updated_at DESC",
                (since,),
            ).fetchall()
            return [json.loads(row["item_json"]) for row in rows]

    def find_by_hash(self, content_hash: str, *, exclude: str | None = None) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT item_json FROM ti_items WHERE content_hash = ?",
                (content_hash,),
            ).fetchall()
        docs = [json.loads(row["item_json"]) for row in rows]
        if exclude:
            docs = [doc for doc in docs if doc.get("id") != exclude]
        return docs

    def find_by_weakness(self, weakness_id: str) -> list[dict[str, Any]]:
        needle = weakness_id
        with connect(self.db_path) as conn:
            rows = conn.execute("SELECT item_json FROM ti_items").fetchall()
        found = []
        for row in rows:
            doc = json.loads(row["item_json"])
            ids = {w.get("id") for w in doc.get("weaknesses") or [] if isinstance(w, dict)}
            if needle in ids or doc.get("source_id") == needle:
                found.append(doc)
        return found

    def audit(
        self,
        *,
        kind: str,
        item_id: str | None,
        actor: str | None,
        previous_state: str | None,
        new_state: str | None,
        detail: dict[str, Any],
    ) -> int:
        with connect(self.db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO ti_audit(created_at, item_id, kind, actor, previous_state, new_state, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    item_id,
                    kind,
                    actor,
                    previous_state,
                    new_state,
                    json.dumps(detail, sort_keys=True, default=str),
                ),
            )
            return int(cur.lastrowid)

    def list_audit(self, item_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            if item_id:
                rows = conn.execute(
                    "SELECT * FROM ti_audit WHERE item_id = ? ORDER BY id DESC LIMIT ?",
                    (item_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM ti_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for row in rows:
                detail = json.loads(row["detail_json"])
                out.append(
                    {
                        "id": row["id"],
                        "created_at": row["created_at"],
                        "item_id": row["item_id"],
                        "kind": row["kind"],
                        "actor": row["actor"],
                        "previous_state": row["previous_state"],
                        "new_state": row["new_state"],
                        "detail": detail,
                    }
                )
            return out

    def prune(self, *, max_items: int) -> int:
        with connect(self.db_path) as conn:
            total = int(conn.execute("SELECT COUNT(*) AS n FROM ti_items").fetchone()["n"])
            if total <= max_items:
                return 0
            extra = total - max_items
            rows = conn.execute(
                """
                SELECT item_id FROM ti_items
                WHERE baseline = 1 AND lifecycle NOT IN ('AWAITING_APPROVAL', 'APPROVED', 'OBSERVE', 'ENFORCED')
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (extra,),
            ).fetchall()
            ids = [row["item_id"] for row in rows if row["item_id"]]
            for item_id in ids:
                conn.execute("DELETE FROM ti_items WHERE item_id = ?", (item_id,))
            return len(ids)

    def item_count(self) -> int:
        with connect(self.db_path) as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM ti_items").fetchone()["n"])


def _item_filters(
    *,
    source: str | None,
    severity: str | None,
    lifecycle: str | None,
    applicability: str | None,
    since: float | None,
    until: float | None,
    query: str | None,
    mapping: str | None,
    actionable: bool,
    surface: str | None,
) -> tuple[list[str], list[Any]]:
    clauses = ["1=1"]
    params: list[Any] = []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if lifecycle:
        clauses.append("lifecycle = ?")
        params.append(lifecycle)
    if applicability:
        clauses.append("applicability = ?")
        params.append(applicability)
    if since is not None:
        clauses.append("updated_at >= ?")
        params.append(since)
    if until is not None:
        clauses.append("updated_at <= ?")
        params.append(until)
    if mapping == "mapped":
        clauses.append(_MAPPED_SQL)
    elif mapping == "unmapped":
        clauses.append(f"NOT ({_MAPPED_SQL})")
    if actionable:
        clauses.append(f"({_ACTIONABLE_SQL})")
    if surface:
        clauses.append(
            "("
            "EXISTS (SELECT 1 FROM json_each(json_extract(item_json, '$.contract.enforcement_surfaces')) WHERE value = ?) "
            "OR EXISTS (SELECT 1 FROM json_each(json_extract(item_json, '$.contract.required_surfaces')) WHERE value = ?)"
            ")"
        )
        params.extend([surface, surface])
    term = (query or "").strip()[:200]
    if term:
        escaped = term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{escaped}%"
        clauses.append(
            "(lower(source_id) LIKE ? ESCAPE '\\' OR lower(COALESCE(json_extract(item_json, '$.title'), '')) LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like])
    return clauses, params
