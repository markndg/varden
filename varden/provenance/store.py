"""Persistence for provenance sources, edges, delegations and findings."""

from __future__ import annotations

import json
import time
from typing import Any

from ..db import connect
from .models import Delegation, ProvenanceAnalysis, ProvenanceSource, new_id


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _loads(text: str | None, default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


class ProvenanceStore:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def upsert_source(self, source: ProvenanceSource, *, tenant_id: str | None, trace_id: str | None = None) -> str:
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO provenance_sources
                   (tenant_id, source_id, source_type, origin, principal, trust_level, integrity,
                    authenticated, provenance_complete, first_seen, metadata_json, trace_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(tenant_id, source_id) DO UPDATE SET
                     trust_level=excluded.trust_level,
                     integrity=excluded.integrity,
                     metadata_json=excluded.metadata_json,
                     trace_id=COALESCE(excluded.trace_id, provenance_sources.trace_id)
                """,
                (
                    tenant_id,
                    source.source_id,
                    source.source_type,
                    source.origin,
                    source.principal,
                    source.trust_level,
                    source.integrity,
                    1 if source.authenticated else 0,
                    1 if source.provenance_complete else 0,
                    source.first_seen,
                    _dumps(source.metadata),
                    trace_id,
                ),
            )
            conn.commit()
        return source.source_id

    def add_edge(
        self,
        *,
        tenant_id: str | None,
        trace_id: str,
        edge_type: str,
        from_id: str,
        to_id: str,
        event_id: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        edge_id = new_id("edge")
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO provenance_edges
                   (tenant_id, edge_id, edge_type, from_id, to_id, trace_id, event_id, metadata_json, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    tenant_id, edge_id, edge_type, from_id, to_id, trace_id, event_id,
                    _dumps(metadata or {}), time.time(),
                ),
            )
            conn.commit()
        return edge_id

    def save_delegation(self, delegation: Delegation, *, tenant_id: str | None) -> str:
        with connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO authority_delegations
                   (tenant_id, delegation_id, principal, capabilities_json, resources_json, constraints_json,
                    issued_by, issued_at, expires_at, trace_scope, integrity)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(tenant_id, delegation_id) DO UPDATE SET
                     capabilities_json=excluded.capabilities_json,
                     resources_json=excluded.resources_json,
                     expires_at=excluded.expires_at,
                     integrity=excluded.integrity
                """,
                (
                    tenant_id,
                    delegation.delegation_id,
                    delegation.principal,
                    _dumps(delegation.capabilities),
                    _dumps(delegation.resources),
                    _dumps(delegation.constraints),
                    delegation.issued_by,
                    delegation.issued_at,
                    delegation.expires_at,
                    delegation.trace_scope,
                    delegation.integrity,
                ),
            )
            conn.commit()
        return delegation.delegation_id

    def active_delegation(self, trace_id: str, *, tenant_id: str | None = None) -> Delegation | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                """SELECT * FROM authority_delegations
                   WHERE (tenant_id IS ? OR (? IS NULL AND tenant_id IS NULL) OR tenant_id = ?)
                     AND (trace_scope = ? OR trace_scope IS NULL)
                     AND integrity = 'verified'
                   ORDER BY issued_at DESC LIMIT 1""",
                (tenant_id, tenant_id, tenant_id, trace_id),
            ).fetchone()
        if not row:
            return None
        dlg = Delegation.from_dict({
            "delegation_id": row["delegation_id"],
            "principal": row["principal"],
            "capabilities": _loads(row["capabilities_json"], []),
            "resources": _loads(row["resources_json"], []),
            "constraints": _loads(row["constraints_json"], {}),
            "issued_by": row["issued_by"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "trace_scope": row["trace_scope"],
            "integrity": row["integrity"],
        })
        return dlg if dlg.is_active() else None

    def sources_for_trace(self, trace_id: str, *, tenant_id: str | None = None, limit: int = 100) -> list[ProvenanceSource]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT * FROM provenance_sources
                   WHERE trace_id = ?
                     AND (tenant_id IS ? OR (? IS NULL AND tenant_id IS NULL) OR tenant_id = ?)
                   ORDER BY first_seen DESC LIMIT ?""",
                (trace_id, tenant_id, tenant_id, tenant_id, limit),
            ).fetchall()
        return [
            ProvenanceSource(
                source_id=row["source_id"],
                source_type=row["source_type"],
                origin=row["origin"] or "",
                principal=row["principal"] or "",
                trust_level=row["trust_level"],
                integrity=row["integrity"],
                authenticated=bool(row["authenticated"]),
                first_seen=row["first_seen"],
                metadata=_loads(row["metadata_json"], {}),
                provenance_complete=bool(row["provenance_complete"]),
            )
            for row in rows
        ]

    def record_analysis(self, action: Any, analysis: ProvenanceAnalysis) -> None:
        tenant_id = getattr(action, "tenant_id", None)
        trace_id = getattr(action, "trace_id", None)
        for source in analysis.sources:
            self.upsert_source(source, tenant_id=tenant_id, trace_id=trace_id)
        if not analysis.findings:
            return
        with connect(self.db_path) as conn:
            for finding in analysis.findings:
                conn.execute(
                    """INSERT INTO authority_findings
                       (tenant_id, finding_id, finding_type, severity, trace_id, tool, resource,
                        explanation, evidence_json, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        tenant_id,
                        new_id("fnd"),
                        finding.get("type") or "authority_escalation",
                        finding.get("severity") or "high",
                        trace_id,
                        getattr(action, "tool", None),
                        (analysis.authority.resource if analysis.authority else None),
                        finding.get("explanation") or "",
                        _dumps(finding),
                        time.time(),
                    ),
                )
            conn.commit()

    def list_findings(
        self,
        *,
        tenant_id: str | None = None,
        finding_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM authority_findings WHERE 1=1"
        params: list[Any] = []
        if tenant_id is not None:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if finding_type:
            query += " AND finding_type = ?"
            params.append(finding_type)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "finding_id": row["finding_id"],
                "type": row["finding_type"],
                "severity": row["severity"],
                "trace_id": row["trace_id"],
                "tool": row["tool"],
                "resource": row["resource"],
                "explanation": row["explanation"],
                "evidence": _loads(row["evidence_json"], {}),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def list_delegations(self, *, tenant_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT * FROM authority_delegations
                   WHERE (tenant_id IS ? OR (? IS NULL AND tenant_id IS NULL) OR tenant_id = ?)
                   ORDER BY issued_at DESC LIMIT ?""",
                (tenant_id, tenant_id, tenant_id, limit),
            ).fetchall()
        return [
            {
                "delegation_id": row["delegation_id"],
                "principal": row["principal"],
                "capabilities": _loads(row["capabilities_json"], []),
                "resources": _loads(row["resources_json"], []),
                "issued_by": row["issued_by"],
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
                "trace_scope": row["trace_scope"],
                "integrity": row["integrity"],
            }
            for row in rows
        ]

    def upsert_tool_fingerprint(
        self,
        *,
        tenant_id: str | None,
        server_id: str,
        tool_name: str,
        fingerprint: str,
        fields_json: dict[str, Any],
    ) -> dict[str, Any]:
        """Store/compare MCP tool fingerprints for rug-pull detection."""
        with connect(self.db_path) as conn:
            existing = conn.execute(
                """SELECT * FROM tool_fingerprints
                   WHERE (tenant_id IS ? OR tenant_id = ?) AND server_id = ? AND tool_name = ?
                   ORDER BY last_seen DESC LIMIT 1""",
                (tenant_id, tenant_id, server_id, tool_name),
            ).fetchone()
            now = time.time()
            changed = False
            previous = None
            if existing and existing["fingerprint"] != fingerprint:
                changed = True
                previous = existing["fingerprint"]
                conn.execute(
                    """UPDATE tool_fingerprints SET trust_status='stale', last_seen=?,
                       changed_fields_json=?, previous_fingerprint=?
                       WHERE id=?""",
                    (now, _dumps(fields_json), previous, existing["id"]),
                )
            if not existing or changed:
                conn.execute(
                    """INSERT INTO tool_fingerprints
                       (tenant_id, server_id, tool_name, fingerprint, fields_json, trust_status,
                        previous_fingerprint, changed_fields_json, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        tenant_id, server_id, tool_name, fingerprint, _dumps(fields_json),
                        "pending" if changed else "observed",
                        previous, _dumps(fields_json) if changed else None, now, now,
                    ),
                )
            else:
                conn.execute(
                    "UPDATE tool_fingerprints SET last_seen=? WHERE id=?",
                    (now, existing["id"]),
                )
            conn.commit()
        return {
            "server_id": server_id,
            "tool_name": tool_name,
            "fingerprint": fingerprint,
            "changed": changed,
            "previous_fingerprint": previous,
            "trust_status": "stale" if changed else "observed",
        }

    def list_tool_fingerprints(self, *, tenant_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT * FROM tool_fingerprints
                   WHERE (tenant_id IS ? OR (? IS NULL AND tenant_id IS NULL) OR tenant_id = ?)
                   ORDER BY last_seen DESC LIMIT ?""",
                (tenant_id, tenant_id, tenant_id, limit),
            ).fetchall()
        return [
            {
                "server_id": row["server_id"],
                "tool_name": row["tool_name"],
                "fingerprint": row["fingerprint"],
                "trust_status": row["trust_status"],
                "previous_fingerprint": row["previous_fingerprint"],
                "fields": _loads(row["fields_json"], {}),
                "changed_fields": _loads(row["changed_fields_json"], {}),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]

    def summary(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        findings = self.list_findings(tenant_id=tenant_id, limit=500)
        by_type: dict[str, int] = {}
        for row in findings:
            by_type[row["type"]] = by_type.get(row["type"], 0) + 1
        fingerprints = self.list_tool_fingerprints(tenant_id=tenant_id, limit=500)
        stale = sum(1 for f in fingerprints if f["trust_status"] in {"stale", "pending"})
        return {
            "findings_total": len(findings),
            "findings_by_type": by_type,
            "authority_violations": by_type.get("delegation_violation", 0) + by_type.get("authority_escalation", 0),
            "confused_deputy": by_type.get("confused_deputy", 0),
            "exfiltration_chains": by_type.get("provenance_exfiltration_chain", 0),
            "cross_server_flows": by_type.get("cross_server_authority_flow", 0),
            "stale_tool_fingerprints": stale,
            "delegations": len(self.list_delegations(tenant_id=tenant_id, limit=500)),
        }
