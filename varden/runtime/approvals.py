"""Scoped, cryptographically protected approval grants for require_approval."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any

from varden.db import connect, init_db


DEFAULT_TTL_SECONDS = 300


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def hash_action_scope(*, action: dict[str, Any], resource: Any = None, authority: Any = None) -> dict[str, str]:
    action_body = {
        "type": action.get("type"),
        "tool": action.get("tool"),
        "method": action.get("method"),
        "url": action.get("url"),
        "domain": action.get("domain"),
        "args": action.get("args") or {},
    }
    resource_body = resource if resource is not None else {
        "url": action.get("url"),
        "tool": action.get("tool"),
        "path": (action.get("args") or {}).get("path"),
    }
    authority_body = authority if authority is not None else (action.get("metadata") or {}).get("authority") or {}
    return {
        "action_hash": hashlib.sha256(_canonical_json(action_body).encode("utf-8")).hexdigest(),
        "resource_hash": hashlib.sha256(_canonical_json(resource_body).encode("utf-8")).hexdigest(),
        "authority_hash": hashlib.sha256(_canonical_json(authority_body).encode("utf-8")).hexdigest(),
    }


class ApprovalStore:
    """Server-authoritative approval grants. Clients cannot self-mint tokens."""

    def __init__(self, db_path: str, *, signing_secret: str):
        self.db_path = db_path
        self.signing_secret = signing_secret
        init_db(db_path)

    def create_pending(
        self,
        *,
        tenant_id: str,
        action: dict[str, Any],
        reason: str,
        event_id: int | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        approved_by: str | None = None,
    ) -> dict[str, Any]:
        approval_id = str(uuid.uuid4())
        now = time.time()
        hashes = hash_action_scope(action=action)
        meta = action.get("metadata") or {}
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO runtime_approvals(
                  approval_id, tenant_id, status, event_id, trace_id,
                  action_hash, resource_hash, authority_hash,
                  action_type, tool, url, method,
                  reason, created_at, expires_at, nonce, metadata_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    approval_id,
                    tenant_id,
                    "pending",
                    event_id,
                    action.get("trace_id"),
                    hashes["action_hash"],
                    hashes["resource_hash"],
                    hashes["authority_hash"],
                    action.get("type"),
                    action.get("tool"),
                    action.get("url"),
                    action.get("method"),
                    reason,
                    now,
                    now + ttl_seconds,
                    secrets.token_hex(16),
                    _canonical_json({"agent_name": action.get("agent_name"), "authority": meta.get("authority")}),
                ),
            )
            conn.commit()
        return self.get(tenant_id, approval_id) or {"approval_id": approval_id, "status": "pending"}

    def get(self, tenant_id: str, approval_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM runtime_approvals WHERE tenant_id=? AND approval_id=?",
                (tenant_id, approval_id),
            ).fetchone()
            return dict(row) if row else None

    def list_pending(self, tenant_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        with connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT * FROM runtime_approvals
                WHERE tenant_id=? AND status='pending' AND expires_at > ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (tenant_id, time.time(), limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def deny(self, tenant_id: str, approval_id: str, *, resolved_by: str | None = None) -> dict[str, Any]:
        row = self.get(tenant_id, approval_id)
        if not row:
            raise KeyError("approval not found")
        if row["status"] != "pending":
            raise ValueError(f"approval already resolved: {row['status']}")
        with connect(self.db_path) as conn:
            conn.execute(
                "UPDATE runtime_approvals SET status='denied', resolved_at=?, resolved_by=? WHERE tenant_id=? AND approval_id=?",
                (time.time(), resolved_by, tenant_id, approval_id),
            )
            conn.commit()
        return self.get(tenant_id, approval_id) or row

    def approve(self, tenant_id: str, approval_id: str, *, resolved_by: str | None = None) -> dict[str, Any]:
        """Issue a single-use signed token bound to action/resource/authority/trace."""
        row = self.get(tenant_id, approval_id)
        if not row:
            raise KeyError("approval not found")
        if row["status"] != "pending":
            raise ValueError(f"approval already resolved: {row['status']}")
        if float(row["expires_at"]) < time.time():
            with connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE runtime_approvals SET status='expired', resolved_at=? WHERE tenant_id=? AND approval_id=?",
                    (time.time(), tenant_id, approval_id),
                )
                conn.commit()
            raise ValueError("approval expired")
        claims = {
            "approval_id": approval_id,
            "tenant_id": tenant_id,
            "trace_id": row.get("trace_id"),
            "event_id": row.get("event_id"),
            "action_hash": row["action_hash"],
            "resource_hash": row["resource_hash"],
            "authority_hash": row["authority_hash"],
            "issued_at": time.time(),
            "expires_at": float(row["expires_at"]),
            "nonce": row["nonce"],
            "approved_by": resolved_by or "operator",
        }
        token = self._sign(claims)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE runtime_approvals
                SET status='approved', resolved_at=?, resolved_by=?, token_hash=?
                WHERE tenant_id=? AND approval_id=?
                """,
                (time.time(), resolved_by or "operator", token_hash, tenant_id, approval_id),
            )
            conn.commit()
        out = self.get(tenant_id, approval_id) or row
        out["token"] = token
        out["claims"] = claims
        return out

    def verify_and_consume(
        self,
        *,
        tenant_id: str,
        token: str,
        action: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate token scope and mark consumed atomically.

        Uses BEGIN IMMEDIATE so concurrent retries cannot both win.
        """
        claims = self._verify(token)
        if claims.get("tenant_id") != tenant_id:
            raise ValueError("approval tenant mismatch")
        approval_id = claims["approval_id"]
        if float(claims.get("expires_at") or 0) < time.time():
            raise ValueError("approval expired")
        hashes = hash_action_scope(action=action)
        if not hmac.compare_digest(str(claims["action_hash"]), hashes["action_hash"]):
            raise ValueError("approval action scope mismatch")
        if not hmac.compare_digest(str(claims["resource_hash"]), hashes["resource_hash"]):
            raise ValueError("approval resource scope mismatch")
        if not hmac.compare_digest(str(claims["authority_hash"]), hashes["authority_hash"]):
            raise ValueError("approval authority scope mismatch")
        if claims.get("trace_id") and action.get("trace_id") and claims["trace_id"] != action.get("trace_id"):
            raise ValueError("approval trace scope mismatch")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM runtime_approvals WHERE tenant_id=? AND approval_id=?",
                (tenant_id, approval_id),
            ).fetchone()
            if not row:
                raise ValueError("approval not found")
            row = dict(row)
            if row["status"] == "consumed":
                raise ValueError("approval already used")
            if row["status"] != "approved":
                raise ValueError(f"approval not usable: {row['status']}")
            if float(row.get("expires_at") or 0) < time.time():
                raise ValueError("approval expired")
            if row.get("token_hash") and not hmac.compare_digest(str(row["token_hash"]), token_hash):
                raise ValueError("approval token mismatch")
            cur = conn.execute(
                """
                UPDATE runtime_approvals
                SET status='consumed', consumed_at=?
                WHERE tenant_id=? AND approval_id=? AND status='approved'
                """,
                (time.time(), tenant_id, approval_id),
            )
            if cur.rowcount != 1:
                raise ValueError("approval already used")
            conn.execute(
                """
                INSERT INTO runtime_approval_consumptions(approval_id, tenant_id, consumed_at, action_hash, event_id)
                VALUES (?,?,?,?,?)
                """,
                (approval_id, tenant_id, time.time(), hashes["action_hash"], action.get("parent_event_id")),
            )
            conn.commit()
        return {"approval_id": approval_id, "status": "consumed", "claims": claims}

    def _sign(self, claims: dict[str, Any]) -> str:
        body = _canonical_json(claims)
        sig = hmac.new(self.signing_secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        payload = {"claims": claims, "sig": sig}
        # Compact transport: base64url would be nicer; hex JSON is fine and auditable.
        return _canonical_json(payload)

    def _verify(self, token: str) -> dict[str, Any]:
        try:
            payload = json.loads(token)
        except Exception as exc:
            raise ValueError("malformed approval token") from exc
        claims = payload.get("claims")
        sig = payload.get("sig")
        if not isinstance(claims, dict) or not isinstance(sig, str):
            raise ValueError("malformed approval token")
        body = _canonical_json(claims)
        expected = hmac.new(self.signing_secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("approval signature invalid")
        return claims
