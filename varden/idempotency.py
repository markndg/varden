from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .db import connect, init_db

DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_KEY_LENGTH = 256


def stable_json(value: Any) -> str:
    """Canonical JSON serialisation used for body hashing. Key order in the
    caller's JSON must never affect whether two requests are treated as the
    "same" request."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class IdempotencyConflict(Exception):
    """Raised when the same idempotency key is reused with a different
    request body within the same tenant/principal/method/route scope. The
    caller (an API route) should turn this into an HTTP 409 with a stable
    error code — see docs/web-shield-hardening-review.md #3."""

    error_code = "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"

    def __init__(self, scope_key: str = ""):
        self.scope_key = scope_key
        super().__init__(f"idempotency key reused with a different request body (scope={scope_key})")


class IdempotencyStore:
    """Caches responses for a caller-supplied idempotency key so a retried
    request returns the original result instead of re-executing.

    The cache identity is a composite of tenant, authenticated principal,
    HTTP method and canonical route — never the raw key alone. Without this,
    a caller who reused (or guessed) another tenant's/principal's/endpoint's
    idempotency key value would receive that other request's cached
    response, which is a cross-tenant data leak. See
    docs/web-shield-hardening-review.md #3 for the full writeup.
    """

    def __init__(self, db_path: str, default_ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.db_path = db_path
        self.default_ttl_seconds = default_ttl_seconds
        init_db(db_path)

    def _composite(self, *, tenant_id: str | None, principal: str | None, method: str, route: str, key: str) -> str:
        return "\x1f".join([str(tenant_id or ""), str(principal or ""), method.upper(), route, key])

    def _key_hash(self, composite: str) -> str:
        return hashlib.sha256(composite.encode("utf-8")).hexdigest()

    def _body_hash(self, body: Any) -> str:
        return hashlib.sha256(stable_json(body).encode("utf-8")).hexdigest()

    def get(
        self,
        key: str,
        *,
        tenant_id: str | None = None,
        principal: str | None = None,
        method: str = "POST",
        route: str = "",
        body: Any = None,
    ) -> dict | None:
        """Returns the cached response for an exact repeat of the same
        request (same scope + key + body). Raises ``IdempotencyConflict`` if
        the key was already used in this scope with a *different* body.
        Returns ``None`` for a genuinely new key or an expired record (which
        is deliberately treated as a fresh request, not an error)."""

        if not key or len(key) > MAX_KEY_LENGTH:
            return None
        composite = self._composite(tenant_id=tenant_id, principal=principal, method=method, route=route, key=key)
        key_hash = self._key_hash(composite)
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT response_json, body_hash, expires_at FROM idempotency_keys WHERE key_hash=?", (key_hash,)
            ).fetchone()
        if row is None:
            return None
        if row["expires_at"] is not None and row["expires_at"] < time.time():
            return None
        body_hash = self._body_hash(body)
        if row["body_hash"] is not None and row["body_hash"] != body_hash:
            raise IdempotencyConflict(scope_key=composite)
        return json.loads(row["response_json"]) if row["response_json"] else None

    def put(
        self,
        key: str,
        response: Any,
        *,
        tenant_id: str | None = None,
        principal: str | None = None,
        method: str = "POST",
        route: str = "",
        body: Any = None,
        ttl_seconds: float | None = None,
    ) -> None:
        if not key or len(key) > MAX_KEY_LENGTH:
            return
        composite = self._composite(tenant_id=tenant_id, principal=principal, method=method, route=route, key=key)
        key_hash = self._key_hash(composite)
        body_hash = self._body_hash(body)
        expires_at = time.time() + (self.default_ttl_seconds if ttl_seconds is None else ttl_seconds)
        with connect(self.db_path) as conn:
            # INSERT OR REPLACE is the same atomic single-statement upsert the
            # rest of this codebase relies on for compare-and-set-ish writes
            # (see webshield_tools); good enough for this cache's consistency
            # needs under SQLite's serialised-writer model.
            conn.execute(
                "INSERT OR REPLACE INTO idempotency_keys(key_hash, created_at, body_hash, response_json, expires_at) VALUES (?,?,?,?,?)",
                (key_hash, time.time(), body_hash, json.dumps(response, ensure_ascii=False, default=str), expires_at),
            )
            conn.commit()
