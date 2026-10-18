"""Signed session contracts for PATH-shim enforcement.

The contract is an authenticated configuration file. It is not an operating
system sandbox. A process running as the same user can replace the file,
skip the shim, or execute another binary directly. Coverage must not report
that path as fully enforced.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from varden.key_derivation import PURPOSE_SESSION_CONTRACT, derive_purpose_key, purpose_hmac

MODE_RANK = {"observe": 0, "guarded": 1, "strict": 2}
_BODY_FIELDS = (
    "contract_id",
    "session_id",
    "principal",
    "mode",
    "fail_mode",
    "trace_id",
    "orig_path",
    "created_at",
    "expires_at",
    "key_id",
)


class ContractError(Exception):
    pass


def principal_for(api_key: str | None) -> str:
    if not api_key:
        return "anonymous"
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]


def verify_key(master_secret: str) -> bytes:
    return derive_purpose_key(master_secret, PURPOSE_SESSION_CONTRACT)


def _canonical(body: dict[str, Any]) -> bytes:
    payload = {field: body[field] for field in _BODY_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_contract(
    *,
    master_secret: str,
    session_id: str,
    principal: str,
    mode: str,
    fail_mode: str,
    trace_id: str,
    orig_path: str,
    ttl_seconds: int = 8 * 3600,
    now: float | None = None,
) -> dict[str, Any]:
    if mode not in MODE_RANK:
        raise ContractError(f"unsupported mode {mode}")
    if fail_mode not in {"open", "closed"}:
        raise ContractError(f"unsupported fail mode {fail_mode}")
    if mode in {"guarded", "strict"} and fail_mode != "closed":
        raise ContractError("guarded and strict sessions must fail closed")
    stamp = time.time() if now is None else now
    body: dict[str, Any] = {
        "contract_id": uuid.uuid4().hex,
        "session_id": session_id,
        "principal": principal,
        "mode": mode,
        "fail_mode": fail_mode,
        "trace_id": trace_id,
        "orig_path": orig_path,
        "created_at": stamp,
        "expires_at": stamp + ttl_seconds,
        "key_id": PURPOSE_SESSION_CONTRACT,
    }
    body["signature"] = purpose_hmac(master_secret, PURPOSE_SESSION_CONTRACT, _canonical(body))
    return body


def verify_contract(
    document: dict[str, Any],
    *,
    raw_key: bytes,
    session_id: str,
    now: float | None = None,
) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ContractError("contract is missing")
    try:
        signature = str(document["signature"])
        canonical = _canonical(document)
    except (KeyError, TypeError) as exc:
        raise ContractError("contract is malformed") from exc
    expected = hmac.new(raw_key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ContractError("contract signature is invalid")
    if document.get("key_id") != PURPOSE_SESSION_CONTRACT:
        raise ContractError("contract key id is not the session purpose")
    stamp = time.time() if now is None else now
    if float(document["expires_at"]) < stamp:
        raise ContractError("contract is expired")
    if str(document.get("session_id")) != session_id:
        raise ContractError("contract session does not match")
    if document.get("mode") not in MODE_RANK:
        raise ContractError("contract mode is unsupported")
    return document


def register_persisted_contract(db_path: str, document: dict[str, Any], *, master_secret: str) -> None:
    from varden.db import connect, init_db

    verify_contract(document, raw_key=verify_key(master_secret), session_id=str(document.get("session_id") or ""))
    init_db(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS session_contracts (
                contract_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at REAL NOT NULL
            )"""
        )
        conn.execute(
            "INSERT OR REPLACE INTO session_contracts(contract_id, session_id, payload_json, created_at) VALUES (?,?,?,?)",
            (document["contract_id"], document["session_id"], json.dumps(document), time.time()),
        )
        conn.commit()


def confirm_persisted_contract(db_path: str, document: dict[str, Any], *, master_secret: str) -> bool:
    from varden.db import connect

    verify_contract(document, raw_key=verify_key(master_secret), session_id=str(document.get("session_id") or ""))
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT payload_json FROM session_contracts WHERE contract_id = ?",
            (document.get("contract_id"),),
        ).fetchone()
    if row is None:
        raise ContractError("contract is not registered")
    stored = json.loads(row["payload_json"])
    if stored.get("signature") != document.get("signature"):
        raise ContractError("contract does not match the registration")
    return True


def weaker_mode(asserted: str | None, registered: str) -> bool:
    if not asserted or asserted not in MODE_RANK:
        return False
    return MODE_RANK[asserted] < MODE_RANK[registered]
