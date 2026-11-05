"""Scoped, single-use approvals for one asset and one invariant.

The protected agent cannot approve its own monitoring change. A token bound
to one asset does not authorise a different asset or a second use.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any


def _token_secret() -> bytes:
    raw = os.environ.get("VARDEN_MIP_APPROVAL_SECRET")
    if raw:
        return raw.encode("utf-8")
    return b"varden-mip-process-local-approval"


@dataclass
class ScopedApproval:
    approval_id: str
    asset_id: str
    invariant_id: str
    operation: str
    subject_agent: str
    issuer: str
    nonce: str
    expires_at: float
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "asset_id": self.asset_id,
            "invariant_id": self.invariant_id,
            "operation": self.operation,
            "subject_agent": self.subject_agent,
            "issuer": self.issuer,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
        }


class ApprovalStore:
    def __init__(self, secret: bytes | None = None, *, authority: str = "process_local") -> None:
        if authority not in {"process_local", "external_file"}:
            raise ValueError("approval authority must be process_local or external_file")
        if authority == "external_file" and not secret:
            raise ValueError("an external approval secret is required")
        self._lock = threading.RLock()
        self._live: dict[str, ScopedApproval] = {}
        self._used: set[str] = set()
        self._secret = secret
        self.authority = authority

    @property
    def independent_authority(self) -> bool:
        """True only when the secret was supplied from outside this process.

        Independence still requires a boundary probe showing the agent cannot
        read that secret. Holding the bytes in-process is not that probe.
        """
        return self.authority == "external_file" and self._secret is not None

    def _secret_bytes(self) -> bytes:
        if self._secret is not None:
            return self._secret
        return _token_secret()

    def issue(
        self,
        *,
        asset_id: str,
        invariant_id: str,
        operation: str,
        subject_agent: str,
        issuer: str,
        ttl_s: float = 120.0,
    ) -> ScopedApproval:
        if not issuer or issuer == subject_agent:
            raise ValueError("approval issuer must be an independent authority")
        nonce = uuid.uuid4().hex
        approval_id = uuid.uuid4().hex
        expires = time.time() + ttl_s
        body = f"{approval_id}|{asset_id}|{invariant_id}|{operation}|{subject_agent}|{issuer}|{nonce}|{expires:.6f}"
        digest = hmac.new(self._secret_bytes(), body.encode("utf-8"), hashlib.sha256).hexdigest()
        record = ScopedApproval(
            approval_id=approval_id,
            asset_id=asset_id,
            invariant_id=invariant_id,
            operation=operation,
            subject_agent=subject_agent,
            issuer=issuer,
            nonce=nonce,
            expires_at=expires,
            digest=digest,
        )
        with self._lock:
            self._live[approval_id] = record
        return record

    def consume(
        self,
        presented: dict[str, Any] | None,
        *,
        asset_id: str,
        invariant_id: str,
        operation: str,
        subject_agent: str,
    ) -> tuple[bool, str]:
        """Validate and burn a token. Replay and scope mismatch fail closed."""
        if not isinstance(presented, dict):
            return False, "approval_missing"
        approval_id = str(presented.get("approval_id") or "")
        nonce = str(presented.get("nonce") or "")
        issuer = str(presented.get("issuer") or "")
        digest = str(presented.get("digest") or "")
        if issuer == subject_agent:
            return False, "self_authorisation"
        with self._lock:
            if nonce and nonce in self._used:
                return False, "approval_replay"
            record = self._live.get(approval_id)
            if record is None:
                return False, "approval_unknown"
            if record.nonce in self._used:
                return False, "approval_replay"
            if not hmac.compare_digest(record.digest, digest):
                return False, "approval_digest_mismatch"
            if record.asset_id != asset_id or record.invariant_id != invariant_id or record.operation != operation:
                return False, "approval_scope_mismatch"
            if record.subject_agent != subject_agent:
                return False, "approval_subject_mismatch"
            if record.issuer != issuer or record.issuer == subject_agent:
                return False, "self_authorisation"
            if time.time() > record.expires_at:
                return False, "approval_expired"
            body = (
                f"{record.approval_id}|{record.asset_id}|{record.invariant_id}|{record.operation}|"
                f"{record.subject_agent}|{record.issuer}|{record.nonce}|{record.expires_at:.6f}"
            )
            expected = hmac.new(self._secret_bytes(), body.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, digest):
                return False, "approval_digest_mismatch"
            self._used.add(record.nonce)
            self._live.pop(approval_id, None)
            return True, "approval_consumed"

    def reset(self) -> None:
        with self._lock:
            self._live.clear()
            self._used.clear()
