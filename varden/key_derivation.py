"""Purpose-separated keys derived from the deployment signing secret.

Existing bearer, approval and audit-chain signatures are unchanged.
New purposes get their own HKDF labels so a leak of one key does not
substitute for another.
"""

from __future__ import annotations

import hashlib
import hmac

PURPOSE_REDACTION = "varden-redaction-correlation-v1"
PURPOSE_SESSION_CONTRACT = "varden-session-contract-v1"
PURPOSE_AUDIT_MIGRATION = "varden-audit-migration-manifest-v1"


def _hkdf(master: bytes, *, purpose: str, length: int = 32) -> bytes:
    """HKDF-SHA256 extract+expand with a fixed salt and one info label."""
    if not master:
        raise ValueError("master key material is required")
    salt = b"varden-hkdf-salt-v1"
    prk = hmac.new(salt, master, hashlib.sha256).digest()
    info = purpose.encode("utf-8")
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_purpose_key(master_secret: str, purpose: str) -> bytes:
    return _hkdf(master_secret.encode("utf-8"), purpose=purpose)


def purpose_hmac(master_secret: str, purpose: str, message: bytes) -> str:
    key = derive_purpose_key(master_secret, purpose)
    return hmac.new(key, message, hashlib.sha256).hexdigest()
