"""First-class evidence for Predictive Authority graph relationships.

Every security-relevant edge answers: why does Varden believe this exists?
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceKind(str, Enum):
    RUNTIME_OBSERVED = "runtime_observed"
    VARDEN_CONFIGURED = "varden_configured"
    APPROVAL_GRANTED = "approval_granted"
    INTERCEPTOR_DERIVED = "interceptor_derived"
    TRUSTED_DISCOVERY = "trusted_discovery"
    POLICY_DERIVED = "policy_derived"
    UNTRUSTED_DECLARED = "untrusted_declared"
    POTENTIAL = "potential"
    # Legacy aliases mapped from EdgeEvidence
    OBSERVED = "runtime_observed"
    INFERRED = "interceptor_derived"
    CONFIGURED = "varden_configured"
    RUNTIME_DISCOVERED = "trusted_discovery"


# Evidence that may establish CONFIRMED authority.
_TRUSTED_EVIDENCE = frozenset(
    {
        EvidenceKind.RUNTIME_OBSERVED.value,
        EvidenceKind.VARDEN_CONFIGURED.value,
        EvidenceKind.APPROVAL_GRANTED.value,
        EvidenceKind.TRUSTED_DISCOVERY.value,
        EvidenceKind.POLICY_DERIVED.value,
        # interceptor_derived may confirm only the *observed* capability itself,
        # never speculative child grants from untrusted claims.
        EvidenceKind.INTERCEPTOR_DERIVED.value,
    }
)

_UNTRUSTED_EVIDENCE = frozenset(
    {
        EvidenceKind.UNTRUSTED_DECLARED.value,
        EvidenceKind.POTENTIAL.value,
    }
)


class AuthorityLifecycle(str, Enum):
    UNKNOWN = "unknown"
    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    TRUNCATED = "truncated"
    OFF = "off"


def evidence_can_confirm(kind: str | EvidenceKind) -> bool:
    value = kind.value if isinstance(kind, EvidenceKind) else str(kind)
    # Untrusted declarations and pure potential never confirm.
    if value in _UNTRUSTED_EVIDENCE or value == EvidenceKind.UNTRUSTED_DECLARED.value:
        return False
    if value == EvidenceKind.POTENTIAL.value:
        return False
    return value in _TRUSTED_EVIDENCE


def normalize_evidence_kind(raw: Any) -> EvidenceKind:
    if isinstance(raw, EvidenceKind):
        # Resolve aliases to canonical members by value.
        return EvidenceKind(raw.value)
    text = str(getattr(raw, "value", raw) or "potential").strip().lower()
    # Strip Enum-style "EvidenceKind.FOO" if ever stringified that way.
    if "." in text and not text.startswith("untrusted"):
        text = text.split(".", 1)[-1]
    aliases = {
        "observed": EvidenceKind.RUNTIME_OBSERVED,
        "runtime_observed": EvidenceKind.RUNTIME_OBSERVED,
        "inferred": EvidenceKind.INTERCEPTOR_DERIVED,
        "inferred_deterministically": EvidenceKind.INTERCEPTOR_DERIVED,
        "interceptor_derived": EvidenceKind.INTERCEPTOR_DERIVED,
        "configured": EvidenceKind.VARDEN_CONFIGURED,
        "varden_configured": EvidenceKind.VARDEN_CONFIGURED,
        "runtime_discovered": EvidenceKind.TRUSTED_DISCOVERY,
        "trusted_discovery": EvidenceKind.TRUSTED_DISCOVERY,
        "approval_granted": EvidenceKind.APPROVAL_GRANTED,
        "policy_derived": EvidenceKind.POLICY_DERIVED,
        "untrusted_declared": EvidenceKind.UNTRUSTED_DECLARED,
        "potential": EvidenceKind.POTENTIAL,
    }
    return aliases.get(text, EvidenceKind.POTENTIAL)


@dataclass
class EvidenceRecord:
    """Why a graph relationship exists."""

    kind: EvidenceKind
    source: str = ""  # human-readable source (never secret material)
    assertion_actor: str = ""  # who/what asserted it
    provenance_ref: str | None = None
    trust_domain: str = ""
    established_at: float = field(default_factory=time.time)
    last_validated_at: float | None = None
    still_valid: bool = True
    lifecycle: AuthorityLifecycle = AuthorityLifecycle.POTENTIAL
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.kind, str):
            object.__setattr__(self, "kind", normalize_evidence_kind(self.kind))
        if isinstance(self.lifecycle, str):
            try:
                object.__setattr__(self, "lifecycle", AuthorityLifecycle(self.lifecycle))
            except ValueError:
                object.__setattr__(self, "lifecycle", AuthorityLifecycle.POTENTIAL)
        # Untrusted evidence can never be confirmed.
        if self.kind == EvidenceKind.UNTRUSTED_DECLARED and self.lifecycle == AuthorityLifecycle.CONFIRMED:
            object.__setattr__(self, "lifecycle", AuthorityLifecycle.POTENTIAL)
        if self.kind == EvidenceKind.POTENTIAL and self.lifecycle == AuthorityLifecycle.CONFIRMED:
            object.__setattr__(self, "lifecycle", AuthorityLifecycle.POTENTIAL)

    @property
    def confirmed(self) -> bool:
        return self.lifecycle == AuthorityLifecycle.CONFIRMED and self.still_valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": self.source,
            "assertion_actor": self.assertion_actor,
            "provenance_ref": self.provenance_ref,
            "trust_domain": self.trust_domain,
            "established_at": self.established_at,
            "last_validated_at": self.last_validated_at,
            "still_valid": self.still_valid,
            "lifecycle": self.lifecycle.value,
            "description": self.description,
            "metadata": dict(self.metadata),
            "can_confirm": evidence_can_confirm(self.kind),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        return cls(
            kind=normalize_evidence_kind(data.get("kind")),
            source=str(data.get("source") or ""),
            assertion_actor=str(data.get("assertion_actor") or ""),
            provenance_ref=data.get("provenance_ref"),
            trust_domain=str(data.get("trust_domain") or ""),
            established_at=float(data.get("established_at") or time.time()),
            last_validated_at=data.get("last_validated_at"),
            still_valid=bool(data.get("still_valid", True)),
            lifecycle=AuthorityLifecycle(str(data.get("lifecycle") or "potential")),
            description=str(data.get("description") or ""),
            metadata=dict(data.get("metadata") or {}),
        )


def make_evidence(
    kind: str | EvidenceKind,
    *,
    source: str = "",
    assertion_actor: str = "",
    provenance_ref: str | None = None,
    trust_domain: str = "",
    lifecycle: AuthorityLifecycle | None = None,
    description: str = "",
    **meta: Any,
) -> EvidenceRecord:
    ek = normalize_evidence_kind(kind)
    if lifecycle is None:
        if ek == EvidenceKind.UNTRUSTED_DECLARED or ek == EvidenceKind.POTENTIAL:
            lifecycle = AuthorityLifecycle.POTENTIAL
        elif evidence_can_confirm(ek) and ek != EvidenceKind.INTERCEPTOR_DERIVED:
            lifecycle = AuthorityLifecycle.CONFIRMED
        elif ek == EvidenceKind.RUNTIME_OBSERVED:
            lifecycle = AuthorityLifecycle.CONFIRMED
        else:
            lifecycle = AuthorityLifecycle.POTENTIAL
    return EvidenceRecord(
        kind=ek,
        source=source,
        assertion_actor=assertion_actor,
        provenance_ref=provenance_ref,
        trust_domain=trust_domain,
        lifecycle=lifecycle,
        description=description,
        metadata=dict(meta),
    )
