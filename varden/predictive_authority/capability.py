"""First-class Capability model with hierarchy and evidence-driven grants.

Capabilities use a dotted namespace. Hierarchy is parent-prefix based:
``aws.s3.write`` implies sensitivity of ``aws.s3`` and ``aws``, but parent
capabilities do NOT automatically grant children (conservative).

Grant relationships are explicit and evidence-driven. Unknown credential
scope yields *potential* capabilities, never confirmed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class CapabilityEvidence(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred_deterministically"
    CONFIGURED = "configured"
    RUNTIME_DISCOVERED = "runtime_discovered"
    APPROVAL_GRANTED = "approval_granted"
    POTENTIAL = "potential"


class CapabilityKind(str, Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"


@dataclass(frozen=True)
class Capability:
    """Stable capability identity in the Varden namespace."""

    name: str
    kind: CapabilityKind = CapabilityKind.CONFIRMED
    sensitivity: int = 0  # 0..100 structural weight, not an opaque risk score
    mutating: bool = False
    reversible: str = "unknown"  # reversible | conditionally_reversible | irreversible | unknown
    domain: str = ""
    evidence: CapabilityEvidence = CapabilityEvidence.OBSERVED
    grant_source: str | None = None  # resource/capability id that granted this
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", canonicalize_capability_name(self.name))
        if not self.domain:
            object.__setattr__(self, "domain", capability_domain(self.name))
        # Potential evidence forces potential kind.
        if self.evidence == CapabilityEvidence.POTENTIAL:
            object.__setattr__(self, "kind", CapabilityKind.POTENTIAL)

    @property
    def node_id(self) -> str:
        prefix = "cap.potential" if self.kind == CapabilityKind.POTENTIAL else "cap"
        return f"{prefix}:{self.name}"

    def as_potential(self) -> Capability:
        return Capability(
            name=self.name,
            kind=CapabilityKind.POTENTIAL,
            sensitivity=self.sensitivity,
            mutating=self.mutating,
            reversible=self.reversible,
            domain=self.domain,
            evidence=CapabilityEvidence.POTENTIAL,
            grant_source=self.grant_source,
            metadata=dict(self.metadata),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "sensitivity": self.sensitivity,
            "mutating": self.mutating,
            "reversible": self.reversible,
            "domain": self.domain,
            "evidence": self.evidence.value,
            "grant_source": self.grant_source,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        kind = CapabilityKind(str(data.get("kind") or "confirmed"))
        evidence = CapabilityEvidence(str(data.get("evidence") or "observed"))
        return cls(
            name=str(data.get("name") or ""),
            kind=kind,
            sensitivity=int(data.get("sensitivity") or 0),
            mutating=bool(data.get("mutating")),
            reversible=str(data.get("reversible") or "unknown"),
            domain=str(data.get("domain") or ""),
            evidence=evidence,
            grant_source=data.get("grant_source"),
            metadata=dict(data.get("metadata") or {}),
        )


def canonicalize_capability_name(name: str) -> str:
    text = str(name or "").strip().lower()
    # Reject path separators / control chars that could poison graph ids.
    for ch in ("/", "\\", "\0", "\n", "\r", "\t", " "):
        text = text.replace(ch, ".")
    while ".." in text:
        text = text.replace("..", ".")
    return text.strip(".")


def capability_domain(name: str) -> str:
    parts = canonicalize_capability_name(name).split(".")
    return parts[0] if parts and parts[0] else "unknown"


def capability_parents(name: str) -> list[str]:
    """Return parent prefixes from most specific parent to root."""
    parts = canonicalize_capability_name(name).split(".")
    if len(parts) <= 1:
        return []
    out: list[str] = []
    for i in range(len(parts) - 1, 0, -1):
        out.append(".".join(parts[:i]))
    return out


# Evidence-driven grant catalogue: credential class → potential child capabilities.
# Conservative: reading AWS credentials does NOT confirm IAM modify.
_CREDENTIAL_GRANTS: dict[str, list[tuple[str, int, bool, str]]] = {
    # (name, sensitivity, mutating, reversible)
    "credential.aws": [
        ("aws.s3.read", 55, False, "reversible"),
        ("aws.s3.write", 70, True, "conditionally_reversible"),
        ("aws.ec2.read", 55, False, "reversible"),
        ("aws.ec2.modify", 80, True, "conditionally_reversible"),
        ("aws.iam.read", 65, False, "reversible"),
        ("aws.iam.modify", 95, True, "irreversible"),
        ("http.write.external", 60, True, "irreversible"),
    ],
    "credential.github": [
        ("git.read", 40, False, "reversible"),
        ("git.write", 60, True, "conditionally_reversible"),
        ("git.push", 75, True, "conditionally_reversible"),
        ("http.write.external", 60, True, "irreversible"),
    ],
    "credential.database": [
        ("database.read", 50, False, "reversible"),
        ("database.write", 70, True, "conditionally_reversible"),
        ("database.admin", 90, True, "irreversible"),
    ],
    "credential.ssh": [
        ("subprocess.execute.privileged", 85, True, "irreversible"),
        ("http.write.external", 60, True, "irreversible"),
    ],
}


# Capability implication edges (capability enables capability) — conservative.
_CAPABILITY_ENABLES: dict[str, list[str]] = {
    "subprocess.execute.local": ["http.write.external", "filesystem.write.workspace"],
    "subprocess.execute.privileged": [
        "http.write.external",
        "filesystem.write.external",
        "cloud.destroy",
    ],
    "credential.aws": ["aws.s3.read", "aws.s3.write", "http.write.external"],
    "aws.iam.modify": ["aws.s3.write", "aws.ec2.modify", "cloud.destroy"],
    "mcp.invoke": [],  # specialised per-tool elsewhere
}


def potential_grants_for_credential(credential_cap: str) -> list[Capability]:
    """Return *potential* capabilities granted by a credential class."""
    key = canonicalize_capability_name(credential_cap)
    rows = _CREDENTIAL_GRANTS.get(key, [])
    # Also try parent prefixes.
    if not rows:
        for parent in capability_parents(key):
            if parent in _CREDENTIAL_GRANTS:
                rows = _CREDENTIAL_GRANTS[parent]
                break
    out: list[Capability] = []
    for name, sens, mutating, reversible in rows:
        out.append(
            Capability(
                name=name,
                kind=CapabilityKind.POTENTIAL,
                sensitivity=sens,
                mutating=mutating,
                reversible=reversible,
                evidence=CapabilityEvidence.POTENTIAL,
                grant_source=key,
            )
        )
    return out


def enables_capabilities(capability_name: str) -> list[str]:
    name = canonicalize_capability_name(capability_name)
    found = list(_CAPABILITY_ENABLES.get(name, []))
    for parent in capability_parents(name):
        found.extend(_CAPABILITY_ENABLES.get(parent, []))
    # Deduplicate preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def known_capability_catalog() -> list[str]:
    """Stable list of well-known capability names for docs/tests."""
    base = [
        "filesystem.read.workspace",
        "filesystem.read.external",
        "filesystem.read.secret",
        "filesystem.write.workspace",
        "filesystem.write.external",
        "subprocess.execute.local",
        "subprocess.execute.privileged",
        "http.read.external",
        "http.write.external",
        "git.read",
        "git.write",
        "git.push",
        "credential.aws",
        "credential.github",
        "credential.database",
        "credential.ssh",
        "aws.s3.read",
        "aws.s3.write",
        "aws.ec2.read",
        "aws.ec2.modify",
        "aws.iam.read",
        "aws.iam.modify",
        "database.read",
        "database.write",
        "database.admin",
        "cloud.deploy",
        "cloud.destroy",
        "mcp.invoke",
    ]
    return sorted(set(base))


def merge_capability_sets(a: Iterable[Capability], b: Iterable[Capability]) -> dict[str, Capability]:
    """Merge by name; confirmed wins over potential; higher sensitivity wins ties."""
    out: dict[str, Capability] = {}
    for cap in list(a) + list(b):
        existing = out.get(cap.name)
        if existing is None:
            out[cap.name] = cap
            continue
        if existing.kind == CapabilityKind.CONFIRMED and cap.kind == CapabilityKind.POTENTIAL:
            continue
        if cap.kind == CapabilityKind.CONFIRMED and existing.kind == CapabilityKind.POTENTIAL:
            out[cap.name] = cap
            continue
        if cap.sensitivity > existing.sensitivity:
            out[cap.name] = cap
    return out
