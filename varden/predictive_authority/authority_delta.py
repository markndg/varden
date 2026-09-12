"""AuthorityDelta — structural authority expansion, not opaque risk scores."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .capability import Capability, CapabilityKind
from .resource import Resource
from .reachability import ReachabilityPath
from .state import AuthorityState


@dataclass
class AuthorityDelta:
    """Canonical result: structural difference Authority(S_after) - Authority(S_before)."""

    added_capabilities: list[Capability] = field(default_factory=list)
    lost_capabilities: list[Capability] = field(default_factory=list)
    added_sensitive_resources: list[Resource] = field(default_factory=list)
    added_sinks: list[Resource] = field(default_factory=list)
    added_hazardous_paths: list[ReachabilityPath] = field(default_factory=list)
    added_irreversible_actions: list[str] = field(default_factory=list)
    added_privilege_domains: list[str] = field(default_factory=list)
    authority_expands: bool = False

    def confirmed_added(self) -> list[Capability]:
        return [c for c in self.added_capabilities if c.kind == CapabilityKind.CONFIRMED]

    def potential_added(self) -> list[Capability]:
        return [c for c in self.added_capabilities if c.kind == CapabilityKind.POTENTIAL]

    def structural_units(self) -> int:
        """Transparent numeric summary derived from structural graph expansion.

        Weights are documented and fixed — not a learned risk model:
          confirmed capability: sensitivity//10 (min 1)
          potential capability: max(1, sensitivity//20)
          sensitive resource: 2
          external sink: 3
          hazardous path: 5
          irreversible action: 4
          new privilege domain: 3
        """
        total = 0
        for cap in self.added_capabilities:
            if cap.kind == CapabilityKind.CONFIRMED:
                total += max(1, int(cap.sensitivity) // 10)
            else:
                total += max(1, int(cap.sensitivity) // 20)
        total += 2 * len(self.added_sensitive_resources)
        total += 3 * len(self.added_sinks)
        total += 5 * len(self.added_hazardous_paths)
        total += 4 * len(self.added_irreversible_actions)
        total += 3 * len(self.added_privilege_domains)
        return total

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_expands": self.authority_expands,
            "added_capabilities": [c.to_dict() for c in self.added_capabilities],
            "lost_capabilities": [c.to_dict() for c in self.lost_capabilities],
            "added_sensitive_resources": [r.to_dict() for r in self.added_sensitive_resources],
            "added_sinks": [r.to_dict() for r in self.added_sinks],
            "added_hazardous_paths": [p.to_dict() for p in self.added_hazardous_paths],
            "added_irreversible_actions": list(self.added_irreversible_actions),
            "added_privilege_domains": list(self.added_privilege_domains),
            "structural_units": self.structural_units(),
            "confirmed_added_count": len(self.confirmed_added()),
            "potential_added_count": len(self.potential_added()),
        }


def compute_authority_delta(
    before: AuthorityState,
    after: AuthorityState,
    *,
    hazardous_paths: list[ReachabilityPath] | None = None,
    irreversible: list[str] | None = None,
) -> AuthorityDelta:
    before_caps = {n: c for n, c in before.capabilities.items()}
    after_caps = {n: c for n, c in after.capabilities.items()}

    added: list[Capability] = []
    for name, cap in sorted(after_caps.items()):
        prev = before_caps.get(name)
        if prev is None:
            added.append(cap)
        elif prev.kind == CapabilityKind.POTENTIAL and cap.kind == CapabilityKind.CONFIRMED:
            added.append(cap)

    lost: list[Capability] = []
    for name, cap in sorted(before_caps.items()):
        if name not in after_caps:
            lost.append(cap)

    before_res = set(before.resources.keys())
    added_sensitive: list[Resource] = []
    added_sinks: list[Resource] = []
    for rid, res in sorted(after.resources.items()):
        if rid in before_res:
            continue
        if res.sensitivity.value in {"sensitive", "secret", "credential"}:
            added_sensitive.append(res)
        # Only mutating/external write destinations count as sinks for escalation.
        if res.external and (bool((res.metadata or {}).get("write")) or bool((res.metadata or {}).get("sink"))):
            added_sinks.append(res)

    before_domains = {c.domain for c in before.capabilities.values() if c.domain}
    after_domains = {c.domain for c in after.capabilities.values() if c.domain}
    new_domains = sorted(after_domains - before_domains)

    haz = list(hazardous_paths or [])
    irrev = list(irreversible or [])

    expands = bool(added or added_sensitive or added_sinks or haz or irrev or new_domains)

    return AuthorityDelta(
        added_capabilities=added,
        lost_capabilities=lost,
        added_sensitive_resources=added_sensitive,
        added_sinks=added_sinks,
        added_hazardous_paths=haz,
        added_irreversible_actions=irrev,
        added_privilege_domains=new_domains,
        authority_expands=expands,
    )
