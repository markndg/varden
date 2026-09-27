"""Session-level AuthorityState."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .capability import Capability, CapabilityKind, merge_capability_sets
from .graph import CapabilityGraph
from .resource import Resource, Sensitivity


@dataclass
class AuthorityTransitionRecord:
    timestamp: float
    action_summary: str
    added_capabilities: list[str]
    added_resources: list[str]
    added_sinks: list[str]
    irreversible: bool = False
    event_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "action_summary": self.action_summary,
            "added_capabilities": list(self.added_capabilities),
            "added_resources": list(self.added_resources),
            "added_sinks": list(self.added_sinks),
            "irreversible": self.irreversible,
            "event_ref": self.event_ref,
        }


@dataclass
class AuthorityState:
    """Deterministic session security state S(t)."""

    session_key: str
    graph: CapabilityGraph
    capabilities: dict[str, Capability] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    provenance_refs: list[str] = field(default_factory=list)
    approvals: list[dict[str, Any]] = field(default_factory=list)
    irreversible_actions: list[str] = field(default_factory=list)
    delegated_authority: list[str] = field(default_factory=list)
    history: list[AuthorityTransitionRecord] = field(default_factory=list)
    initial_capability_names: set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    policy_context: dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def snapshot_capability_names(self, *, kind: CapabilityKind | None = None) -> set[str]:
        with self._lock:
            if kind is None:
                return set(self.capabilities.keys())
            return {n for n, c in self.capabilities.items() if c.kind == kind}

    def confirmed_capabilities(self) -> list[Capability]:
        with self._lock:
            return [c for c in self.capabilities.values() if c.kind == CapabilityKind.CONFIRMED]

    def potential_capabilities(self) -> list[Capability]:
        with self._lock:
            return [c for c in self.capabilities.values() if c.kind == CapabilityKind.POTENTIAL]

    def sensitive_resources(self) -> list[Resource]:
        with self._lock:
            return [
                r
                for r in self.resources.values()
                if r.sensitivity in {Sensitivity.SENSITIVE, Sensitivity.SECRET, Sensitivity.CREDENTIAL}
            ]

    def external_sinks(self) -> list[Resource]:
        with self._lock:
            return [
                r
                for r in self.resources.values()
                if r.external and (bool((r.metadata or {}).get("write")) or bool((r.metadata or {}).get("sink")))
            ]

    def add_capability(self, cap: Capability) -> bool:
        with self._lock:
            merged = merge_capability_sets(self.capabilities.values(), [cap])
            before = self.capabilities.get(cap.name)
            self.capabilities = merged
            self.updated_at = time.time()
            after = self.capabilities.get(cap.name)
            return before != after

    def add_resource(self, resource: Resource) -> bool:
        with self._lock:
            existing = self.resources.get(resource.node_id)
            if existing is not None:
                # Upgrade sensitivity / trust conservatively (min trust, max sensitivity).
                return False
            self.resources[resource.node_id] = resource
            self.updated_at = time.time()
            return True

    def record_transition(self, record: AuthorityTransitionRecord, *, max_history: int = 256) -> None:
        with self._lock:
            self.history.append(record)
            if len(self.history) > max_history:
                self.history = self.history[-max_history:]
            self.updated_at = time.time()

    def mark_initial(self) -> None:
        with self._lock:
            self.initial_capability_names = set(self.capabilities.keys())

    def acquired_capabilities(self) -> list[Capability]:
        with self._lock:
            return [c for n, c in self.capabilities.items() if n not in self.initial_capability_names]

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "session_key": self.session_key,
                "capabilities": {k: v.to_dict() for k, v in sorted(self.capabilities.items())},
                "resources": {k: v.to_dict() for k, v in sorted(self.resources.items())},
                "provenance_refs": list(self.provenance_refs),
                "approvals": list(self.approvals),
                "irreversible_actions": list(self.irreversible_actions),
                "delegated_authority": list(self.delegated_authority),
                "history": [h.to_dict() for h in self.history],
                "initial_capability_names": sorted(self.initial_capability_names),
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "policy_context": dict(self.policy_context),
                "graph": self.graph.to_dict(),
            }
