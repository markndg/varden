"""Lightweight directed capability/resource graph.

Optimized for session-scoped runtime use — not a general graph database.
Deterministic node/edge ordering. Distinguishes potential vs confirmed.
Every edge carries first-class evidence answering why it exists.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .evidence import (
    AuthorityLifecycle,
    EvidenceKind,
    EvidenceRecord,
    make_evidence,
    normalize_evidence_kind,
)


class EdgeKind(str, Enum):
    GRANTS = "grants"
    MAY_GRANT = "may_grant"
    ENABLES = "enables"
    REACHES = "reaches"
    INTRODUCES = "introduces"
    INFLUENCES = "influences"
    ENABLES_ACTION = "enables_action"
    FLOWS_TO = "flows_to"
    SANITISED_BY = "sanitised_by"
    APPROVED_BY = "approved_by"
    BLOCKED_BY = "blocked_by"
    READS = "reads"
    PRODUCES = "produces"
    INVOKES = "invokes"
    WRITES_TO = "writes_to"


# Backward-compatible alias used by older call sites / tests.
class EdgeEvidence(str, Enum):
    OBSERVED = "runtime_observed"
    INFERRED = "interceptor_derived"
    CONFIGURED = "varden_configured"
    RUNTIME_DISCOVERED = "trusted_discovery"
    APPROVAL_GRANTED = "approval_granted"
    POTENTIAL = "potential"
    UNTRUSTED_DECLARED = "untrusted_declared"


@dataclass(frozen=True)
class GraphEdge:
    src: str
    dst: str
    kind: EdgeKind
    evidence: EvidenceRecord = field(default_factory=lambda: make_evidence(EvidenceKind.POTENTIAL))
    label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Accept legacy EdgeEvidence / str for evidence field.
        ev = self.evidence
        if isinstance(ev, EdgeEvidence):
            object.__setattr__(
                self,
                "evidence",
                make_evidence(ev.value, lifecycle=AuthorityLifecycle.POTENTIAL if ev == EdgeEvidence.POTENTIAL else AuthorityLifecycle.CONFIRMED),
            )
        elif isinstance(ev, str):
            object.__setattr__(self, "evidence", make_evidence(ev))
        elif isinstance(ev, dict):
            object.__setattr__(self, "evidence", EvidenceRecord.from_dict(ev))

    @property
    def edge_id(self) -> str:
        return f"{self.src}|{self.kind.value}|{self.dst}|{self.evidence.kind.value}"

    @property
    def lifecycle(self) -> AuthorityLifecycle:
        return self.evidence.lifecycle

    @property
    def still_valid(self) -> bool:
        return self.evidence.still_valid and self.lifecycle not in {
            AuthorityLifecycle.DISPROVEN,
            AuthorityLifecycle.REVOKED,
            AuthorityLifecycle.EXPIRED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "src": self.src,
            "dst": self.dst,
            "source": self.src,
            "target": self.dst,
            "kind": self.kind.value,
            "relationship": self.kind.value,
            "evidence": self.evidence.to_dict(),
            "evidenceKind": self.evidence.kind.value,
            "state": self.lifecycle.value,
            "label": self.label,
            "metadata": dict(self.metadata),
            "still_valid": self.still_valid,
        }


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str = ""
    confirmed: bool = True
    lifecycle: AuthorityLifecycle = AuthorityLifecycle.CONFIRMED
    metadata: dict[str, Any] = field(default_factory=dict)
    first_observed_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if isinstance(self.lifecycle, str):
            try:
                self.lifecycle = AuthorityLifecycle(self.lifecycle)
            except ValueError:
                self.lifecycle = AuthorityLifecycle.POTENTIAL if not self.confirmed else AuthorityLifecycle.CONFIRMED
        if not self.confirmed and self.lifecycle == AuthorityLifecycle.CONFIRMED:
            self.lifecycle = AuthorityLifecycle.POTENTIAL

    @property
    def active(self) -> bool:
        return self.lifecycle not in {
            AuthorityLifecycle.DISPROVEN,
            AuthorityLifecycle.REVOKED,
            AuthorityLifecycle.EXPIRED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "node_id": self.node_id,
            "node_type": self.node_type,
            "kind": self.node_type,
            "label": self.label,
            "confirmed": self.confirmed and self.lifecycle == AuthorityLifecycle.CONFIRMED,
            "state": self.lifecycle.value,
            "lifecycle": self.lifecycle.value,
            "observed": bool((self.metadata or {}).get("observed", True)),
            "sensitive": bool((self.metadata or {}).get("sensitive") or (self.metadata or {}).get("credential")),
            "trustDomain": (self.metadata or {}).get("authority_domain") or (self.metadata or {}).get("trust_domain") or "",
            "metadata": dict(self.metadata),
            "first_observed_at": self.first_observed_at,
        }


class CapabilityGraph:
    """Thread-safe directed multigraph with soft size bounds."""

    SCHEMA_VERSION = 2

    def __init__(self, *, max_nodes: int = 2048, max_edges: int = 8192) -> None:
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._out: dict[str, list[str]] = {}
        self._in: dict[str, list[str]] = {}
        self._lock = threading.RLock()
        self._truncated = False
        self._truncation_reason: str | None = None
        self._version = 0
        # Reachability memo keyed by (version, frozenset sources, depth, target/pred id)
        self._reach_cache: dict[tuple, Any] = {}

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._out.clear()
            self._in.clear()
            self._truncated = False
            self._truncation_reason = None
            self._reach_cache.clear()
            self._version += 1

    def invalidate_caches(self) -> None:
        with self._lock:
            self._reach_cache.clear()
            self._version += 1

    @property
    def version(self) -> int:
        return self._version

    @property
    def truncated(self) -> bool:
        return self._truncated

    @property
    def truncation_reason(self) -> str | None:
        return self._truncation_reason

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def add_node(self, node: GraphNode) -> bool:
        with self._lock:
            if node.node_id in self._nodes:
                existing = self._nodes[node.node_id]
                if node.confirmed and not existing.confirmed and existing.lifecycle == AuthorityLifecycle.POTENTIAL:
                    existing.confirmed = True
                    existing.lifecycle = AuthorityLifecycle.CONFIRMED
                    self.invalidate_caches()
                return True
            if len(self._nodes) >= self.max_nodes:
                self._truncated = True
                self._truncation_reason = "MAX_NODES"
                self.invalidate_caches()
                return False
            self._nodes[node.node_id] = node
            self._out.setdefault(node.node_id, [])
            self._in.setdefault(node.node_id, [])
            self.invalidate_caches()
            return True

    def add_edge(self, edge: GraphEdge) -> bool:
        with self._lock:
            # Untrusted declarations cannot create confirmed edges.
            if edge.evidence.kind == EvidenceKind.UNTRUSTED_DECLARED:
                if edge.evidence.lifecycle == AuthorityLifecycle.CONFIRMED:
                    edge = GraphEdge(
                        src=edge.src,
                        dst=edge.dst,
                        kind=edge.kind if edge.kind != EdgeKind.GRANTS else EdgeKind.MAY_GRANT,
                        evidence=make_evidence(
                            EvidenceKind.UNTRUSTED_DECLARED,
                            source=edge.evidence.source,
                            assertion_actor=edge.evidence.assertion_actor,
                            provenance_ref=edge.evidence.provenance_ref,
                            trust_domain=edge.evidence.trust_domain,
                            lifecycle=AuthorityLifecycle.POTENTIAL,
                            description=edge.evidence.description,
                        ),
                        label=edge.label or "untrusted_claim",
                        metadata=dict(edge.metadata),
                    )
            if edge.edge_id in self._edges:
                return True
            if edge.src not in self._nodes or edge.dst not in self._nodes:
                return False
            if len(self._edges) >= self.max_edges:
                self._truncated = True
                self._truncation_reason = "MAX_EDGES"
                self.invalidate_caches()
                return False
            self._edges[edge.edge_id] = edge
            self._out.setdefault(edge.src, []).append(edge.edge_id)
            self._in.setdefault(edge.dst, []).append(edge.edge_id)
            self._out[edge.src].sort()
            self._in[edge.dst].sort()
            self.invalidate_caches()
            return True

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge | None:
        return self._edges.get(edge_id)

    def successors(
        self,
        node_id: str,
        *,
        kinds: Iterable[EdgeKind] | None = None,
        include_invalid: bool = False,
        traverse_sanitisation: bool = False,
    ) -> list[tuple[GraphEdge, GraphNode]]:
        kind_set = {k.value if isinstance(k, EdgeKind) else str(k) for k in kinds} if kinds is not None else None
        out: list[tuple[GraphEdge, GraphNode]] = []
        for eid in self._out.get(node_id, []):
            edge = self._edges[eid]
            if kind_set is not None and edge.kind.value not in kind_set:
                continue
            if not include_invalid and not edge.still_valid:
                continue
            # Sanitisation boundary terminates sensitive flow unless explicitly traversed.
            if edge.kind == EdgeKind.SANITISED_BY and not traverse_sanitisation:
                continue
            dst = self._nodes.get(edge.dst)
            if dst is None or (not include_invalid and not dst.active):
                continue
            # Nodes marked as sanitisation boundaries stop sensitive traversal.
            if (dst.metadata or {}).get("sanitisation_boundary") and not traverse_sanitisation:
                continue
            out.append((edge, dst))
        return out

    def nodes(self) -> list[GraphNode]:
        return [self._nodes[k] for k in sorted(self._nodes.keys())]

    def edges(self) -> list[GraphEdge]:
        return [self._edges[k] for k in sorted(self._edges.keys())]

    def remove_edge(self, edge_id: str) -> bool:
        with self._lock:
            edge = self._edges.pop(edge_id, None)
            if edge is None:
                return False
            if edge_id in self._out.get(edge.src, []):
                self._out[edge.src].remove(edge_id)
            if edge_id in self._in.get(edge.dst, []):
                self._in[edge.dst].remove(edge_id)
            self.invalidate_caches()
            return True

    def set_edge_lifecycle(self, edge_id: str, lifecycle: AuthorityLifecycle, *, still_valid: bool | None = None) -> bool:
        with self._lock:
            edge = self._edges.get(edge_id)
            if edge is None:
                return False
            ev = edge.evidence
            new_ev = EvidenceRecord(
                kind=ev.kind,
                source=ev.source,
                assertion_actor=ev.assertion_actor,
                provenance_ref=ev.provenance_ref,
                trust_domain=ev.trust_domain,
                established_at=ev.established_at,
                last_validated_at=time.time(),
                still_valid=ev.still_valid if still_valid is None else still_valid,
                lifecycle=lifecycle,
                description=ev.description,
                metadata=dict(ev.metadata),
            )
            if lifecycle in {AuthorityLifecycle.DISPROVEN, AuthorityLifecycle.REVOKED, AuthorityLifecycle.EXPIRED}:
                new_ev.still_valid = False
            replacement = GraphEdge(
                src=edge.src,
                dst=edge.dst,
                kind=edge.kind,
                evidence=new_ev,
                label=edge.label,
                metadata=dict(edge.metadata),
            )
            # Replace under same structural id if evidence kind unchanged.
            self._edges[edge_id] = replacement
            self.invalidate_caches()
            return True

    def set_node_lifecycle(self, node_id: str, lifecycle: AuthorityLifecycle) -> bool:
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return False
            node.lifecycle = lifecycle
            node.confirmed = lifecycle == AuthorityLifecycle.CONFIRMED
            self.invalidate_caches()
            return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "truncated": self._truncated,
            "truncation_reason": self._truncation_reason,
            "version": self._version,
            "nodes": [n.to_dict() for n in self.nodes()],
            "edges": [e.to_dict() for e in self.edges()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, max_nodes: int = 2048, max_edges: int = 8192) -> CapabilityGraph:
        g = cls(max_nodes=max_nodes, max_edges=max_edges)
        for nd in data.get("nodes") or []:
            g.add_node(
                GraphNode(
                    node_id=str(nd.get("node_id") or nd.get("id") or ""),
                    node_type=str(nd.get("node_type") or nd.get("kind") or "unknown"),
                    label=str(nd.get("label") or ""),
                    confirmed=bool(nd.get("confirmed", True)),
                    lifecycle=AuthorityLifecycle(str(nd.get("lifecycle") or nd.get("state") or ("confirmed" if nd.get("confirmed", True) else "potential"))),
                    metadata=dict(nd.get("metadata") or {}),
                )
            )
        for ed in data.get("edges") or []:
            ev_raw = ed.get("evidence")
            if isinstance(ev_raw, dict):
                evidence = EvidenceRecord.from_dict(ev_raw)
            else:
                evidence = make_evidence(ed.get("evidenceKind") or ed.get("evidence") or "potential")
            g.add_edge(
                GraphEdge(
                    src=str(ed.get("src") or ed.get("source") or ""),
                    dst=str(ed.get("dst") or ed.get("target") or ""),
                    kind=EdgeKind(str(ed.get("kind") or ed.get("relationship") or "flows_to")),
                    evidence=evidence,
                    label=str(ed.get("label") or ""),
                    metadata=dict(ed.get("metadata") or {}),
                )
            )
        if data.get("truncated"):
            g._truncated = True
            g._truncation_reason = data.get("truncation_reason") or "MAX_NODES"
        return g
