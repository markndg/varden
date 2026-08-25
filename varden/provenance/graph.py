"""Bounded causal / influence graph for provenance ancestry.

Uses IDs rather than embedding payloads. Traversal is depth-bounded and
cycle-safe so policy evaluation cannot become unbounded.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable

from .models import EDGE_TYPES, NODE_TYPES, GraphEdge, GraphNode, new_id

DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_NODES = 256


class ProvenanceGraph:
    def __init__(self, *, max_depth: int = DEFAULT_MAX_DEPTH, max_nodes: int = DEFAULT_MAX_NODES) -> None:
        self.max_depth = max(1, int(max_depth))
        self.max_nodes = max(1, int(max_nodes))
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._out: dict[str, list[GraphEdge]] = defaultdict(list)
        self._in: dict[str, list[GraphEdge]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> GraphNode:
        if node.node_type not in NODE_TYPES:
            node.node_type = "observation"
        self.nodes[node.node_id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        if edge.edge_type not in EDGE_TYPES:
            edge.edge_type = "influenced_by"
        self.edges.append(edge)
        self._out[edge.from_node].append(edge)
        self._in[edge.to_node].append(edge)
        return edge

    def link(
        self,
        from_node: str,
        to_node: str,
        edge_type: str,
        *,
        trace_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> GraphEdge:
        return self.add_edge(
            GraphEdge(
                edge_id=new_id("edge"),
                edge_type=edge_type,
                from_node=from_node,
                to_node=to_node,
                trace_id=trace_id,
                metadata=dict(metadata or {}),
            )
        )

    def ancestors(
        self,
        node_id: str,
        *,
        max_depth: int | None = None,
        max_nodes: int | None = None,
        edge_types: Iterable[str] | None = None,
    ) -> list[tuple[GraphNode, int, str]]:
        """Bounded BFS over incoming edges. Returns (node, depth, via_edge_type).

        Both depth and absolute node visit counts are capped so wide fan-in
        cannot turn policy evaluation into a DoS.
        """
        limit = self.max_depth if max_depth is None else max(1, int(max_depth))
        node_cap = self.max_nodes if max_nodes is None else max(1, int(max_nodes))
        # Never exceed the graph's configured caps even if a caller asks for more.
        limit = min(limit, self.max_depth)
        node_cap = min(node_cap, self.max_nodes)
        allowed = set(edge_types) if edge_types else None
        seen: set[str] = {node_id}
        out: list[tuple[GraphNode, int, str]] = []
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= limit:
                continue
            for edge in self._in.get(current, []):
                if len(out) >= node_cap:
                    return out
                if allowed is not None and edge.edge_type not in allowed:
                    continue
                parent_id = edge.from_node
                if parent_id in seen:
                    continue
                seen.add(parent_id)
                parent = self.nodes.get(parent_id)
                if parent is None:
                    continue
                out.append((parent, depth + 1, edge.edge_type))
                queue.append((parent_id, depth + 1))
        return out

    def path_labels(self, node_id: str, *, max_depth: int | None = None) -> list[str]:
        """Compact attack-path labels from root ancestors to the node."""
        chain = self.ancestors(node_id, max_depth=max_depth)
        # ancestors returns nearest-first; reverse for root→leaf narrative
        labels = []
        for node, depth, _via in reversed(chain):
            trust = (node.trust_level or "unknown").upper()
            labels.append(f"[{trust}] {node.label or node.node_type}")
        tip = self.nodes.get(node_id)
        if tip:
            labels.append(f"[{(tip.trust_level or 'unknown').upper()}] {tip.label or tip.node_type}")
        return labels

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "max_depth": self.max_depth,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, *, max_depth: int = DEFAULT_MAX_DEPTH) -> "ProvenanceGraph":
        graph = cls(max_depth=max_depth)
        data = data or {}
        for raw in data.get("nodes") or []:
            graph.add_node(GraphNode(**{k: raw[k] for k in GraphNode.__dataclass_fields__ if k in raw}))
        for raw in data.get("edges") or []:
            graph.add_edge(GraphEdge(**{k: raw[k] for k in GraphEdge.__dataclass_fields__ if k in raw}))
        return graph
