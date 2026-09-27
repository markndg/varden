"""Bounded reachability over the capability graph."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode

# Default expansion budget for zero-cost / alias-compressed walks.
DEFAULT_MAX_VISITS = 4096

_PRIVILEGED_TOKENS = (
    "aws.",
    "cloud.",
    "database.admin",
    "subprocess.execute.privileged",
    "http.write.external",
    "iam.modify",
    "cloud.destroy",
    "aws.ec2.modify",
    "aws.iam.modify",
    "aws.s3.write",
)


@dataclass(frozen=True)
class ReachabilityPath:
    nodes: tuple[str, ...]
    edges: tuple[str, ...]  # edge ids
    evidence: tuple[str, ...]
    labels: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        return max(0, len(self.nodes) - 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "edges": list(self.edges),
            "evidence": list(self.evidence),
            "labels": list(self.labels),
            "length": self.length,
            "display": " -> ".join(self.labels or self.nodes),
        }


@dataclass
class ReachabilityResult:
    reachable: bool
    paths: list[ReachabilityPath] = field(default_factory=list)
    max_depth: int = 0
    truncated: bool = False
    analysis_incomplete: bool = False
    incompleteness_reason: str | None = None
    visited_nodes: int = 0
    visited_edges: int = 0
    visits: int = 0  # queue expansions (may exceed unique visited_nodes)

    def shortest(self) -> ReachabilityPath | None:
        if not self.paths:
            return None
        return min(self.paths, key=lambda p: p.length)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "max_depth": self.max_depth,
            "truncated": self.truncated,
            "analysis_incomplete": self.analysis_incomplete,
            "incompleteness_reason": self.incompleteness_reason,
            "visited_nodes": self.visited_nodes,
            "visited_edges": self.visited_edges,
            "visits": self.visits,
            "paths": [p.to_dict() for p in self.paths],
            "shortest": self.shortest().to_dict() if self.shortest() else None,
            # Never imply "safe" when incomplete.
            "safe_conclusion": (not self.analysis_incomplete) and (not self.truncated) and (not self.reachable),
        }


def node_is_privileged(node_id: str, graph: CapabilityGraph) -> bool:
    """Privileged / high-authority capability tokens used by hazardous patterns."""
    node = graph.get_node(node_id)
    if node is None:
        return False
    if any(tok in node_id for tok in _PRIVILEGED_TOKENS):
        return True
    label = str(node.label or "")
    return any(tok in label for tok in _PRIVILEGED_TOKENS)


def authority_relevant_node(node_id: str, graph: CapabilityGraph) -> bool:
    """Nodes that consume hazardous-analysis depth budget.

    Intermediate alias / representation / benign capability wiring does **not**
    count. This prevents attacker-controlled topology from indefinitely pushing
    a sink just beyond raw hop ``max_depth`` (horizon camping).
    """
    return (
        node_is_untrusted(node_id, graph)
        or node_is_credential(node_id, graph)
        or node_is_sensitive(node_id, graph)
        or node_is_sink(node_id, graph)
        or node_is_privileged(node_id, graph)
        or _node_is_mcp(node_id, graph)
    )


def _node_is_mcp(node_id: str, graph: CapabilityGraph) -> bool:
    node = graph.get_node(node_id)
    if node is None:
        return False
    return node.node_type in {"mcp_server", "mcp_tool"} or node_id.startswith("res:mcp_")


def authority_hop_cost(_edge: GraphEdge, dst: GraphNode, graph: CapabilityGraph) -> int:
    """Hazardous-analysis hop cost.

    Cost 1: arrival at an authority-relevant node (real security transition).
    Cost 0: representational indirection / alias / authority-neutral wiring —
    these do **not** consume the authority-depth budget. Computational work is
    still bounded by ``max_visits``, graph limits, cycles, and ``max_paths``.
    Do not mark arbitrary business-domain nodes as zero-cost.
    """
    if (dst.metadata or {}).get("authority_neutral") or (_edge.metadata or {}).get("authority_neutral"):
        return 0
    return 1 if authority_relevant_node(dst.node_id, graph) else 0


def bounded_reachability(
    graph: CapabilityGraph,
    sources: Iterable[str],
    *,
    max_depth: int = 3,
    predicate: Callable[[str], bool] | None = None,
    target: str | None = None,
    kinds: Iterable[EdgeKind] | None = None,
    include_potential: bool = True,
    max_paths: int = 16,
    hop_cost: Callable[[GraphEdge, GraphNode], int] | None = None,
    max_visits: int = DEFAULT_MAX_VISITS,
) -> ReachabilityResult:
    """BFS reachability bounded by ``max_depth``.

    IMPORTANT — two different distance semantics exist in Predictive Authority:

    * **This function defaults to ordinary topological graph distance**: every
      traversed edge consumes one hop (``hop_cost`` defaults to 1). That answers
      a *graph* question for general consumers.

    * **Predictive hazardous-path analysis** intentionally passes an
      authority-relevant ``hop_cost`` (see ``authority_hop_cost`` /
      ``hazardous._hazardous_reachability``). Pure representational aliases do
      not consume the security horizon. That answers a *security* question.

    Do **not** replace one with the other. Using raw topology for hazardous
    analysis previously allowed horizon-camping attacks through alias padding.
    Using authority-relevant distance for general graph APIs would silently
    change non-security consumers.

    Returns concrete paths (not just boolean). Cycles are skipped.
    Potential edges are included only when ``include_potential`` is True.
    Timing is not part of the security result.
    """
    max_depth = max(0, int(max_depth))
    source_list = [s for s in sources if graph.get_node(s) is not None]
    if not source_list:
        return ReachabilityResult(reachable=False, max_depth=max_depth)

    paths: list[ReachabilityPath] = []
    truncated = False
    incompleteness_reason: str | None = None
    cost_fn = hop_cost or (lambda _e, _d: 1)

    # State: (node, depth, path_nodes, path_edges, path_evidence, path_labels)
    queue: deque[tuple[str, int, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = deque()
    for src in sorted(set(source_list)):
        node = graph.get_node(src)
        label = (node.label if node and node.label else src,)
        queue.append((src, 0, (src,), (), (), label))

    visited_at_depth: dict[str, int] = {}
    expansions = 0
    visited_edge_ids: set[str] = set()

    while queue:
        node_id, depth, path_nodes, path_edges, path_evidence, path_labels = queue.popleft()
        expansions += 1
        if expansions > max_visits:
            truncated = True
            incompleteness_reason = "MAX_VISITS"
            break
        prev_best = visited_at_depth.get(node_id)
        if prev_best is not None and prev_best < depth:
            continue
        visited_at_depth[node_id] = depth

        matches = False
        if target is not None and node_id == target:
            matches = True
        elif predicate is not None and predicate(node_id):
            matches = True
        if matches and depth > 0:
            paths.append(
                ReachabilityPath(
                    nodes=path_nodes,
                    edges=path_edges,
                    evidence=path_evidence,
                    labels=path_labels,
                )
            )
            if len(paths) >= max_paths:
                truncated = True
                incompleteness_reason = incompleteness_reason or "MAX_PATHS"
                break

        # At max authority depth we may still walk zero-cost (alias) edges.
        for edge, dst in graph.successors(node_id, kinds=kinds):
            visited_edge_ids.add(edge.edge_id)
            ev_kind = edge.evidence.kind.value if hasattr(edge.evidence, "kind") else str(edge.evidence)
            if not include_potential and ev_kind in {"potential", "untrusted_declared"}:
                continue
            if not include_potential and not dst.confirmed:
                continue
            # Skip edges that do not carry sensitive flow (post-sanitisation safe produce).
            if (edge.metadata or {}).get("sensitive_flow_terminated"):
                continue
            if dst.node_id in path_nodes:
                continue  # cycle
            step = int(cost_fn(edge, dst))
            if step < 0:
                step = 0
            new_depth = depth + step
            if new_depth > max_depth:
                continue
            # Raw default: depth>=max means no further expansion of cost>=1; zero-cost
            # still allowed so alias chains beyond the last authority hop remain visible.
            if depth >= max_depth and step > 0:
                continue
            dst_label = dst.label or dst.node_id
            queue.append(
                (
                    dst.node_id,
                    new_depth,
                    path_nodes + (dst.node_id,),
                    path_edges + (edge.edge_id,),
                    path_evidence + (ev_kind,),
                    path_labels + (dst_label,),
                )
            )

    # Deterministic path order: shorter first, then lexicographic display.
    paths.sort(key=lambda p: (p.length, p.to_dict()["display"], p.nodes))
    incomplete = bool(graph.truncated) or truncated
    reason = graph.truncation_reason if graph.truncated else None
    if truncated:
        reason = incompleteness_reason or reason or "MAX_PATHS"
    return ReachabilityResult(
        reachable=bool(paths),
        paths=paths,
        max_depth=max_depth,
        truncated=truncated or graph.truncated,
        analysis_incomplete=incomplete,
        incompleteness_reason=reason,
        visited_nodes=len(visited_at_depth),
        visited_edges=len(visited_edge_ids),
        visits=expansions,
    )


def node_is_sink(node_id: str, graph: CapabilityGraph) -> bool:
    node = graph.get_node(node_id)
    if node is None:
        return False
    if node.node_type in {"sink", "network_sink"}:
        return True
    meta = node.metadata or {}
    return bool(meta.get("external_sink") or meta.get("sink"))


def node_is_credential(node_id: str, graph: CapabilityGraph) -> bool:
    node = graph.get_node(node_id)
    if node is None:
        return False
    if node.node_type == "credential":
        return True
    if node_id.startswith("cap:") and "credential." in node_id:
        return True
    return bool((node.metadata or {}).get("credential"))


def node_is_sensitive(node_id: str, graph: CapabilityGraph) -> bool:
    node = graph.get_node(node_id)
    if node is None:
        return False
    sens = str((node.metadata or {}).get("sensitivity") or "")
    return sens in {"sensitive", "secret", "credential"} or node_is_credential(node_id, graph)


def node_is_untrusted(node_id: str, graph: CapabilityGraph) -> bool:
    node = graph.get_node(node_id)
    if node is None:
        return False
    trust = str((node.metadata or {}).get("trust_level") or "")
    return trust in {"untrusted", "hostile"} or node.node_type in {"untrusted_content", "provenance"}
