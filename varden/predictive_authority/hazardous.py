"""Deterministic hazardous path detection predicates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .graph import CapabilityGraph
from .reachability import (
    ReachabilityPath,
    ReachabilityResult,
    authority_hop_cost,
    bounded_reachability,
    node_is_credential,
    node_is_sensitive,
    node_is_sink,
    node_is_untrusted,
)


def _hazardous_reachability(graph: CapabilityGraph, sources: list[str], *, max_depth: int, predicate) -> ReachabilityResult:
    """Bounded reachability for hazardous patterns (security question).

    IMPORTANT: uses authority-relevant distance via ``authority_hop_cost``, not
    raw topological hop count. See ``bounded_reachability`` docstring — do not
    collapse these two APIs. Alias padding must not defeat the security horizon,
    while computational bounds (``max_visits``, graph limits, cycles) still apply.
    """
    return bounded_reachability(
        graph,
        sources,
        max_depth=max_depth,
        predicate=predicate,
        include_potential=True,
        hop_cost=lambda edge, dst: authority_hop_cost(edge, dst, graph),
    )


@dataclass(frozen=True)
class HazardousPattern:
    name: str
    description: str
    find: Callable[[CapabilityGraph, int], ReachabilityResult]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description}


@dataclass
class HazardousFinding:
    pattern: str
    path: ReachabilityPath
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "description": self.description,
            "path": self.path.to_dict(),
        }


def _sources_matching(graph: CapabilityGraph, pred: Callable[[str], bool]) -> list[str]:
    return [n.node_id for n in graph.nodes() if pred(n.node_id)]


def _retain_bounds(result: ReachabilityResult, paths: list[ReachabilityPath]) -> ReachabilityResult:
    """Keep truncation / visit accounting when filtering hazardous paths."""
    return ReachabilityResult(
        reachable=bool(paths),
        paths=paths,
        max_depth=result.max_depth,
        truncated=result.truncated,
        analysis_incomplete=result.analysis_incomplete or result.truncated,
        incompleteness_reason=result.incompleteness_reason,
        visited_nodes=result.visited_nodes,
        visited_edges=result.visited_edges,
        visits=result.visits,
    )


def _find_untrusted_to_sensitive_to_sink(graph: CapabilityGraph, max_depth: int) -> ReachabilityResult:
    sources = _sources_matching(graph, lambda n: node_is_untrusted(n, graph))
    # Two-stage: untrusted -> sensitive, then sensitive -> sink within remaining depth.
    # For simplicity within bound: search untrusted -> sink and require a sensitive/credential midpoint.
    result = _hazardous_reachability(
        graph,
        sources,
        max_depth=max_depth,
        predicate=lambda n: node_is_sink(n, graph),
    )
    filtered: list[ReachabilityPath] = []
    for path in result.paths:
        has_mid = any(node_is_sensitive(n, graph) or node_is_credential(n, graph) for n in path.nodes[1:-1])
        if has_mid or any(node_is_credential(n, graph) for n in path.nodes):
            filtered.append(path)
    return _retain_bounds(result, filtered)


def _find_untrusted_to_credential_to_privileged(graph: CapabilityGraph, max_depth: int) -> ReachabilityResult:
    sources = _sources_matching(graph, lambda n: node_is_untrusted(n, graph))
    result = _hazardous_reachability(
        graph,
        sources,
        max_depth=max_depth,
        predicate=lambda n: (
            n.startswith("cap:")
            and any(
                tok in n
                for tok in (
                    "aws.",
                    "cloud.",
                    "database.admin",
                    "subprocess.execute.privileged",
                    "http.write.external",
                    "iam.modify",
                )
            )
        ),
    )
    filtered = [
        p
        for p in result.paths
        if any(node_is_credential(n, graph) or "credential." in n for n in p.nodes)
    ]
    return _retain_bounds(result, filtered)


def _find_sensitive_to_subprocess_to_network(graph: CapabilityGraph, max_depth: int) -> ReachabilityResult:
    sources = _sources_matching(graph, lambda n: node_is_sensitive(n, graph) or node_is_credential(n, graph))
    result = _hazardous_reachability(
        graph,
        sources,
        max_depth=max_depth,
        predicate=lambda n: node_is_sink(n, graph) or n.endswith("http.write.external") or "http.write" in n,
    )
    filtered = [
        p
        for p in result.paths
        if any("subprocess" in n or n.startswith("cap:subprocess") for n in p.nodes)
    ]
    return _retain_bounds(result, filtered)


def _find_cross_mcp_trust_domain(graph: CapabilityGraph, max_depth: int) -> ReachabilityResult:
    mcp_nodes = [n for n in graph.nodes() if n.node_type in {"mcp_server", "mcp_tool"} or n.node_id.startswith("res:mcp_")]
    if len(mcp_nodes) < 2:
        return ReachabilityResult(reachable=False, max_depth=max_depth)
    domains = {}
    for n in mcp_nodes:
        domains[n.node_id] = str((n.metadata or {}).get("authority_domain") or n.label or n.node_id)
    sources = [n.node_id for n in mcp_nodes]
    result = _hazardous_reachability(
        graph,
        sources,
        max_depth=max_depth,
        predicate=lambda nid: nid in domains,
    )
    filtered: list[ReachabilityPath] = []
    for path in result.paths:
        path_domains = {domains.get(n) for n in path.nodes if n in domains}
        path_domains.discard(None)
        if len(path_domains) >= 2:
            filtered.append(path)
    return _retain_bounds(result, filtered)


def _find_credential_to_cloud_mutation(graph: CapabilityGraph, max_depth: int) -> ReachabilityResult:
    sources = _sources_matching(graph, lambda n: node_is_credential(n, graph) or "credential." in n)
    return _hazardous_reachability(
        graph,
        sources,
        max_depth=max_depth,
        predicate=lambda n: any(
            tok in n
            for tok in ("cloud.destroy", "aws.ec2.modify", "aws.iam.modify", "aws.s3.write", "database.admin")
        ),
    )


DEFAULT_PATTERNS: list[HazardousPattern] = [
    HazardousPattern(
        name="untrusted_to_sensitive_to_external",
        description="untrusted_source -> sensitive_resource -> external_sink",
        find=_find_untrusted_to_sensitive_to_sink,
    ),
    HazardousPattern(
        name="untrusted_to_credential_to_privileged",
        description="untrusted_source -> credential -> privileged_action",
        find=_find_untrusted_to_credential_to_privileged,
    ),
    HazardousPattern(
        name="sensitive_to_subprocess_to_network",
        description="sensitive_resource -> subprocess -> external_network",
        find=_find_sensitive_to_subprocess_to_network,
    ),
    HazardousPattern(
        name="cross_mcp_trust_domain",
        description="one MCP trust domain -> authority acquisition -> second MCP trust domain",
        find=_find_cross_mcp_trust_domain,
    ),
    HazardousPattern(
        name="credential_to_cloud_mutation",
        description="credential acquisition -> high-authority cloud mutation",
        find=_find_credential_to_cloud_mutation,
    ),
]


@dataclass
class HazardousAnalysis:
    """Hazard findings plus search-completeness metadata."""

    findings: list[HazardousFinding] = field(default_factory=list)
    truncated: bool = False
    analysis_incomplete: bool = False
    incompleteness_reason: str | None = None
    visited_nodes: int = 0
    visited_edges: int = 0
    visits: int = 0
    paths_examined: int = 0

    @property
    def safe_conclusion(self) -> bool:
        return (not self.analysis_incomplete) and (not self.truncated) and (not self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "truncated": self.truncated,
            "analysis_incomplete": self.analysis_incomplete,
            "incompleteness_reason": self.incompleteness_reason,
            "visited_nodes": self.visited_nodes,
            "visited_edges": self.visited_edges,
            "visits": self.visits,
            "paths_examined": self.paths_examined,
            "hazard_found": bool(self.findings),
            "hazard_status": "PROVEN" if self.findings else ("NOT_OBSERVED" if self.analysis_incomplete or self.truncated else "ABSENT_IN_COMPLETE_SEARCH"),
            "safe_conclusion": self.safe_conclusion,
        }


def detect_hazardous_analysis(
    graph: CapabilityGraph,
    *,
    max_depth: int = 3,
    patterns: list[HazardousPattern] | None = None,
) -> HazardousAnalysis:
    """Detect hazardous paths and retain traversal completeness status.

    A negative result with ``truncated`` / ``analysis_incomplete`` means the hazard
    was **not observed** within the completed search — not that none exists.
    """
    findings: list[HazardousFinding] = []
    truncated = bool(graph.truncated)
    incomplete = bool(graph.truncated)
    reason = graph.truncation_reason if graph.truncated else None
    visited_nodes = 0
    visited_edges = 0
    visits = 0
    paths_examined = 0
    for pattern in patterns or DEFAULT_PATTERNS:
        result = pattern.find(graph, max_depth)
        paths_examined += len(result.paths)
        visited_nodes = max(visited_nodes, result.visited_nodes)
        visited_edges = max(visited_edges, result.visited_edges)
        visits = max(visits, result.visits)
        if result.truncated or result.analysis_incomplete:
            truncated = truncated or result.truncated
            incomplete = True
            reason = reason or result.incompleteness_reason
        for path in result.paths:
            findings.append(
                HazardousFinding(pattern=pattern.name, path=path, description=pattern.description)
            )
    findings.sort(key=lambda f: (f.pattern, f.path.length, f.path.to_dict()["display"]))
    return HazardousAnalysis(
        findings=findings,
        truncated=truncated,
        analysis_incomplete=incomplete,
        incompleteness_reason=reason,
        visited_nodes=visited_nodes,
        visited_edges=visited_edges,
        visits=visits,
        paths_examined=paths_examined,
    )


def detect_hazardous_paths(
    graph: CapabilityGraph,
    *,
    max_depth: int = 3,
    patterns: list[HazardousPattern] | None = None,
) -> list[HazardousFinding]:
    return detect_hazardous_analysis(graph, max_depth=max_depth, patterns=patterns).findings
