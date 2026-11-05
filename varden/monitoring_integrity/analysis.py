"""Hazardous monitoring-integrity paths on the Predictive Authority graph.

This module does not implement a second traversal. It builds nodes and asks
``detect_hazardous_analysis`` for paths. Minimum cuts are exact only inside
the stated combination budget; otherwise the result is marked as a heuristic
and is not a proof.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from varden.predictive_authority.graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from varden.predictive_authority.hazardous import detect_hazardous_analysis

from .assets import AssetRegistry, ToolGrant
from .invariants import INVARIANTS


@dataclass
class AnalysisCache:
    hits: int = 0
    misses: int = 0
    invalidations: int = 0
    _entries: dict[tuple, dict[str, Any]] = field(default_factory=dict)
    _generation: int = -1

    def invalidate(self) -> None:
        self.invalidations += 1
        self._entries.clear()

    def get(self, generation: int, key: tuple) -> dict[str, Any] | None:
        if generation != self._generation:
            self._entries.clear()
            self._generation = generation
        found = self._entries.get(key)
        if found is None:
            self.misses += 1
            return None
        self.hits += 1
        return found

    def put(self, generation: int, key: tuple, value: dict[str, Any]) -> None:
        self._generation = generation
        self._entries[key] = value


_CACHE = AnalysisCache()


def get_analysis_cache() -> AnalysisCache:
    return _CACHE


def invalidate_analysis() -> None:
    _CACHE.invalidate()


def _tool_node(grant: ToolGrant) -> str:
    return f"mip:tool:{grant.id}"


def _asset_node(asset_id: str) -> str:
    return f"mip:asset:{asset_id}"


def _prohibited_node(asset_id: str) -> str:
    return f"mip:prohibited:{asset_id}"


def _protection(surface: str, boundary: Any) -> dict[str, str]:
    """Annotate an edge with the assurance of its enforcement point.

    A claim upgrades the tier only when it was produced by a probe. A
    configuration flag cannot do that.
    """
    intercepted = {"protection_tier": "INTERCEPTED", "protection_mechanism": "python_interceptor"}
    if boundary is None or getattr(boundary, "origin", None) != "probe" or not getattr(boundary, "verified", False):
        return intercepted
    covers = set(getattr(boundary, "covers", ()) or ())
    if surface in covers:
        return {"protection_tier": boundary.tier, "protection_mechanism": boundary.mechanism}
    if surface == "mcp":
        return {
            "protection_tier": "NOT_ENFORCEABLE",
            "protection_mechanism": "local_boundary_does_not_cover_remote_mcp",
        }
    return intercepted


def build_graph(registry: AssetRegistry, grants: list[ToolGrant] | None = None, boundary: Any = None) -> CapabilityGraph:
    graph = CapabilityGraph()
    agent_id = "mip:agent:protected"
    graph.add_node(GraphNode(node_id=agent_id, node_type="agent", label="protected agent", metadata={"mip_agent": True}))
    protected = [asset for asset in registry.assets() if asset.protected]
    for asset in protected:
        graph.add_node(
            GraphNode(
                node_id=_asset_node(asset.id),
                node_type="security_asset",
                label=asset.id,
                metadata={"sensitivity": "sensitive", "mip_asset": True, "asset_type": asset.asset_type.value},
            )
        )
        invariant = "INV-003"
        for key, spec in INVARIANTS.items():
            if asset.asset_type.value == "policy" and key == "INV-007":
                invariant = key
            elif asset.asset_type.value == "enforcement_config" and key == "INV-001":
                invariant = key
        graph.add_node(
            GraphNode(
                node_id=_prohibited_node(asset.id),
                node_type="monitoring_state",
                label=f"{asset.id} integrity lost",
                metadata={"sensitivity": "sensitive", "mip_prohibited": True, "invariant": invariant, "asset_id": asset.id},
            )
        )
    chosen = list(grants if grants is not None else registry.grants())
    sequenced = sorted((grant for grant in chosen if grant.sequence is not None), key=lambda item: (item.sequence or 0, item.id))
    loose = [grant for grant in chosen if grant.sequence is None]
    previous = agent_id
    for grant in sequenced:
        previous = _add_grant(graph, grant, previous, protected, boundary)
    for grant in loose:
        _add_grant(graph, grant, agent_id, protected, boundary)
    return graph


def _targets(grant: ToolGrant, protected: list) -> list:
    if not grant.assets:
        return []
    if grant.assets == ("*",) or "*" in grant.assets:
        return list(protected)
    ids = set(grant.assets)
    return [asset for asset in protected if asset.id in ids]


def _add_grant(graph: CapabilityGraph, grant: ToolGrant, previous: str, protected: list, boundary: Any = None) -> str:
    tool_id = _tool_node(grant)
    neutral = grant.authority_neutral or (not grant.activation and grant.operations == ("read",))
    graph.add_node(
        GraphNode(
            node_id=tool_id,
            node_type="tool",
            label=grant.id,
            metadata={
                "surface": grant.surface,
                "operations": list(grant.operations),
                "authority_neutral": neutral,
                "mip_tool": True,
            },
        )
    )
    graph.add_edge(
        GraphEdge(
            src=previous,
            dst=tool_id,
            kind=EdgeKind.ENABLES,
            evidence=EdgeEvidence.CONFIGURED,
            label="enables",
            metadata={"authority_neutral": True, "interruption_candidate": False, "grant_id": grant.id},
        )
    )
    targets = _targets(grant, protected)
    mutating = any(op != "read" for op in grant.operations)
    for asset in targets:
        graph.add_edge(
            GraphEdge(
                src=tool_id,
                dst=_asset_node(asset.id),
                kind=EdgeKind.READS if not mutating else EdgeKind.WRITES_TO,
                evidence=EdgeEvidence.CONFIGURED,
                label=grant.operations[0],
                metadata={
                    "authority_neutral": not mutating,
                    "interruption_candidate": mutating,
                    "enforceable": grant.enforceable,
                    "operation": grant.operations[0],
                    "surface": grant.surface,
                    "asset_id": asset.id,
                    "grant_id": grant.id,
                    **_protection(grant.surface, boundary),
                },
            )
        )
        if mutating or grant.activation:
            graph.add_edge(
                GraphEdge(
                    src=tool_id,
                    dst=_prohibited_node(asset.id),
                    kind=EdgeKind.ENABLES,
                    evidence=EdgeEvidence.CONFIGURED,
                    label="can disable monitoring",
                    metadata={
                        "interruption_candidate": True,
                        "enforceable": grant.enforceable,
                        "operation": grant.operations[0],
                        "surface": grant.surface,
                        "asset_id": asset.id,
                        "grant_id": grant.id,
                        "activation": grant.activation,
                        **_protection(grant.surface, boundary),
                    },
                )
            )
    if not targets and grant.activation:
        for asset in protected:
            graph.add_edge(
                GraphEdge(
                    src=tool_id,
                    dst=_prohibited_node(asset.id),
                    kind=EdgeKind.ENABLES,
                    evidence=EdgeEvidence.POTENTIAL,
                    label="activation",
                    metadata={
                        "interruption_candidate": True,
                        "enforceable": grant.enforceable,
                        "operation": "exec",
                        "surface": grant.surface,
                        "asset_id": asset.id,
                        "grant_id": grant.id,
                        "activation": True,
                        **_protection(grant.surface, boundary),
                    },
                )
            )
    return tool_id


def earliest_interruption(graph: CapabilityGraph, path_edges: list[str]) -> dict[str, Any] | None:
    fallback = None
    for edge_id in path_edges:
        edge = graph.get_edge(edge_id)
        if edge is None:
            continue
        meta = edge.metadata or {}
        if not meta.get("interruption_candidate"):
            continue
        point = {
            "edge_id": edge.edge_id,
            "grant_id": meta.get("grant_id"),
            "asset_id": meta.get("asset_id"),
            "operation": meta.get("operation"),
            "surface": meta.get("surface"),
            "enforceable": bool(meta.get("enforceable")),
            "source": edge.src,
            "target": edge.dst,
            "protection_tier": meta.get("protection_tier") or "INTERCEPTED",
            "protection_mechanism": meta.get("protection_mechanism") or "python_interceptor",
        }
        if point["enforceable"]:
            point["outcome"] = "DENY"
            return point
        fallback = point
    if fallback is not None:
        fallback["outcome"] = "NOT_ENFORCEABLE"
        fallback["reason"] = "The earliest mutating step has no enforcement surface."
    return fallback


def minimum_cut(paths: list[list[str]], *, max_edges: int = 16, max_combinations: int = 20000) -> dict[str, Any]:
    """Smallest set of enforceable edges that intersects every known path.

    ``proven`` is true only when the exact search finishes inside the budget.
    """
    cleaned = [path for path in paths if path]
    if not cleaned:
        return {
            "edges": [],
            "proven": False,
            "method": "no_enforceable_edges",
            "breaks_all_known_paths": False,
            "analysis_incomplete": True,
            "reason": "Known hazardous paths have no enforceable edge.",
        }
    universe = sorted({edge for path in cleaned for edge in path})
    if not universe:
        return {
            "edges": [],
            "proven": False,
            "method": "no_enforceable_edges",
            "breaks_all_known_paths": False,
            "analysis_incomplete": True,
            "reason": "No enforceable interruption on the known paths.",
        }
    combinations = 0
    exact_budget = len(universe) <= max_edges
    if exact_budget:
        for size in range(1, len(universe) + 1):
            exhausted = False
            for subset in itertools.combinations(universe, size):
                combinations += 1
                if combinations > max_combinations:
                    exhausted = True
                    break
                chosen = set(subset)
                if all(any(edge in chosen for edge in path) for path in cleaned):
                    return {
                        "edges": list(subset),
                        "proven": True,
                        "method": "exact_set_cover",
                        "combinations": combinations,
                        "breaks_all_known_paths": True,
                        "analysis_incomplete": False,
                    }
            if exhausted:
                break
    counts: dict[str, int] = {}
    remaining = [set(path) for path in cleaned]
    chosen_edges: list[str] = []
    while remaining:
        counts = {}
        for path in remaining:
            for edge in path:
                counts[edge] = counts.get(edge, 0) + 1
        if not counts:
            break
        best = max(sorted(counts), key=lambda edge: (counts[edge], edge))
        chosen_edges.append(best)
        remaining = [path for path in remaining if best not in path]
    return {
        "edges": chosen_edges,
        "proven": False,
        "method": "greedy_approximation",
        "combinations": combinations,
        "breaks_all_known_paths": not remaining,
        "analysis_incomplete": True,
        "reason": "Exact minimum cut exceeded the combination budget." if exact_budget else "Edge universe exceeded the exact-cut budget.",
    }


def _enforceable_edges(graph: CapabilityGraph, edge_ids: list[str]) -> list[str]:
    found = []
    for edge_id in edge_ids:
        edge = graph.get_edge(edge_id)
        meta = (edge.metadata or {}) if edge else {}
        if meta.get("interruption_candidate") and meta.get("enforceable"):
            found.append(edge_id)
    return found


def _path_records(graph: CapabilityGraph, findings) -> list[dict[str, Any]]:
    records = []
    for finding in findings:
        if finding.pattern != "monitoring_integrity_sabotage":
            continue
        edges = list(finding.path.edges)
        records.append(
            {
                "pattern": finding.pattern,
                "description": finding.description,
                "path": finding.path.to_dict(),
                "interruption": earliest_interruption(graph, edges),
                "enforceable_edges": _enforceable_edges(graph, edges),
            }
        )
    return records


def analyse(
    registry: AssetRegistry,
    *,
    max_depth: int = 8,
    max_edges: int = 16,
    max_combinations: int = 20000,
    use_cache: bool = True,
    grants: list[ToolGrant] | None = None,
    boundary: Any = None,
) -> dict[str, Any]:
    grant_list = list(grants if grants is not None else registry.grants())
    key = (
        registry.section_hash,
        max_depth,
        max_edges,
        max_combinations,
        tuple((item.id, item.operations, item.assets, item.enforceable, item.sequence, item.activation) for item in grant_list),
        getattr(boundary, "tier", None),
        getattr(boundary, "mechanism", None),
        tuple(getattr(boundary, "covers", ()) or ()),
        bool(getattr(boundary, "verified", False)),
        getattr(boundary, "origin", None),
    )
    if use_cache:
        cached = _CACHE.get(registry.generation, key)
        if cached is not None:
            return cached
    graph = build_graph(registry, grant_list, boundary)
    if max_depth < 1:
        report = {
            "hazard_found": False,
            "paths": [],
            "interruption": None,
            "minimum_cut": {
                "edges": [],
                "proven": False,
                "method": "not_run",
                "analysis_incomplete": True,
                "reason": "DEPTH_BUDGET",
                "breaks_all_known_paths": False,
            },
            "analysis_incomplete": True,
            "incompleteness_reason": "DEPTH_BUDGET",
            "safe_conclusion": False,
            "graph_nodes": len(graph.nodes()),
            "graph_edges": len(graph.edges()),
            "max_depth": max_depth,
            "limitations": ["The depth budget was too small to search. This is not a safety conclusion."],
            "os_isolation": False,
        }
        if use_cache:
            _CACHE.put(registry.generation, key, report)
        return report
    if not grant_list:
        report = {
            "hazard_found": False,
            "paths": [],
            "interruption": None,
            "minimum_cut": {
                "edges": [],
                "proven": False,
                "method": "not_run",
                "analysis_incomplete": True,
                "reason": "NO_TOOL_GRANTS",
                "breaks_all_known_paths": False,
            },
            "analysis_incomplete": True,
            "incompleteness_reason": "NO_TOOL_GRANTS",
            "safe_conclusion": False,
            "graph_nodes": len(graph.nodes()),
            "graph_edges": len(graph.edges()),
            "max_depth": max_depth,
            "limitations": [
                "No tool grants were declared. Single-step interception may still deny a protected mutation. That is not a proof that no multi-step path exists.",
            ],
            "os_isolation": False,
        }
        if use_cache:
            _CACHE.put(registry.generation, key, report)
        return report
    analysis = detect_hazardous_analysis(graph, max_depth=max_depth)
    paths = _path_records(graph, analysis.findings)
    cut = minimum_cut([record["enforceable_edges"] for record in paths], max_edges=max_edges, max_combinations=max_combinations) if paths else {
        "edges": [],
        "proven": not (analysis.analysis_incomplete or analysis.truncated),
        "method": "no_hazard_in_completed_search" if not (analysis.analysis_incomplete or analysis.truncated) else "incomplete_search",
        "breaks_all_known_paths": True,
        "analysis_incomplete": bool(analysis.analysis_incomplete or analysis.truncated),
        "reason": analysis.incompleteness_reason,
    }
    incomplete = bool(analysis.analysis_incomplete or analysis.truncated or cut.get("analysis_incomplete") and paths)
    if paths and cut.get("method") == "exact_set_cover":
        incomplete = bool(analysis.analysis_incomplete or analysis.truncated)
    report = {
        "hazard_found": bool(paths),
        "paths": paths,
        "interruption": paths[0]["interruption"] if paths else None,
        "minimum_cut": cut,
        "analysis_incomplete": incomplete,
        "incompleteness_reason": analysis.incompleteness_reason,
        "safe_conclusion": (not paths) and (not analysis.analysis_incomplete) and (not analysis.truncated),
        "graph_nodes": len(graph.nodes()),
        "graph_edges": len(graph.edges()),
        "max_depth": max_depth,
        "visited_nodes": analysis.visited_nodes,
        "limitations": [
            "The graph contains only declared grants. Undeclared tools are outside this result.",
            "A hazardous path is prevented only when an interruption is enforceable and an interceptor runs before the side effect.",
            "Incomplete search is not evidence of safety.",
        ],
        "os_isolation": False,
        "trust_boundary": "predictive_authority_graph",
    }
    if use_cache:
        _CACHE.put(registry.generation, key, report)
    return report


def counterfactual(registry: AssetRegistry, intervention: dict[str, Any], **bounds) -> dict[str, Any]:
    """Re-run the same analysis after one declared change. Does not mutate the registry."""
    kind = str(intervention.get("kind") or "")
    grants = []
    for grant in registry.grants():
        if kind == "remove_permission" and grant.id == intervention.get("grant_id"):
            continue
        if kind == "constrain_tool" and grant.id == intervention.get("grant_id"):
            continue
        updated = grant
        if kind == "surface_unavailable" and grant.surface == intervention.get("surface"):
            updated = ToolGrant(
                id=grant.id,
                operations=grant.operations,
                assets=grant.assets,
                surface=grant.surface,
                enforceable=False,
                sequence=grant.sequence,
                activation=grant.activation,
                authority_neutral=grant.authority_neutral,
            )
        if kind == "require_approval" and grant.id == intervention.get("grant_id"):
            updated = ToolGrant(
                id=grant.id,
                operations=grant.operations,
                assets=grant.assets,
                surface=grant.surface,
                enforceable=True,
                sequence=grant.sequence,
                activation=grant.activation,
                authority_neutral=grant.authority_neutral,
            )
        grants.append(updated)
    before = analyse(registry, use_cache=False, **bounds)
    after = analyse(registry, grants=grants, use_cache=False, **bounds)
    return {
        "intervention": intervention,
        "before_hazards": len(before["paths"]),
        "after_hazards": len(after["paths"]),
        "before_safe_conclusion": before["safe_conclusion"],
        "after_safe_conclusion": after["safe_conclusion"],
        "after_incomplete": after["analysis_incomplete"],
        "after_interruption": after.get("interruption"),
        "hazard_removed": bool(before["paths"]) and not after["paths"] and not after["analysis_incomplete"],
        "note": (
            "Removing an enforcement surface does not make a remaining path safe."
            if kind == "surface_unavailable"
            else "Approval changes the interruption outcome only when the path still exists and the interceptor demands that approval."
            if kind == "require_approval"
            else "Comparison is limited to the declared grant model."
        ),
        "after": after,
    }
