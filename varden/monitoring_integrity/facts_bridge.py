"""Attach monitoring-integrity nodes to an existing Predictive Authority state.

No-op unless a registry is bound or enabled. Does not execute tools.
"""

from __future__ import annotations

from typing import Any

from varden.predictive_authority.graph import EdgeEvidence, EdgeKind, GraphEdge, GraphNode

from .service import current_registry, enabled


def annotate_action_facts(action: Any, facts: Any) -> None:
    if not enabled():
        return
    registry = current_registry()
    annotations = []
    path = None
    args = getattr(action, "args", None) or {}
    if isinstance(args, dict):
        path = args.get("path") or args.get("file") or args.get("dst")
    if path:
        for match in registry.match_path(str(path)):
            if match.asset.protected:
                annotations.append({"asset_id": match.asset.id, "via": match.via, "operation": "touch"})
    facts.mip_annotations = annotations


def apply_monitoring_facts(state: Any, facts: Any) -> None:
    annotations = getattr(facts, "mip_annotations", None) or []
    if not annotations:
        return
    graph = state.graph
    agent_id = "mip:agent:session"
    graph.add_node(GraphNode(node_id=agent_id, node_type="agent", label="session agent", metadata={"mip_agent": True}))
    for item in annotations:
        asset_id = str(item["asset_id"])
        asset_node = f"mip:asset:{asset_id}"
        prohibited = f"mip:prohibited:{asset_id}"
        graph.add_node(
            GraphNode(
                node_id=asset_node,
                node_type="security_asset",
                label=asset_id,
                metadata={"sensitivity": "sensitive", "mip_asset": True},
            )
        )
        graph.add_node(
            GraphNode(
                node_id=prohibited,
                node_type="monitoring_state",
                label=f"{asset_id} integrity lost",
                metadata={"sensitivity": "sensitive", "mip_prohibited": True, "asset_id": asset_id},
            )
        )
        action_id = getattr(facts, "action_node_id", "") or "action:mip"
        graph.add_edge(
            GraphEdge(
                src=agent_id,
                dst=action_id,
                kind=EdgeKind.ENABLES,
                evidence=EdgeEvidence.OBSERVED,
                label="attempted",
                metadata={"authority_neutral": True, "interruption_candidate": False},
            )
        )
        graph.add_edge(
            GraphEdge(
                src=action_id,
                dst=prohibited,
                kind=EdgeKind.ENABLES,
                evidence=EdgeEvidence.OBSERVED,
                label="would affect monitoring",
                metadata={
                    "interruption_candidate": True,
                    "enforceable": True,
                    "surface": "filesystem",
                    "asset_id": asset_id,
                    "operation": item.get("operation") or "write",
                },
            )
        )
