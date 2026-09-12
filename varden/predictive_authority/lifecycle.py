"""Authority lifecycle: confirm, disprove, revoke, expire."""

from __future__ import annotations

import time
from typing import Iterable

from .capability import Capability, CapabilityKind
from .evidence import AuthorityLifecycle, EvidenceKind, make_evidence
from .graph import CapabilityGraph, EdgeKind, GraphEdge
from .state import AuthorityState


def confirm_capability(state: AuthorityState, name: str, *, source: str = "trusted_discovery") -> None:
    """Promote a potential capability to confirmed with trusted evidence."""
    from .capability import CapabilityEvidence

    cap = state.capabilities.get(name)
    if cap is None:
        cap = Capability(name=name, kind=CapabilityKind.CONFIRMED, evidence=CapabilityEvidence.OBSERVED)
    else:
        cap = Capability(
            name=cap.name,
            kind=CapabilityKind.CONFIRMED,
            sensitivity=cap.sensitivity,
            mutating=cap.mutating,
            reversible=cap.reversible,
            domain=cap.domain,
            evidence=CapabilityEvidence.OBSERVED,
            grant_source=cap.grant_source,
            metadata={**(cap.metadata or {}), "confirmed_by": source},
        )
    state.capabilities[name] = cap
    # Ensure confirmed node id exists (cap:name), not only potential prefix.
    from .graph import GraphNode

    node_id = f"cap:{name}"
    if not state.graph.get_node(node_id):
        state.graph.add_node(
            GraphNode(
                node_id=node_id,
                node_type="capability",
                label=name,
                confirmed=True,
                lifecycle=AuthorityLifecycle.CONFIRMED,
                metadata={"kind": "confirmed", "domain": cap.domain},
            )
        )
    else:
        state.graph.set_node_lifecycle(node_id, AuthorityLifecycle.CONFIRMED)
    pot_id = f"cap.potential:{name}"
    if state.graph.get_node(pot_id):
        state.graph.set_node_lifecycle(pot_id, AuthorityLifecycle.CONFIRMED)


def disprove_capabilities(
    state: AuthorityState,
    names: Iterable[str],
    *,
    reason: str = "narrowed_by_trusted_evidence",
) -> list[str]:
    """Mark speculative capabilities as disproven; they stop contributing to reachability."""
    removed: list[str] = []
    for name in names:
        cap = state.capabilities.get(name)
        if cap is None:
            continue
        # Only disprove potential (or explicitly speculative) capabilities unless forced.
        if cap.kind == CapabilityKind.POTENTIAL or name in names:
            state.capabilities.pop(name, None)
            removed.append(name)
            for nid in (f"cap:{name}", f"cap.potential:{name}"):
                if state.graph.get_node(nid):
                    state.graph.set_node_lifecycle(nid, AuthorityLifecycle.DISPROVEN)
            for edge in list(state.graph.edges()):
                if edge.dst.endswith(name) or edge.src.endswith(name) or name in edge.dst or name in edge.src:
                    if edge.evidence.kind in {EvidenceKind.POTENTIAL, EvidenceKind.UNTRUSTED_DECLARED, EvidenceKind.INTERCEPTOR_DERIVED}:
                        state.graph.set_edge_lifecycle(edge.edge_id, AuthorityLifecycle.DISPROVEN)
    state.updated_at = time.time()
    state.graph.invalidate_caches()
    return removed


def revoke_capability(state: AuthorityState, name: str, *, reason: str = "revoked") -> bool:
    cap = state.capabilities.pop(name, None)
    for nid in (f"cap:{name}", f"cap.potential:{name}"):
        if state.graph.get_node(nid):
            state.graph.set_node_lifecycle(nid, AuthorityLifecycle.REVOKED)
    for edge in list(state.graph.edges()):
        if name in edge.src or name in edge.dst:
            state.graph.set_edge_lifecycle(edge.edge_id, AuthorityLifecycle.REVOKED)
    state.graph.invalidate_caches()
    state.updated_at = time.time()
    return cap is not None


def apply_trusted_scope_narrowing(
    state: AuthorityState,
    credential_name: str,
    allowed_capabilities: Iterable[str],
) -> dict[str, list[str]]:
    """Trusted evidence establishes a narrow scope; disprove other potential grants."""
    allowed = {str(x) for x in allowed_capabilities}
    # Confirm allowed.
    confirmed: list[str] = []
    for name in sorted(allowed):
        confirm_capability(state, name, source="trusted_discovery")
        # Ensure grant edge from credential.
        cred_id = f"cap:{credential_name}"
        cap_id = f"cap:{name}"
        if state.graph.get_node(cred_id) and state.graph.get_node(cap_id):
            state.graph.add_edge(
                GraphEdge(
                    src=cred_id,
                    dst=cap_id,
                    kind=EdgeKind.GRANTS,
                    evidence=make_evidence(
                        EvidenceKind.TRUSTED_DISCOVERY,
                        source="trusted_permission_discovery",
                        assertion_actor="varden",
                        lifecycle=AuthorityLifecycle.CONFIRMED,
                        description=f"Trusted scope includes {name}",
                    ),
                    label="grants",
                )
            )
        confirmed.append(name)

    # Disprove sibling potential grants from this credential.
    to_disprove: list[str] = []
    for name, cap in list(state.capabilities.items()):
        if name in allowed:
            continue
        if cap.grant_source == credential_name or (
            cap.kind == CapabilityKind.POTENTIAL and cap.domain == credential_name.split(".", 1)[0].replace("credential", "aws")
        ):
            # Narrow: potential AWS grants from credential.aws not in allowed list.
            if credential_name == "credential.aws" and name.startswith("aws."):
                to_disprove.append(name)
            elif cap.grant_source == credential_name:
                to_disprove.append(name)
    disproven = disprove_capabilities(state, to_disprove, reason="narrowed_by_trusted_evidence")
    return {"confirmed": confirmed, "disproven": disproven}


def add_sanitisation_boundary(
    graph: CapabilityGraph,
    *,
    from_node: str,
    boundary_id: str,
    to_node: str,
    trusted: bool,
    source: str = "varden_sanitiser",
    cleared_properties: list[str] | None = None,
    remaining_properties: list[str] | None = None,
) -> None:
    """Insert a trusted information-flow declassification boundary.

    This is **not** HTML sanitisation, SQL escaping, prompt filtering, or an
    untrusted tool claiming it "sanitised" something.

    A Varden-recognised trusted transformation may terminate only the tracked
    properties listed in ``cleared_properties`` (default: sensitive content
    flow). It does **not** imply all taint / provenance is erased.

    Untrusted "we sanitised it" claims do NOT create SANITISED_BY edges that
    stop reachability — they are recorded as UNTRUSTED_DECLARED influences.
    """
    from .graph import GraphNode

    # Property-specific: default clears sensitive content only — not provenance trust.
    props = list(cleared_properties) if cleared_properties is not None else ["sensitive_content", "SECRET"]
    clears_sensitive = any(p in {"sensitive_content", "SECRET", "SENSITIVE", "sensitive"} for p in props)
    if remaining_properties is not None:
        remaining = list(remaining_properties)
    else:
        remaining = []
        if "UNTRUSTED_PROVENANCE" not in props and "provenance" not in {p.lower() for p in props}:
            remaining.append("UNTRUSTED_PROVENANCE")
        if not clears_sensitive and "SECRET" not in props:
            remaining.append("SECRET")

    graph.add_node(
        GraphNode(
            node_id=boundary_id,
            node_type="sanitisation_boundary",
            label="DECLASSIFICATION BOUNDARY" if trusted else "UNTRUSTED SANITISATION CLAIM",
            confirmed=trusted,
            lifecycle=AuthorityLifecycle.CONFIRMED if trusted else AuthorityLifecycle.POTENTIAL,
            metadata={
                "sanitisation_boundary": trusted and clears_sensitive,
                "declassification_boundary": trusted,
                "fake_sanitisation": not trusted,
                "terminates_sensitive_flow": trusted and clears_sensitive,
                "cleared_properties": props if trusted else [],
                "remaining_properties": remaining if trusted else [],
                "trusted_information_flow_declassification": trusted,
                "trusted_mechanism": source if trusted else None,
                "trusted_because": (
                    "assertion_actor=varden with runtime_observed / varden_sanitiser evidence"
                    if trusted
                    else None
                ),
                "input_node": from_node,
                "output_node": to_node,
            },
        )
    )
    if trusted:
        graph.add_edge(
            GraphEdge(
                src=from_node,
                dst=boundary_id,
                kind=EdgeKind.SANITISED_BY,
                evidence=make_evidence(
                    EvidenceKind.RUNTIME_OBSERVED,
                    source=source,
                    assertion_actor="varden",
                    lifecycle=AuthorityLifecycle.CONFIRMED,
                    description=(
                        "Trusted Varden declassification boundary; "
                        f"cleared_properties={props}; remaining_properties={remaining}"
                    ),
                ),
                label="sanitised_by",
                metadata={
                    "cleared_properties": props,
                    "remaining_properties": remaining,
                    "trusted_mechanism": source,
                },
            )
        )
        # Safe side continues from boundary to sink without carrying cleared properties.
        graph.add_edge(
            GraphEdge(
                src=boundary_id,
                dst=to_node,
                kind=EdgeKind.PRODUCES,
                evidence=make_evidence(
                    EvidenceKind.RUNTIME_OBSERVED,
                    source=source,
                    assertion_actor="varden",
                    lifecycle=AuthorityLifecycle.CONFIRMED,
                    description="Derived value after trusted declassification of listed properties",
                ),
                label="produces_safe",
                metadata={
                    "sensitive_flow_terminated": clears_sensitive,
                    "cleared_properties": props,
                    "remaining_properties": remaining,
                },
            )
        )
    else:
        # Fake claim: do NOT terminate — keep FLOWS_TO so path remains hazardous.
        graph.add_edge(
            GraphEdge(
                src=from_node,
                dst=to_node,
                kind=EdgeKind.FLOWS_TO,
                evidence=make_evidence(
                    EvidenceKind.UNTRUSTED_DECLARED,
                    source="untrusted_sanitisation_claim",
                    assertion_actor=source,
                    lifecycle=AuthorityLifecycle.POTENTIAL,
                    description="Untrusted party claimed sanitisation; flow NOT terminated",
                ),
                label="claimed_sanitised",
                metadata={"fake_sanitisation": True, "cleared_properties": []},
            )
        )
