"""Delegation: the authority a causal chain is permitted to exercise.

Capability possession (the agent process can call tool X) is distinct from
delegated authority (this causal chain is authorised to exercise X).

Untrusted data must never create or broaden a Delegation.
Monotonicity: information entering a workflow may reduce usable authority,
but untrusted data may never increase it.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from .models import (
    AUTHORITY_CLASSES,
    AuthorityAnalysis,
    AuthorityRequirement,
    Delegation,
    ProvenanceSource,
    TaintSet,
    authority_rank,
    new_id,
    trust_rank,
)


def empty_delegation(*, principal: str = "agent", trace_scope: str | None = None) -> Delegation:
    return Delegation(
        delegation_id=new_id("dlg"),
        principal=principal,
        capabilities=["NONE"],
        resources=[],
        issued_by="system",
        trace_scope=trace_scope,
        integrity="verified",
    )


def default_agent_delegation(*, principal: str = "agent", trace_scope: str | None = None) -> Delegation:
    """Baseline when no explicit user intent is observed.

    Intentionally narrow: public read / public network / unprivileged MCP.
    Sensitive actions require an explicit user delegation or approval.
    """
    return Delegation.public_read_only(principal=principal, trace_scope=trace_scope)


def user_delegation(
    capabilities: Iterable[str],
    *,
    resources: Iterable[str] | None = None,
    principal: str = "user",
    trace_scope: str | None = None,
    expires_at: float | None = None,
) -> Delegation:
    caps = [c for c in capabilities if c in AUTHORITY_CLASSES]
    if not caps:
        caps = ["READ_PUBLIC"]
    return Delegation(
        delegation_id=new_id("dlg"),
        principal=principal,
        capabilities=caps,
        resources=list(resources or ["*"]),
        issued_by="user",
        issued_at=time.time(),
        expires_at=expires_at,
        trace_scope=trace_scope,
        integrity="verified",
    )


def intersect_capabilities(left: Iterable[str], right: Iterable[str]) -> list[str]:
    """Monotonic intersection — usable authority can only shrink."""
    lset, rset = set(left), set(right)
    if "ADMIN" in lset:
        return sorted(rset, key=authority_rank)
    if "ADMIN" in rset:
        return sorted(lset, key=authority_rank)
    return sorted(lset & rset, key=authority_rank)


def reduce_delegation_for_taint(delegation: Delegation, taint: TaintSet, sources: list[ProvenanceSource]) -> Delegation:
    """Apply monotonic authority reduction based on untrusted influence.

    Rules:
    - Hostile ancestor → capabilities collapse to NONE (plus READ_PUBLIC only
      if explicitly user-authorised taint is also present — still no secrets).
    - Untrusted / unknown incomplete provenance → strip privileged caps.
    - Secret/private taint does not grant new caps; it only marks sensitivity.
    - ``user_authorised`` taint preserves the existing delegation.
    """
    caps = list(delegation.capabilities)
    min_src_trust = min((trust_rank(s.trust_level) for s in sources), default=trust_rank("unknown"))
    incomplete = any(not s.provenance_complete for s in sources) or any(
        s.trust_level == "unknown" and s.source_type == "unknown" for s in sources
    )

    if taint.has("user_authorised") and any(s.source_type == "user" and s.integrity == "verified" for s in sources):
        return delegation

    privileged = {
        "READ_SECRETS", "READ_PRIVATE", "WRITE_DATABASE", "WRITE_CLOUD",
        "WRITE_REPOSITORY", "EXECUTE_PRIVILEGED", "NETWORK_CREDENTIALLED",
        "MCP_PRIVILEGED", "IDENTITY_USE", "PAYMENT", "DELETE", "ADMIN",
        "NETWORK_INTERNAL",
    }

    if taint.has("hostile") or min_src_trust == trust_rank("hostile"):
        caps = ["NONE"]
    elif taint.is_untrusted() or min_src_trust <= trust_rank("untrusted") or incomplete:
        caps = [c for c in caps if c not in privileged]
        if not caps:
            caps = ["READ_PUBLIC", "NETWORK_PUBLIC", "MCP_UNPRIVILEGED"]

    return Delegation(
        delegation_id=delegation.delegation_id,
        principal=delegation.principal,
        capabilities=caps,
        resources=list(delegation.resources),
        constraints=dict(delegation.constraints),
        issued_by=delegation.issued_by,
        issued_at=delegation.issued_at,
        expires_at=delegation.expires_at,
        trace_scope=delegation.trace_scope,
        integrity=delegation.integrity,
    )


def evaluate_authority(
    required: AuthorityRequirement,
    delegation: Delegation,
    *,
    taint: TaintSet | None = None,
    sources: list[ProvenanceSource] | None = None,
) -> AuthorityAnalysis:
    """Compare required authority against effective delegated authority.

    This is the §8–9 check: does *this causal chain* hold a valid delegation
    for the authorities the action needs?
    """
    taint = taint or TaintSet()
    sources = sources or []
    effective = reduce_delegation_for_taint(delegation, taint, sources)

    missing: list[str] = []
    for auth in sorted(required.required, key=authority_rank):
        if auth == "NONE":
            continue
        if not effective.grants(auth, required.resource):
            # Also allow if a strictly higher capability is granted that
            # subsumes this one via ADMIN only — we do not invent soft
            # subsumption between unrelated classes.
            if "ADMIN" in effective.capabilities and effective.is_active():
                continue
            missing.append(auth)

    escalation = bool(missing)
    # Escalation relative to pre-reduction delegation (untrusted broadened?).
    for auth in required.required:
        if auth == "NONE":
            continue
        pre_ok = delegation.grants(auth, required.resource) or "ADMIN" in delegation.capabilities
        post_ok = effective.grants(auth, required.resource) or "ADMIN" in effective.capabilities
        if post_ok and not pre_ok:
            # Untrusted data somehow increased authority — invariant break.
            escalation = True
            if auth not in missing:
                missing.append(auth)

    findings: list[str] = []
    if missing:
        findings.append("delegation_violation")
        findings.append("authority_escalation")
    if taint.is_untrusted() and any(authority_rank(a) >= authority_rank("READ_PRIVATE") for a in required.required):
        findings.append("untrusted_to_privileged")
    if any(s.trust_level == "unknown" for s in sources) and any(
        authority_rank(a) >= authority_rank("DELETE") for a in required.required
    ):
        findings.append("unknown_provenance_sensitive_action")

    reason = (
        f"required={sorted(required.required)} granted={effective.capabilities} missing={missing}"
        if missing
        else f"delegated authority covers {sorted(required.required)}"
    )

    return AuthorityAnalysis(
        required=sorted(required.required, key=authority_rank),
        granted=list(effective.capabilities),
        missing=missing,
        escalation=escalation,
        violation=bool(missing),
        resource=required.resource,
        reason=reason,
        findings=sorted(set(findings)),
    )


def extract_client_delegation(metadata: dict[str, Any] | None) -> Delegation | None:
    """Parse a client-supplied delegation claim.

    CRITICAL: client-supplied delegations are NEVER trusted as-is.
    They are returned with integrity='unverified' and ignored by
    evaluate_authority unless a server-side store upgrades them.
    """
    if not metadata:
        return None
    raw = metadata.get("delegation") or metadata.get("authority_delegation")
    if not isinstance(raw, dict):
        return None
    dlg = Delegation.from_dict(raw)
    dlg.integrity = "unverified"
    return dlg


def server_issue_delegation(
    capabilities: Iterable[str],
    *,
    principal: str,
    resources: Iterable[str] | None = None,
    issued_by: str = "control-plane",
    trace_scope: str | None = None,
    expires_at: float | None = None,
) -> Delegation:
    """Mint a verified delegation — only callable from the control plane."""
    return Delegation(
        delegation_id=new_id("dlg"),
        principal=principal,
        capabilities=[c for c in capabilities if c in AUTHORITY_CLASSES],
        resources=list(resources or ["*"]),
        issued_by=issued_by,
        issued_at=time.time(),
        expires_at=expires_at,
        trace_scope=trace_scope,
        integrity="verified",
    )
