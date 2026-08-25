"""Provenance-aware authority-flow analysis engine.

Runs before PolicyEngine.evaluate. Enriches the Action with explicit
provenance / taint / authority / flow / causal fields so existing ordered
policy buckets can enforce Ghostjacking-style constraints.

Security decisions derive from observable runtime relationships — not from
asking an LLM whether malicious text "really caused" an action.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from ..models import Action
from .authority import classify_action
from .delegation import (
    default_agent_delegation,
    evaluate_authority,
    extract_client_delegation,
    reduce_delegation_for_taint,
    user_delegation,
)
from .graph import ProvenanceGraph
from .models import (
    CausalAnalysis,
    FlowAnalysis,
    ProvenanceAnalysis,
    ProvenanceSource,
    TaintSet,
    new_id,
    trust_rank,
)
from .taint import infer_taints_from_classifiers, merge_sources, tag_from_source


def _as_dict(action: Action | dict[str, Any]) -> dict[str, Any]:
    if hasattr(action, "to_dict"):
        return action.to_dict()
    return dict(action or {})


def _demote_client_source(src: ProvenanceSource) -> ProvenanceSource:
    """Client-supplied provenance can never self-attest trust or user identity.

    Any integrity=verified / trust=trusted / source_type=user claim arriving
    via action metadata is treated as forgery and demoted. Verified user
    sources may only be injected via server-side kwargs / store lookups.
    """
    src.integrity = "unverified"
    src.authenticated = False
    if src.source_type == "user":
        src.source_type = "unknown"
        src.trust_level = "unknown"
        src.provenance_complete = False
        src.metadata = {**(src.metadata or {}), "forged_user_claim": True}
    elif src.trust_level in {"trusted", "delegated"}:
        src.trust_level = "unknown"
        src.provenance_complete = False
        src.metadata = {**(src.metadata or {}), "forged_trust_claim": True}
    return src


def _parse_sources_from_metadata(metadata: dict[str, Any]) -> list[ProvenanceSource]:
    """Extract provenance sources from action metadata / SDK lineage.

    Client-asserted trust=trusted / source=user / integrity=verified is
    NEVER accepted from request metadata. Unknown or missing provenance
    becomes an explicit unknown source.
    """
    sources: list[ProvenanceSource] = []
    raw_list = []
    lineage = metadata.get("lineage") or {}
    if isinstance(lineage, dict):
        raw_list.extend(lineage.get("sources") or [])
    if isinstance(metadata.get("provenance_sources"), list):
        raw_list.extend(metadata["provenance_sources"])
    prov = metadata.get("provenance") or {}
    if isinstance(prov, dict) and isinstance(prov.get("sources"), list):
        raw_list.extend(prov["sources"])

    for raw in raw_list:
        if isinstance(raw, str):
            # Legacy SDK lineage strings — including forged "user" markers —
            # are observational only. Never mint a verified user source.
            if raw in {"user", "user:verified", "principal:user"}:
                sources.append(
                    ProvenanceSource.unknown(
                        origin="client_asserted_user",
                        reason="forged_user_lineage_string",
                    )
                )
            else:
                sources.append(
                    ProvenanceSource(
                        source_id=new_id("src"),
                        source_type="unknown",
                        origin=raw,
                        trust_level="untrusted",
                        integrity="unverified",
                        provenance_complete=False,
                        metadata={"legacy_lineage": raw},
                    )
                )
            continue
        if not isinstance(raw, dict):
            continue
        sources.append(_demote_client_source(ProvenanceSource.from_dict(raw)))

    # Web Shield / MCP annotations on the action itself.
    if metadata.get("webmcp") or metadata.get("owner_origin"):
        trust = str(metadata.get("trust_state") or "unknown")
        if trust in {"trusted", "locally_trusted", "pinned"}:
            # Local Web Shield trust is "locally trusted origin", not global
            # safety — map to internal, never trusted-for-authority.
            mapped = "internal"
        elif trust in {"blocked", "hostile"}:
            mapped = "hostile"
        elif trust in {"untrusted", "observed"}:
            mapped = "untrusted"
        else:
            mapped = "unknown"
        findings = metadata.get("findings") or metadata.get("webshield_findings") or []
        taint_hostile = any(
            (f.get("category") if isinstance(f, dict) else None) in {
                "instruction_override", "prompt_injection", "secret_exfiltration",
            }
            or (f.get("severity") if isinstance(f, dict) else None) == "critical"
            for f in findings
        )
        if taint_hostile:
            mapped = "hostile"
        sources.append(
            ProvenanceSource(
                source_id=new_id("src"),
                source_type="webmcp_tool" if metadata.get("webmcp") else "mcp_tool_definition",
                origin=str(metadata.get("owner_origin") or metadata.get("origin") or ""),
                trust_level=mapped,
                # Observational annotation from this server path — not a
                # client self-attestation of user authority.
                integrity="unverified",
                authenticated=False,
                provenance_complete=True,
                metadata={"webshield": True, "findings_count": len(findings)},
            )
        )

    if metadata.get("mcp_server"):
        trust = str(metadata.get("mcp_trust") or "unknown")
        if trust not in {"trusted", "untrusted", "hostile", "internal", "unknown", "delegated"}:
            trust = "unknown"
        # MCP servers do not get to declare themselves trusted — including
        # via a forged mcp_trust_integrity marker.
        if trust in {"trusted", "delegated"}:
            trust = "untrusted"
        sources.append(
            ProvenanceSource(
                source_id=new_id("src"),
                source_type="mcp_tool_response" if metadata.get("is_tool_result") else "mcp_tool_definition",
                origin=f"mcp://{metadata.get('mcp_server')}",
                principal=str(metadata.get("mcp_server") or ""),
                trust_level=trust,
                integrity="unverified",
                provenance_complete=bool(metadata.get("provenance_complete", True)),
            )
        )

    # Client-asserted user_intent / user_intent_integrity / approved /
    # user_granted_capabilities are intentionally ignored here. Only the
    # server_verified_user kwarg (or a store-backed verified Delegation)
    # may introduce a trusted user source.

    return sources


def _webshield_taints(metadata: dict[str, Any]) -> TaintSet:
    t = TaintSet()
    findings = metadata.get("findings") or metadata.get("webshield_findings") or []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        cat = str(finding.get("category") or "")
        sev = str(finding.get("severity") or "")
        if cat in {"instruction_override", "prompt_injection", "hidden_instruction"}:
            t.add("untrusted_instruction", "untrusted_tool_metadata", "external_input")
        if cat in {"secret_exfiltration", "credential_harvest"}:
            t.add("secret", "credential")
        if cat in {"cross_origin"} or finding.get("rule_id", "").startswith("WEBMCP-PROV"):
            t.add("cross_origin", "external_input")
        if sev == "critical":
            t.add("untrusted_instruction", "external_input")
    if metadata.get("risk_band") in {"high", "critical"}:
        t.add("external_input")
    return t


def _causal_from_sources(sources: list[ProvenanceSource], metadata: dict[str, Any]) -> CausalAnalysis:
    depth = int(metadata.get("causal_depth") or len(sources))
    untrusted = any(s.trust_level in {"untrusted", "hostile"} for s in sources)
    hostile = any(s.trust_level == "hostile" for s in sources)
    unknown = any(s.trust_level == "unknown" or not s.provenance_complete for s in sources)
    user_auth = any(
        s.source_type == "user" and s.trust_level == "trusted" and s.integrity == "verified"
        for s in sources
    )
    complete = all(s.provenance_complete for s in sources) if sources else False
    path = [
        {
            "source_id": s.source_id,
            "source_type": s.source_type,
            "origin": s.origin,
            "trust_level": s.trust_level,
        }
        for s in sources
    ]
    return CausalAnalysis(
        depth=depth,
        untrusted_ancestor=untrusted,
        hostile_ancestor=hostile,
        unknown_ancestor=unknown or not sources,
        user_authorised=user_auth,
        ancestor_source_ids=[s.source_id for s in sources],
        path=path,
        provenance_complete=complete,
    )


def _flow_analysis(
    action_data: dict[str, Any],
    sources: list[ProvenanceSource],
    taint: TaintSet,
    required: set[str],
) -> FlowAnalysis:
    flow = FlowAnalysis()
    origins = {s.origin for s in sources if s.origin}
    meta = action_data.get("metadata") or {}
    dest = action_data.get("url") or action_data.get("domain") or meta.get("destination") or ""
    dest_host = ""
    try:
        dest_host = (urlparse(str(dest)).hostname or str(dest)).lower()
    except Exception:
        dest_host = str(dest).lower()

    src_hosts = set()
    for origin in origins:
        try:
            host = urlparse(origin).hostname or origin
        except Exception:
            host = origin
        if host:
            src_hosts.add(str(host).lower())

    if len(src_hosts) > 1:
        flow.cross_origin = True
        flow.details.append("multiple source origins in causal context")
    if dest_host and src_hosts and dest_host not in src_hosts and any(
        s.source_type in {"web_page", "webmcp_tool", "http_response"} for s in sources
    ):
        flow.cross_origin = True
        flow.details.append(f"cross-origin relay toward {dest_host}")

    servers = {
        s.principal or s.origin
        for s in sources
        if s.source_type in {"mcp_tool_definition", "mcp_tool_response"}
    }
    dest_server = meta.get("mcp_server")
    if dest_server and servers and dest_server not in servers:
        flow.cross_server = True
        flow.details.append(f"cross-server MCP flow toward {dest_server}")
    if len(servers) > 1:
        flow.cross_server = True
        flow.details.append("multiple MCP servers in causal context")

    if taint.is_sensitive() and (
        "NETWORK_PUBLIC" in required or "WRITE_CLOUD" in required or action_data.get("type") in {"http_request", "http_call"}
    ):
        # Private/secret → public sink
        public = True
        if dest_host in {"localhost", "127.0.0.1", "::1"} or dest_host.endswith(".internal"):
            public = False
        if public:
            flow.private_to_public = True
            flow.secret_egress = taint.has_any("secret", "credential")
            flow.details.append("sensitive data toward public network sink")

    if taint.is_untrusted() and any(
        a in required
        for a in {
            "READ_SECRETS", "READ_PRIVATE", "EXECUTE_PRIVILEGED", "WRITE_DATABASE",
            "WRITE_CLOUD", "DELETE", "ADMIN", "PAYMENT", "MCP_PRIVILEGED",
            "NETWORK_CREDENTIALLED", "IDENTITY_USE",
        }
    ):
        flow.untrusted_to_privileged = True
        flow.details.append("untrusted provenance influencing privileged action")

    return flow


def _build_findings(analysis: ProvenanceAnalysis) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    auth = analysis.authority
    flow = analysis.flow
    causal = analysis.causal

    def add(ftype: str, severity: str, explanation: str, **extra: Any) -> None:
        findings.append({
            "type": ftype,
            "severity": severity,
            "explanation": explanation,
            **extra,
        })

    if auth.violation:
        add(
            "delegation_violation",
            "critical" if any(a in auth.missing for a in ("READ_SECRETS", "DELETE", "ADMIN", "PAYMENT")) else "high",
            f"Action requires {auth.required} but causal chain is only delegated {auth.granted} (missing {auth.missing}).",
            required=auth.required,
            granted=auth.granted,
            missing=auth.missing,
            resource=auth.resource,
        )
        add(
            "authority_escalation",
            "critical",
            "Privileged action attempted without matching delegated authority for this causal chain.",
        )

    if flow.untrusted_to_privileged:
        add(
            "untrusted_to_privileged",
            "critical",
            "Untrusted provenance is influencing a privileged capability.",
        )

    if flow.cross_server:
        add(
            "cross_server_authority_flow",
            "high",
            "Authority flow crosses MCP server trust boundaries.",
            details=flow.details,
        )

    if flow.private_to_public or flow.secret_egress:
        add(
            "provenance_exfiltration_chain",
            "critical",
            "Sensitive/private data is flowing toward a public network sink under untrusted or incomplete provenance.",
            secret_egress=flow.secret_egress,
        )

    if causal.unknown_ancestor and any(
        a in auth.required for a in ("DELETE", "ADMIN", "PAYMENT", "READ_SECRETS", "EXECUTE_PRIVILEGED")
    ):
        add(
            "unknown_provenance_sensitive_action",
            "high",
            "Sensitive action requested under unknown/incomplete provenance — not treated as trusted.",
        )

    # Confused deputy: principal A influences deputy exercising B's authority
    # without a valid delegation from B.
    if flow.untrusted_to_privileged or (auth.violation and causal.untrusted_ancestor):
        requesting = [
            {"origin": s.origin, "type": s.source_type, "trust": s.trust_level}
            for s in analysis.sources
            if s.trust_level in {"untrusted", "hostile", "unknown"}
        ]
        if requesting:
            add(
                "confused_deputy",
                "critical",
                "Untrusted principal influenced the agent (deputy) to exercise privileged authority without a valid delegation.",
                requesting_provenance=requesting,
                privileged_capability=auth.required,
                resource=auth.resource,
                expected_delegating_principal="user",
                actual_delegation=auth.granted,
            )

    return findings


def _explanation(analysis: ProvenanceAnalysis, action_data: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    tool = action_data.get("tool") or action_data.get("type") or "action"
    resource = analysis.authority.resource or action_data.get("url") or ""
    if analysis.authority.violation:
        lines.append(f"Blocked candidate: {tool} {resource}".strip())
        lines.append(
            f"Required authority: {', '.join(analysis.authority.required) or 'NONE'}."
        )
        lines.append(
            f"Delegated authority for this causal chain: {', '.join(analysis.authority.granted) or 'NONE'}."
        )
        if analysis.authority.missing:
            lines.append(
                f"Missing: {', '.join(analysis.authority.missing)} — untrusted/unknown data cannot extend delegation."
            )
    for src in analysis.sources[:6]:
        lines.append(
            f"Influenced by {src.source_type} from {src.origin or 'unknown'} (trust={src.trust_level}, complete={src.provenance_complete})."
        )
    if analysis.flow.secret_egress:
        lines.append("Sensitive ancestor data would egress to a public sink.")
    if analysis.flow.cross_server:
        lines.append("Cross-server MCP authority flow detected.")
    if not analysis.causal.provenance_complete:
        lines.append("Provenance is incomplete — treated as untrusted, not trusted.")
    if analysis.causal.user_authorised and not analysis.authority.violation:
        lines.append("Verified user delegation covers this action.")
    return lines


def _attack_path(analysis: ProvenanceAnalysis, action_data: dict[str, Any]) -> list[str]:
    path: list[str] = []
    for src in analysis.sources:
        marker = src.trust_level.upper()
        path.append(f"[{marker}] {src.source_type}:{src.origin or src.source_id}")
    path.append("[AGENT] deputy")
    label = action_data.get("tool") or action_data.get("type") or "action"
    resource = analysis.authority.resource or ""
    path.append(f"[PRIVILEGED] {label} {resource}".strip())
    if analysis.authority.violation:
        path.append("[BLOCK]")
    return path


def analyse_action(
    action: Action | dict[str, Any],
    *,
    delegation: Any | None = None,
    graph: ProvenanceGraph | None = None,
    prior_sources: list[ProvenanceSource] | None = None,
    prior_taints: TaintSet | None = None,
    server_verified_user: bool = False,
    server_granted_capabilities: list[str] | None = None,
    server_granted_resources: list[str] | None = None,
    prior_lookup_failed: bool = False,
) -> ProvenanceAnalysis:
    """Core pre-execution analysis. Pure function w.r.t. policy decision.

    ``server_verified_user`` / ``server_granted_*`` are process-local kwargs
    only — never read from client metadata. HTTP/SDK callers cannot set them.
    """
    start = time.perf_counter()
    data = _as_dict(action)
    metadata = dict(data.get("metadata") or {})

    # Prior sources from the server store may only retain verified user/system
    # trust; any other residual claim is demoted.
    safe_priors: list[ProvenanceSource] = []
    for src in prior_sources or []:
        if src.integrity == "verified" and (
            (src.source_type == "user" and src.trust_level == "trusted")
            or src.source_type in {"system", "developer"}
        ):
            safe_priors.append(src)
        else:
            safe_priors.append(_demote_client_source(src))

    sources = merge_sources(
        safe_priors,
        _parse_sources_from_metadata(metadata),
    )
    if server_verified_user:
        sources.append(
            ProvenanceSource.user(principal=str(metadata.get("user_principal") or "user"))
        )
    if not sources:
        sources = [ProvenanceSource.unknown(reason="no_provenance_observed")]
    if prior_lookup_failed:
        sources.append(ProvenanceSource.unknown(reason="prior_provenance_lookup_failed"))
        for src in sources:
            src.provenance_complete = False

    taint = TaintSet()
    for src in sources:
        taint.merge(tag_from_source(src))
    taint.merge(infer_taints_from_classifiers(data.get("classifiers")))
    taint.merge(_webshield_taints(metadata))
    if prior_taints:
        taint.merge(prior_taints)
    # Lineage classifications from SDK
    lineage = metadata.get("lineage") or {}
    for tag in lineage.get("classifications") or []:
        if tag in {"secrets", "credentials"}:
            taint.add("secret", "credential")
        elif tag in {"internal"}:
            taint.add("internal_data")
        elif tag in {"pii"}:
            taint.add("private_data")
        elif tag in {"external", "untrusted"}:
            taint.add("external_input")

    required = classify_action(data)

    # Delegation resolution:
    # 1. Server-verified delegation argument wins.
    # 2. Server-verified user kwargs → scoped user delegation.
    # 3. Otherwise default narrow agent delegation, then reduce for taint.
    # Client metadata user_granted_capabilities / approved / delegated_authority
    # are never consulted for enforcement.
    if delegation is not None and getattr(delegation, "integrity", None) == "verified":
        base_dlg = delegation
    else:
        client_dlg = extract_client_delegation(metadata)  # always unverified
        _ = client_dlg  # intentionally discarded for enforcement
        if server_verified_user:
            granted = server_granted_capabilities
            if isinstance(granted, list) and granted:
                base_dlg = user_delegation(
                    granted,
                    resources=server_granted_resources or ["*"],
                    trace_scope=data.get("trace_id"),
                )
            else:
                base_dlg = user_delegation(
                    required.required or ["READ_PUBLIC"],
                    resources=[required.resource or "*"],
                    trace_scope=data.get("trace_id"),
                )
        else:
            base_dlg = default_agent_delegation(trace_scope=data.get("trace_id"))

    auth = evaluate_authority(required, base_dlg, taint=taint, sources=sources)
    causal = _causal_from_sources(sources, metadata)
    flow = _flow_analysis(data, sources, taint, required.required)

    analysis = ProvenanceAnalysis(
        sources=sources,
        taint=taint,
        authority=auth,
        flow=flow,
        causal=causal,
    )
    analysis.findings = _build_findings(analysis)
    analysis.explanation = _explanation(analysis, data)
    analysis.attack_path = _attack_path(analysis, data)
    analysis.latency_ms = round((time.perf_counter() - start) * 1000.0, 3)

    if graph is not None and data.get("trace_id"):
        node = graph.add_node(
            __import__("varden.provenance.models", fromlist=["GraphNode"]).GraphNode(
                node_id=new_id("node"),
                node_type={
                    "http_request": "http_request",
                    "subprocess": "subprocess",
                    "file_read": "file_read",
                    "file_write": "file_write",
                    "llm_call": "llm_call",
                    "tool_call": "tool_call",
                    "mcp_call": "mcp_call",
                }.get(str(data.get("type") or ""), "tool_call"),
                trace_id=str(data.get("trace_id") or ""),
                label=str(data.get("tool") or data.get("type") or "action"),
                source_ids=[s.source_id for s in sources],
                authority_required=list(auth.required),
                trust_level=min((s.trust_level for s in sources), key=trust_rank) if sources else "unknown",
                taints=sorted(taint.tags),
                metadata={"resource": auth.resource},
            )
        )
        analysis.causal.path.append({"node_id": node.node_id, "label": node.label})

    return analysis


def enrich(
    action: Action,
    payload: Any = None,
    *,
    store: Any | None = None,
    server_verified_user: bool = False,
    server_granted_capabilities: list[str] | None = None,
    server_granted_resources: list[str] | None = None,
) -> Action:
    """Enrich a Varden Action with provenance/authority metadata for PolicyEngine.

    Safe to call even when no provenance context exists: missing provenance
    becomes explicit ``unknown``, never silent trust.

    ``server_verified_*`` kwargs are process-local only (eval harness / trusted
    integrations). They are never populated from HTTP request metadata.
    """
    meta = dict(action.metadata or {})
    # Allow integrations to pass prior taint via metadata._prior_taints
    prior_taints = None
    if isinstance(meta.get("_prior_taints"), dict):
        prior_taints = TaintSet.from_dict(meta["_prior_taints"])

    prior_sources = None
    prior_lookup_failed = False
    if store is not None and action.trace_id:
        try:
            prior_sources = store.sources_for_trace(action.trace_id, tenant_id=action.tenant_id)
        except Exception:
            prior_sources = None
            prior_lookup_failed = True

    # Server-side active delegation for this trace, if any.
    delegation = None
    if store is not None and action.trace_id:
        try:
            delegation = store.active_delegation(action.trace_id, tenant_id=action.tenant_id)
        except Exception:
            delegation = None
            prior_lookup_failed = True

    analysis = analyse_action(
        action,
        delegation=delegation,
        prior_sources=prior_sources,
        prior_taints=prior_taints,
        server_verified_user=server_verified_user,
        server_granted_capabilities=server_granted_capabilities,
        server_granted_resources=server_granted_resources,
        prior_lookup_failed=prior_lookup_failed,
    )
    enriched = analysis.to_metadata()

    # Merge without dropping unrelated metadata.
    for key, value in enriched.items():
        meta[key] = value

    # Convenience classifier-style booleans for simple policy predicates.
    classifiers = dict(action.classifiers or {})
    classifiers["provenance_untrusted"] = analysis.taint.is_untrusted() or analysis.causal.untrusted_ancestor
    classifiers["provenance_unknown"] = analysis.causal.unknown_ancestor or not analysis.causal.provenance_complete
    classifiers["authority_violation"] = analysis.authority.violation
    classifiers["authority_escalation"] = analysis.authority.escalation
    classifiers["confused_deputy"] = any(f.get("type") == "confused_deputy" for f in analysis.findings)
    classifiers["exfiltration_chain"] = any(f.get("type") == "provenance_exfiltration_chain" for f in analysis.findings)
    classifiers["cross_server_flow"] = analysis.flow.cross_server
    classifiers["untrusted_to_privileged"] = analysis.flow.untrusted_to_privileged
    action.classifiers = classifiers
    action.metadata = meta

    if store is not None:
        try:
            store.record_analysis(action, analysis)
        except Exception:
            # Persistence failure must not fail open the security decision —
            # analysis metadata is already on the action for PolicyEngine.
            pass

    return action


def explain_analysis(analysis: ProvenanceAnalysis | dict[str, Any], *, decision: str | None = None) -> str:
    """Human-readable explanation for CLI / dashboard."""
    if isinstance(analysis, dict):
        # Rehydrate minimally from metadata shape.
        auth = analysis.get("authority") or {}
        lines = analysis.get("explanation") or []
        findings = analysis.get("findings") or []
        path = analysis.get("attack_path") or []
    else:
        auth = analysis.authority.to_dict()
        lines = analysis.explanation
        findings = analysis.findings
        path = analysis.attack_path

    header = "AUTHORITY-FLOW ANALYSIS"
    if decision:
        header = f"{decision.upper()}: authority-flow decision"
    parts = [header, ""]
    for line in lines:
        parts.append(f"  {line}")
    if path:
        parts.append("")
        parts.append("Causal path:")
        for step in path:
            parts.append(f"  {step}")
    if findings:
        parts.append("")
        parts.append("Findings:")
        for finding in findings:
            parts.append(f"  - {finding.get('type')}: {finding.get('explanation')}")
    if auth:
        parts.append("")
        parts.append(f"Required: {auth.get('required')}")
        parts.append(f"Delegated: {auth.get('granted')}")
        parts.append(f"Missing: {auth.get('missing')}")
    return "\n".join(parts)
