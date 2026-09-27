"""Emit deterministic graph facts from normalized Varden actions.

Counterfactual / predictive analysis must never execute tools. This module
only inspects Action fields and existing provenance metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..models import Action
from .capability import (
    Capability,
    CapabilityEvidence,
    CapabilityKind,
    enables_capabilities,
    potential_grants_for_credential,
)
from .evidence import AuthorityLifecycle, EvidenceKind, make_evidence
from .graph import CapabilityGraph, EdgeEvidence, EdgeKind, GraphEdge, GraphNode
from .lifecycle import add_sanitisation_boundary
from .resource import (
    Sensitivity,
    TrustLevel,
    credential_resource,
    filesystem_resource,
    mcp_server_resource,
    mcp_tool_resource,
    network_origin_resource,
    sanitize_identifier,
    untrusted_content_resource,
)
from .reversibility import classify_action_reversibility, classify_capability_reversibility
from .state import AuthorityState


@dataclass
class ActionFacts:
    """Facts extracted from a single action — no side effects."""

    capabilities: list[Capability] = field(default_factory=list)
    resources: list[Any] = field(default_factory=list)
    action_node_id: str = ""
    action_label: str = ""
    irreversible: bool = False
    summary: str = ""
    provenance_refs: list[str] = field(default_factory=list)
    trust_domains: list[str] = field(default_factory=list)
    sanitisation_trusted: bool = False
    sanitisation_fake: bool = False
    untrusted_capability_claims: list[str] = field(default_factory=list)


_AWS_CRED_PATH = re.compile(r"(?i)(\.aws|/aws/|credentials|\.env)")
_GITHUB_CRED = re.compile(r"(?i)(ghp_|github.?token|\.git-credentials)")
_SSH_PATH = re.compile(r"(?i)(\.ssh|id_rsa|id_ed25519)")


def _path_from_action(action: Action) -> str | None:
    args = action.args or {}
    for key in ("path", "file", "filename", "filepath", "target"):
        if key in args and args[key]:
            return str(args[key])
    # Common open()/Path patterns: args.args = [path, mode]
    positional = args.get("args")
    if isinstance(positional, (list, tuple)) and positional:
        return str(positional[0])
    meta = action.metadata or {}
    fs = meta.get("filesystem") or {}
    if isinstance(fs, dict) and fs.get("path"):
        return str(fs["path"])
    if meta.get("path"):
        return str(meta["path"])
    return None


def _trust_from_provenance(action: Action) -> TrustLevel:
    meta = action.metadata or {}
    sources = meta.get("provenance_sources") or []
    levels: list[str] = []
    for src in sources:
        if isinstance(src, dict):
            levels.append(str(src.get("trust_level") or "unknown"))
    analysis = meta.get("provenance") or meta.get("authority") or {}
    if isinstance(analysis, dict):
        levels.append(str(analysis.get("min_trust") or analysis.get("trust_level") or "unknown"))
    if any(l in {"hostile"} for l in levels):
        return TrustLevel.HOSTILE
    if any(l in {"untrusted"} for l in levels):
        return TrustLevel.UNTRUSTED
    if action.classifiers.get("provenance_untrusted") or action.classifiers.get("untrusted_to_privileged"):
        return TrustLevel.UNTRUSTED
    if any(l in {"trusted"} for l in levels):
        return TrustLevel.TRUSTED
    return TrustLevel.UNKNOWN


def extract_facts(action: Action) -> ActionFacts:
    """Pure extraction — never executes tools or reads files."""
    facts = ActionFacts()
    at = str(action.type or "").lower()
    tool = str(action.tool or "").lower()
    method = str(action.method or "").upper()
    path = _path_from_action(action)
    trust = _trust_from_provenance(action)
    rev = classify_action_reversibility(at, tool=tool, method=method)
    facts.irreversible = rev.value == "irreversible"

    # Provenance / untrusted sources as graph roots.
    meta = action.metadata or {}
    for src in meta.get("provenance_sources") or []:
        if not isinstance(src, dict):
            continue
        sid = str(src.get("source_id") or src.get("id") or src.get("type") or "source")
        stype = str(src.get("type") or src.get("source_type") or "unknown")
        trust_l = TrustLevel(str(src.get("trust_level") or "unknown")) if str(src.get("trust_level") or "unknown") in TrustLevel._value2member_map_ else TrustLevel.UNKNOWN
        if trust_l in {TrustLevel.UNTRUSTED, TrustLevel.HOSTILE} or stype in {
            "web_page",
            "http_response",
            "email",
            "chat_message",
            "mcp_tool_response",
            "mcp_tool_definition",
        }:
            res = untrusted_content_resource(f"{stype}:{sid}", trust=trust_l)
            facts.resources.append(res)
            facts.provenance_refs.append(res.node_id)
            server = src.get("server") or src.get("mcp_server")
            if server:
                facts.resources.append(mcp_server_resource(str(server), trust=trust_l))
                facts.trust_domains.append(f"mcp:{server}")

    # Filesystem
    if at in {"filesystem_read", "file_read"} or "read" in tool or tool in {"open", "pathlib.path.open", "builtins.open"}:
        if path:
            res = filesystem_resource(path, trust=trust)
            facts.resources.append(res)
            if res.sensitivity in {Sensitivity.SECRET, Sensitivity.CREDENTIAL}:
                facts.capabilities.append(
                    Capability(
                        name="filesystem.read.secret",
                        sensitivity=80,
                        mutating=False,
                        reversible="unknown",
                        evidence=CapabilityEvidence.OBSERVED,
                    )
                )
                # Credential acquisition (potential grants).
                if _AWS_CRED_PATH.search(path):
                    cred = credential_resource("credential.aws", known_scope=False)
                    facts.resources.append(cred)
                    facts.capabilities.append(
                        Capability(
                            name="credential.aws",
                            sensitivity=85,
                            mutating=False,
                            reversible="unknown",
                            evidence=CapabilityEvidence.OBSERVED,
                        )
                    )
                    facts.capabilities.extend(potential_grants_for_credential("credential.aws"))
                elif _GITHUB_CRED.search(path):
                    facts.resources.append(credential_resource("credential.github", known_scope=False))
                    facts.capabilities.append(
                        Capability(name="credential.github", sensitivity=80, evidence=CapabilityEvidence.OBSERVED)
                    )
                    facts.capabilities.extend(potential_grants_for_credential("credential.github"))
                elif _SSH_PATH.search(path):
                    facts.resources.append(credential_resource("credential.ssh", known_scope=False))
                    facts.capabilities.append(
                        Capability(name="credential.ssh", sensitivity=85, evidence=CapabilityEvidence.OBSERVED)
                    )
                    facts.capabilities.extend(potential_grants_for_credential("credential.ssh"))
            else:
                facts.capabilities.append(
                    Capability(
                        name="filesystem.read.workspace",
                        sensitivity=20,
                        mutating=False,
                        reversible="reversible",
                        evidence=CapabilityEvidence.OBSERVED,
                    )
                )
        facts.summary = f"filesystem.read {path or tool or ''}".strip()

    if at in {"filesystem_write", "file_write"} or tool in {"path.write_text", "builtins.open"} and method == "WRITE":
        if path:
            facts.resources.append(filesystem_resource(path, trust=trust))
        facts.capabilities.append(
            Capability(
                name="filesystem.write.workspace",
                sensitivity=35,
                mutating=True,
                reversible="conditionally_reversible",
                evidence=CapabilityEvidence.OBSERVED,
            )
        )
        facts.summary = facts.summary or f"filesystem.write {path or ''}".strip()

    # Explicit mode on open: 'w' etc.
    if tool in {"open", "builtins.open", "io.open"} and path:
        mode = ""
        args = action.args or {}
        if isinstance(args.get("args"), (list, tuple)) and len(args["args"]) > 1:
            mode = str(args["args"][1])
        mode = mode or str(args.get("mode") or "")
        if any(m in mode for m in ("w", "a", "x", "+")):
            facts.capabilities.append(
                Capability(
                    name="filesystem.write.workspace",
                    sensitivity=35,
                    mutating=True,
                    reversible="conditionally_reversible",
                    evidence=CapabilityEvidence.OBSERVED,
                )
            )

    # HTTP
    if at in {"http_request", "network"} or "http" in tool or "requests" in tool or "urllib" in tool:
        url = action.url or (action.args or {}).get("url") or ""
        write = method in {"POST", "PUT", "PATCH", "DELETE"} or "post" in tool
        if url:
            sink = network_origin_resource(str(url), write=write)
            facts.resources.append(sink)
        cap_name = "http.write.external" if write else "http.read.external"
        facts.capabilities.append(
            Capability(
                name=cap_name,
                sensitivity=60 if write else 25,
                mutating=write,
                reversible="irreversible" if write else "reversible",
                evidence=CapabilityEvidence.OBSERVED,
            )
        )
        facts.irreversible = facts.irreversible or write
        facts.summary = f"http.{'write' if write else 'read'} {action.domain or url}".strip()

    # Subprocess
    if at in {"subprocess", "shell"} or "subprocess" in tool:
        privileged = False
        cmd = str((action.args or {}).get("args") or (action.args or {}).get("cmd") or "")
        if any(tok in cmd.lower() for tok in ("sudo", "aws ", "kubectl", "terraform", "docker")):
            privileged = True
        name = "subprocess.execute.privileged" if privileged else "subprocess.execute.local"
        facts.capabilities.append(
            Capability(
                name=name,
                sensitivity=85 if privileged else 40,
                mutating=True,
                reversible="unknown",
                evidence=CapabilityEvidence.OBSERVED,
            )
        )
        # Subprocess can enable network sink (potential).
        for enabled in enables_capabilities(name):
            facts.capabilities.append(
                Capability(
                    name=enabled,
                    kind=CapabilityKind.POTENTIAL,
                    sensitivity=50,
                    mutating="write" in enabled or "destroy" in enabled,
                    reversible=classify_capability_reversibility(enabled).value,
                    evidence=CapabilityEvidence.POTENTIAL,
                    grant_source=name,
                )
            )
        facts.summary = f"subprocess {cmd[:80]}".strip()

    # MCP
    if at.startswith("mcp") or "mcp" in tool:
        server = str((action.metadata or {}).get("mcp_server") or (action.args or {}).get("server") or "unknown")
        mcp_tool = str(action.tool or (action.args or {}).get("tool") or "tool")
        privileged = bool(
            action.classifiers.get("mcp_privileged")
            or any(tok in mcp_tool.lower() for tok in ("delete", "admin", "secret", "credential", "exec", "shell"))
        )
        facts.resources.append(mcp_server_resource(server, trust=trust))
        facts.resources.append(mcp_tool_resource(server, mcp_tool, privileged=privileged))
        facts.capabilities.append(
            Capability(
                name=f"mcp.invoke.{server}.{mcp_tool}",
                sensitivity=70 if privileged else 30,
                mutating=privileged,
                reversible="unknown",
                evidence=CapabilityEvidence.OBSERVED,
            )
        )
        facts.trust_domains.append(f"mcp:{server}")
        facts.summary = f"mcp.invoke {server}/{mcp_tool}"

        # Graph poisoning defence: untrusted MCP self-declared capabilities
        # are recorded as UNTRUSTED_DECLARED / potential — never confirmed.
        declared = (
            (action.metadata or {}).get("declared_capabilities")
            or (action.args or {}).get("capabilities")
            or (action.metadata or {}).get("capabilities")
        )
        if isinstance(declared, list) and declared:
            for item in declared:
                name = str(item or "").strip().lower()
                if not name:
                    continue
                facts.untrusted_capability_claims.append(name)
                facts.capabilities.append(
                    Capability(
                        name=name,
                        kind=CapabilityKind.POTENTIAL,
                        sensitivity=90,
                        mutating=True,
                        reversible="unknown",
                        evidence=CapabilityEvidence.POTENTIAL,
                        grant_source=f"untrusted_mcp:{server}",
                        metadata={
                            "untrusted_declared": True,
                            "assertion_actor": f"mcp:{server}",
                            "evidence_kind": "untrusted_declared",
                        },
                    )
                )

    # Trusted sanitisation marker from Varden (never from untrusted self-claims alone).
    if action.classifiers.get("sanitised") or (action.metadata or {}).get("varden_sanitised"):
        facts.sanitisation_trusted = True
    if (action.metadata or {}).get("claimed_sanitised") and not (
        action.classifiers.get("sanitised") or (action.metadata or {}).get("varden_sanitised")
    ):
        facts.sanitisation_fake = True
    # Tool call generic
    if not facts.summary:
        facts.summary = f"{at}:{tool}" if tool else at or "action"

    facts.summary = sanitize_identifier(facts.summary)
    facts.action_label = facts.summary
    facts.action_node_id = f"action:{facts.summary}"[:200]
    return facts


def apply_facts_to_state(state: AuthorityState, facts: ActionFacts) -> None:
    """Mutate session state + graph with extracted facts."""
    g = state.graph

    # Action node
    g.add_node(
        GraphNode(
            node_id=facts.action_node_id,
            node_type="action",
            label=facts.action_label,
            confirmed=True,
            metadata={"irreversible": facts.irreversible},
        )
    )

    for res in facts.resources:
        state.add_resource(res)
        confirmed = res.sensitivity != Sensitivity.PUBLIC
        g.add_node(
            GraphNode(
                node_id=res.node_id,
                node_type=res.resource_type.value,
                label=res.identifier,
                confirmed=True,
                metadata={
                    "sensitivity": res.sensitivity.value,
                    "trust_level": res.trust_level.value,
                    "external": res.external,
                    "external_sink": res.external and bool((res.metadata or {}).get("write") or res.resource_type.value == "network_origin"),
                    "sink": res.external and bool((res.metadata or {}).get("write")),
                    "credential": res.resource_type.value == "credential" or res.sensitivity == Sensitivity.CREDENTIAL,
                    "authority_domain": res.authority_domain,
                },
            )
        )
        # Untrusted content influences action.
        if res.resource_type.value == "untrusted_content":
            g.add_edge(
                GraphEdge(
                    src=res.node_id,
                    dst=facts.action_node_id,
                    kind=EdgeKind.INFLUENCES,
                    evidence=EdgeEvidence.OBSERVED,
                    label="influences",
                )
            )

    for cap in facts.capabilities:
        state.add_capability(cap)
        untrusted_claim = bool((cap.metadata or {}).get("untrusted_declared"))
        lifecycle = (
            AuthorityLifecycle.POTENTIAL
            if untrusted_claim or cap.kind == CapabilityKind.POTENTIAL
            else AuthorityLifecycle.CONFIRMED
        )
        g.add_node(
            GraphNode(
                node_id=cap.node_id,
                node_type="capability",
                label=cap.name,
                confirmed=lifecycle == AuthorityLifecycle.CONFIRMED,
                lifecycle=lifecycle,
                metadata={
                    "kind": cap.kind.value,
                    "sensitivity": cap.sensitivity,
                    "domain": cap.domain,
                    "credential": cap.name.startswith("credential."),
                    "external_sink": cap.name.startswith("http.write"),
                    "sink": cap.name.startswith("http.write"),
                    "untrusted_declared": untrusted_claim,
                },
            )
        )
        if untrusted_claim:
            ev = make_evidence(
                EvidenceKind.UNTRUSTED_DECLARED,
                source="mcp_tool_metadata",
                assertion_actor=str((cap.metadata or {}).get("assertion_actor") or "untrusted"),
                lifecycle=AuthorityLifecycle.POTENTIAL,
                description="Untrusted MCP self-declared capability — not confirmed",
            )
        elif cap.kind == CapabilityKind.POTENTIAL:
            ev = make_evidence(
                EvidenceKind.POTENTIAL,
                source="interceptor_derived",
                assertion_actor="varden",
                lifecycle=AuthorityLifecycle.POTENTIAL,
                description="Potential grant from credential classification",
            )
        else:
            ev = make_evidence(
                EvidenceKind.RUNTIME_OBSERVED,
                source="interceptor",
                assertion_actor="varden",
                lifecycle=AuthorityLifecycle.CONFIRMED,
                description="Observed capability from intercepted action",
            )
        g.add_edge(
            GraphEdge(
                src=facts.action_node_id,
                dst=cap.node_id,
                kind=EdgeKind.INTRODUCES,
                evidence=ev,
                label="introduces",
            )
        )
        if cap.grant_source:
            src_id = f"cap:{cap.grant_source}" if not cap.grant_source.startswith("cap:") else cap.grant_source
            # Also try potential prefix.
            if g.get_node(src_id) or g.get_node(f"cap.potential:{cap.grant_source}"):
                real_src = src_id if g.get_node(src_id) else f"cap.potential:{cap.grant_source}"
                g.add_edge(
                    GraphEdge(
                        src=real_src,
                        dst=cap.node_id,
                        kind=EdgeKind.ENABLES if cap.kind == CapabilityKind.POTENTIAL else EdgeKind.GRANTS,
                        evidence=EdgeEvidence.POTENTIAL if cap.kind == CapabilityKind.POTENTIAL else EdgeEvidence.INFERRED,
                        label="grants" if cap.name.startswith("aws.") else "enables",
                    )
                )

    # Link secrets/credentials to capabilities and sinks.
    for res in facts.resources:
        if res.resource_type.value == "credential" or res.sensitivity == Sensitivity.CREDENTIAL:
            for cap in facts.capabilities:
                if cap.name.startswith("credential.") or cap.grant_source:
                    g.add_edge(
                        GraphEdge(
                            src=res.node_id,
                            dst=cap.node_id,
                            kind=EdgeKind.GRANTS,
                            evidence=EdgeEvidence.OBSERVED if cap.kind == CapabilityKind.CONFIRMED else EdgeEvidence.POTENTIAL,
                            label="grants",
                        )
                    )
        if res.external and (res.metadata or {}).get("write"):
            for cap in facts.capabilities:
                if "http.write" in cap.name or cap.name.startswith("credential."):
                    g.add_edge(
                        GraphEdge(
                            src=cap.node_id,
                            dst=res.node_id,
                            kind=EdgeKind.REACHES,
                            evidence=EdgeEvidence.OBSERVED,
                            label="reaches",
                        )
                    )

    # Cross-action continuity: existing untrusted provenance → new sensitive/credential.
    existing_untrusted = [
        nid
        for nid, node in ((n.node_id, n) for n in g.nodes())
        if node.node_type == "untrusted_content"
        or str((node.metadata or {}).get("trust_level") or "") in {"untrusted", "hostile"}
    ]
    for ref in state.provenance_refs:
        if ref not in existing_untrusted:
            existing_untrusted.append(ref)

    new_sensitive = [
        r.node_id
        for r in facts.resources
        if r.sensitivity in {Sensitivity.SECRET, Sensitivity.CREDENTIAL, Sensitivity.SENSITIVE}
        or r.resource_type.value == "credential"
    ]
    # Also credentials introduced as capabilities.
    new_cred_caps = [c.node_id for c in facts.capabilities if c.name.startswith("credential.")]

    for p in existing_untrusted:
        for s in new_sensitive + new_cred_caps:
            g.add_edge(
                GraphEdge(
                    src=p,
                    dst=s,
                    kind=EdgeKind.FLOWS_TO,
                    evidence=EdgeEvidence.INFERRED,
                    label="flows_to",
                )
            )

    # Same-action provenance → sensitive.
    for p in [r.node_id for r in facts.resources if r.resource_type.value == "untrusted_content"]:
        for s in new_sensitive:
            g.add_edge(
                GraphEdge(
                    src=p,
                    dst=s,
                    kind=EdgeKind.FLOWS_TO,
                    evidence=EdgeEvidence.INFERRED,
                    label="flows_to",
                )
            )

    # Existing credentials / secret caps → new external sinks / http.write.
    existing_creds = [
        n.node_id
        for n in g.nodes()
        if (n.metadata or {}).get("credential")
        or n.node_id.startswith("cap:credential.")
        or n.node_type == "credential"
    ]
    new_sinks = [r.node_id for r in facts.resources if r.external and (r.metadata or {}).get("write")]
    new_http_write = [c.node_id for c in facts.capabilities if "http.write" in c.name]
    for cred in existing_creds:
        for sink in new_sinks + new_http_write:
            g.add_edge(
                GraphEdge(
                    src=cred,
                    dst=sink,
                    kind=EdgeKind.REACHES,
                    evidence=EdgeEvidence.INFERRED,
                    label="reaches",
                )
            )

    # Sensitive -> subprocess -> network edges within same action facts.
    sens = [r for r in facts.resources if r.sensitivity in {Sensitivity.SECRET, Sensitivity.CREDENTIAL}]
    sub_caps = [c for c in facts.capabilities if c.name.startswith("subprocess.")]
    http_caps = [c for c in facts.capabilities if "http.write" in c.name]
    for s in sens:
        for c in sub_caps:
            g.add_edge(
                GraphEdge(
                    src=s.node_id,
                    dst=c.node_id,
                    kind=EdgeKind.FLOWS_TO,
                    evidence=EdgeEvidence.INFERRED,
                    label="via_subprocess",
                )
            )
            for hc in http_caps:
                g.add_edge(
                    GraphEdge(
                        src=c.node_id,
                        dst=hc.node_id,
                        kind=EdgeKind.ENABLES,
                        evidence=EdgeEvidence.POTENTIAL,
                        label="enables",
                    )
                )

    # Cross-MCP: link prior MCP domain resources to new MCP invocations.
    new_mcp = [r for r in facts.resources if r.resource_type.value in {"mcp_server", "mcp_tool"}]
    prior_mcp = [
        n
        for n in g.nodes()
        if n.node_type in {"mcp_server", "mcp_tool"} and n.node_id not in {r.node_id for r in new_mcp}
    ]
    for prior in prior_mcp:
        for nxt in new_mcp:
            if (prior.metadata or {}).get("authority_domain") != nxt.authority_domain:
                g.add_edge(
                    GraphEdge(
                        src=prior.node_id,
                        dst=nxt.node_id,
                        kind=EdgeKind.FLOWS_TO,
                        evidence=EdgeEvidence.INFERRED,
                        label="cross_mcp",
                    )
                )

    for ref in facts.provenance_refs:
        if ref not in state.provenance_refs:
            state.provenance_refs.append(ref)
    if facts.irreversible and facts.summary not in state.irreversible_actions:
        state.irreversible_actions.append(facts.summary)

    # Sanitisation / fake sanitisation between sensitive resources and sinks.
    sens = [
        r.node_id
        for r in facts.resources
        if r.sensitivity in {Sensitivity.SECRET, Sensitivity.CREDENTIAL, Sensitivity.SENSITIVE}
        or r.resource_type.value == "credential"
    ]
    # Cross-action: include already-known sensitive/credential nodes in the session graph.
    for n in g.nodes():
        if (n.metadata or {}).get("credential") or str((n.metadata or {}).get("sensitivity") or "") in {
            "secret",
            "credential",
            "sensitive",
        }:
            if n.node_id not in sens:
                sens.append(n.node_id)
    sinks = [r.node_id for r in facts.resources if r.external and (r.metadata or {}).get("write")]
    http_caps = [c.node_id for c in facts.capabilities if "http.write" in c.name]
    # Also terminate edges into any existing http.write* capability nodes.
    for n in g.nodes():
        if "http.write" in n.node_id or (n.metadata or {}).get("external_sink"):
            if n.node_id not in http_caps:
                http_caps.append(n.node_id)
    targets = sinks + http_caps
    if sens and targets:
        if facts.sanitisation_trusted:
            add_sanitisation_boundary(
                g,
                from_node=sens[0],
                boundary_id=f"sanitise:{sens[0]}:{targets[0]}",
                to_node=targets[0],
                trusted=True,
                source="varden_sanitiser",
            )
            # Remove direct sensitive→sink edges so sanitisation terminates the flow.
            for edge in list(g.edges()):
                src_node = g.get_node(edge.src)
                sensitive_src = bool(
                    edge.src in sens
                    or (src_node and ((src_node.metadata or {}).get("credential") or str((src_node.metadata or {}).get("sensitivity") or "") in {"secret", "credential", "sensitive"}))
                    or "credential." in edge.src
                )
                if sensitive_src and edge.dst in targets and edge.kind in {
                    EdgeKind.FLOWS_TO,
                    EdgeKind.REACHES,
                    EdgeKind.ENABLES,
                    EdgeKind.GRANTS,
                    EdgeKind.MAY_GRANT,
                }:
                    g.remove_edge(edge.edge_id)
        elif facts.sanitisation_fake:
            add_sanitisation_boundary(
                g,
                from_node=sens[0],
                boundary_id=f"fake_sanitise:{sens[0]}:{targets[0]}",
                to_node=targets[0],
                trusted=False,
                source="untrusted_claim",
            )
