"""Incident read model for Authority & Provenance UI.

An *incident* is one guarded action / security event. Multiple findings
attached to that action are properties of the same incident — never
separate attacks.

Security decisions remain backend-owned. This module only shapes
persisted event evidence for operators.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

FINDING_LABELS: dict[str, str] = {
    "confused_deputy": "Confused deputy",
    "untrusted_to_privileged": "Untrusted source attempted privileged action",
    "authority_escalation": "Authority escalation",
    "delegation_violation": "Missing delegated authority",
    "provenance_exfiltration_chain": "Potential data exfiltration",
    "unknown_provenance_sensitive_action": "Sensitive action with unknown origin",
    "cross_server_authority_flow": "Cross-server authority flow",
    "cross_origin_authority_flow": "Cross-origin authority flow",
}

FINDING_BLURBS: dict[str, str] = {
    "confused_deputy": "Untrusted input attempted to use the agent's privileged access.",
    "untrusted_to_privileged": "An untrusted source influenced a privileged capability.",
    "authority_escalation": "The action needed more authority than this causal chain was granted.",
    "delegation_violation": "Required authority was not present in the delegated set.",
    "provenance_exfiltration_chain": "Sensitive data was headed toward a public destination.",
    "unknown_provenance_sensitive_action": "A sensitive action ran with incomplete or unknown provenance.",
    "cross_server_authority_flow": "Authority crossed MCP server boundaries in this chain.",
    "cross_origin_authority_flow": "Authority crossed origin boundaries in this chain.",
}

SEVERITY_RANK = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 0}

# Soft bound for full lineage expansion (never claim completeness past this).
_FULL_LINEAGE_NODE_CAP = 40


def humanize_finding(finding_type: str | None) -> str:
    key = str(finding_type or "").strip()
    return FINDING_LABELS.get(key, key.replace("_", " ").strip() or "Finding")


def finding_blurb(finding_type: str | None) -> str:
    key = str(finding_type or "").strip()
    return FINDING_BLURBS.get(key, humanize_finding(key))


def truncate_path(value: str, limit: int = 48) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _max_severity(findings: list[dict[str, Any]], *, fallback: str = "info") -> str:
    best = fallback
    best_rank = SEVERITY_RANK.get(fallback, 0)
    for finding in findings:
        sev = str(finding.get("severity") or "info").lower()
        rank = SEVERITY_RANK.get(sev, 0)
        if rank > best_rank:
            best, best_rank = sev, rank
    return best


def _decision_label(event: dict[str, Any]) -> str:
    status = str(event.get("status") or "").lower()
    decision = event.get("decision") or {}
    action = str(decision.get("action") or "").lower()
    if status == "blocked" or action in {"block", "blocked"}:
        return "blocked"
    if action in {"require_approval", "approval_required"}:
        return "approval_required"
    if action in {"sanitise", "sanitize", "sanitised", "sanitized"}:
        return "sanitised"
    if status in {"warned", "warn"} or action in {"warn", "warned"}:
        return "warned"
    if status == "monitor" or action == "monitor":
        return "monitored"
    return "allowed"


def _primary_finding_type(findings: list[dict[str, Any]]) -> str | None:
    """Prefer narrative finding types over overlapping technical siblings."""
    priority = (
        "provenance_exfiltration_chain",
        "confused_deputy",
        "cross_server_authority_flow",
        "untrusted_to_privileged",
        "unknown_provenance_sensitive_action",
        "authority_escalation",
        "delegation_violation",
    )
    types = {str(f.get("type") or "") for f in findings if isinstance(f, dict)}
    for key in priority:
        if key in types:
            return key
    for f in findings:
        if isinstance(f, dict) and f.get("type"):
            return str(f["type"])
    return None


def _human_tool_label(tool: str | None, action_type: str | None = None) -> str:
    name = str(tool or "").strip()
    if not name:
        return {
            "file_read": "File read",
            "file_write": "File write",
            "http_request": "HTTP request",
            "http_call": "HTTP request",
            "mcp_call": "MCP tool call",
            "subprocess": "Subprocess",
        }.get(str(action_type or ""), "Action")
    pretty = name.replace("_", " ").replace("-", " ").strip()
    return pretty[:1].upper() + pretty[1:] if pretty else "Action"


def _title_for_incident(
    *,
    decision: str,
    findings: list[dict[str, Any]],
    tool: str | None,
    resource: str | None,
    authority: dict[str, Any],
    action_type: str | None = None,
    method: str | None = None,
) -> str:
    primary = _primary_finding_type(findings)
    res = str(resource or "")
    if primary == "provenance_exfiltration_chain":
        return "Sensitive data headed toward a public destination"
    if primary == "confused_deputy":
        if action_type in {"file_read", "filesystem"} or tool == "read_file":
            if "READ_PRIVATE" in (authority.get("required") or []) or "/Documents/" in res:
                return "Private file access from untrusted MCP"
        if "mcp://" in res or action_type == "mcp_call":
            return "Untrusted input attempted privileged CRM access"
        return "Untrusted input attempted to use privileged access"
    if primary == "cross_server_authority_flow":
        return "Untrusted MCP attempted a privileged server action"
    if primary == "untrusted_to_privileged":
        return "Untrusted source attempted a privileged action"
    if primary in {"authority_escalation", "delegation_violation"}:
        missing = authority.get("missing") or []
        if missing:
            return f"Attempted {', '.join(missing[:3])} without delegated authority"
        return "Privileged action without matching delegated authority"
    if primary == "unknown_provenance_sensitive_action":
        return "Sensitive action with unknown origin"

    # Benign / non-finding titles — human event first, not decision+tool.
    if action_type in {"file_read", "filesystem"} or tool == "read_file":
        if "README" in res.upper() or "/workspace" in res or "varden-workspace" in res:
            return "Workspace file read"
        if any(x in res for x in (".ssh", ".aws", ".env", "credentials")):
            return "Secret file access attempt"
        if "/Documents/" in res or "READ_PRIVATE" in (authority.get("required") or []):
            return "Private file access"
        return "File read"
    if action_type in {"http_request", "http_call"}:
        host = ""
        try:
            host = (urlparse(res).hostname or "")
        except Exception:
            host = ""
        if "weather" in host:
            return "Weather API request"
        if method and method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            return f"Outbound {method.upper()} to {host or 'remote host'}"
        return f"HTTP request to {host or 'remote host'}"
    if action_type == "mcp_call":
        return f"MCP tool: {_human_tool_label(tool)}"
    if decision == "approval_required":
        return f"Approval required for {_human_tool_label(tool, action_type)}"
    if decision == "blocked":
        return f"Blocked {_human_tool_label(tool, action_type)}"
    if decision == "warned":
        return _human_tool_label(tool, action_type)
    if decision == "sanitised":
        return f"Sanitised {_human_tool_label(tool, action_type)}"
    return _human_tool_label(tool, action_type)


def _parse_mcp_ref(value: str) -> tuple[str | None, str | None]:
    text = str(value or "").strip()
    if text.startswith("mcp://"):
        rest = text[len("mcp://"):]
        server, _, tool = rest.partition("/")
        return (server or None), (tool or None)
    if text.startswith("mcp:"):
        return text[4:] or None, None
    return None, None


def _display_host(url_or_host: str) -> str:
    text = str(url_or_host or "")
    try:
        parsed = urlparse(text if "://" in text else f"https://{text}")
        return parsed.hostname or text
    except Exception:
        return text


def _basename(path: str) -> str:
    text = str(path or "").rstrip("/")
    if not text:
        return ""
    return text.split("/")[-1].split("\\")[-1]


def _enforcement_outcome(event: dict[str, Any], *, decision: str, action_type: str | None, tool: str | None, resource: str | None) -> dict[str, Any]:
    """Derive outcome claims only from enforcement evidence.

    Primary label = what did not happen. Secondary detail = how Varden intervened.
    """
    action = event.get("action") or {}
    meta = action.get("metadata") or {}
    enf = dict(meta.get("enforcement") or {})

    prevented: bool | None
    if "side_effect_prevented" in enf:
        raw = enf.get("side_effect_prevented")
        prevented = None if raw is None else bool(raw)
        basis = str(enf.get("surface") or "enforcement_stamp")
    elif enf.get("surface") == "sdk_log":
        prevented = None
        basis = "sdk_log"
    elif meta.get("authority") is not None and decision in {"blocked", "approval_required"}:
        prevented = True
        basis = "guarded_evaluation"
    else:
        prevented = None
        basis = "unknown"

    tool_l = str(tool or "action")
    res = str(resource or "")
    host = _display_host(res)
    file_name = _basename(res) or "file"

    if prevented is True:
        if action_type in {"http_request", "http_call"}:
            label = "NO DATA WAS SENT"
            detail = "Varden stopped the outbound request before transmission."
        elif action_type in {"file_read", "filesystem"} or tool_l == "read_file":
            label = f"THE REQUESTED FILE WAS NOT READ"
            if file_name and file_name != "file":
                label = f"{file_name.upper()} WAS NOT READ" if len(file_name) < 24 else "THE REQUESTED FILE WAS NOT READ"
            # Prefer plain language for private docs.
            label = "THE REQUESTED FILE WAS NOT READ"
            detail = "Varden intercepted the action before execution."
        elif action_type in {"file_write"}:
            label = "THE FILE WAS NOT WRITTEN"
            detail = "Varden intercepted the action before execution."
        elif action_type in {"subprocess", "shell", "command"}:
            label = "THE COMMAND DID NOT RUN"
            detail = "Varden blocked the subprocess before launch."
        elif action_type == "mcp_call":
            if "delete" in tool_l.lower():
                label = "THE USER WAS NOT DELETED"
            else:
                label = f"{_human_tool_label(tool_l).upper()} DID NOT RUN"
            detail = f"Varden stopped `{tool_l}` before execution."
        else:
            label = f"{_human_tool_label(tool_l).upper()} DID NOT RUN"
            detail = "Varden intercepted the action before execution."
        if decision == "approval_required":
            label = "EXECUTION DENIED"
            detail = f"`{tool_l}` was not executed — require_approval without a scoped approval token."
        return {
            "enforced": True,
            "executed": False,
            "side_effect_prevented": True,
            "label": label,
            "detail": detail.strip(),
            "basis": basis,
        }

    # Permitted actions: do not treat side_effect_prevented=false as "OBSERVED prevention failure".
    if decision in {"allowed", "monitored", "warned", "sanitised"}:
        sanitiser = meta.get("sanitiser")
        if sanitiser and decision in {"allowed", "monitored", "sanitised"}:
            return {
                "enforced": True,
                "executed": None,
                "side_effect_prevented": False,
                "label": "SANITISED OPERATION PERMITTED",
                "detail": f"Typed sanitiser `{sanitiser}` was recorded; required authority matched this causal chain.",
                "basis": basis if basis != "unknown" else "policy_allow",
            }
        return {
            "enforced": True,
            "executed": None,
            "side_effect_prevented": False,
            "label": "AUTHORITY MATCHED",
            "detail": f"Varden allowed `{tool_l}` under the effective delegated authority for this causal chain.",
            "basis": basis if basis != "unknown" else "policy_allow",
        }

    # Blocked / approval without a reliable pre-execution prevention stamp.
    if prevented is False or basis == "sdk_log":
        return {
            "enforced": False,
            "executed": None,
            "side_effect_prevented": None,
            "label": "OBSERVED",
            "detail": enf.get("note")
            or "This integration reported the action but Varden cannot verify that execution was prevented.",
            "basis": basis,
        }

    return {
        "enforced": False,
        "executed": None,
        "side_effect_prevented": None,
        "label": "OUTCOME UNVERIFIED",
        "detail": "Insufficient enforcement evidence to claim prevention or execution.",
        "basis": basis,
    }


def build_explanation(incident: dict[str, Any]) -> dict[str, Any]:
    """Structured deterministic explanation — no LLM, no invented causality."""
    decision = incident.get("decision") or "allowed"
    authority = incident.get("authority") or {}
    required = list(authority.get("required") or [])
    granted = list(authority.get("granted") or [])
    missing = list(authority.get("missing") or [])
    reasons = dict(authority.get("required_reasons") or {})
    sources = incident.get("sources") or []
    tool = incident.get("tool") or "action"
    resource = incident.get("resource") or ""
    complete = bool((incident.get("provenance") or {}).get("complete", True))
    outcome = incident.get("outcome") or {}
    primary = _primary_finding_type([{"type": t} for t in (incident.get("finding_types") or [])])

    untrusted = [
        s for s in sources
        if isinstance(s, dict)
        and str(s.get("trust_level") or "").lower() in {"untrusted", "hostile", "unknown"}
    ]
    source_reason = ""
    if untrusted:
        bits = []
        for src in untrusted[:3]:
            origin = src.get("origin") or src.get("principal") or src.get("source_type")
            server, tool_name = _parse_mcp_ref(str(origin or ""))
            if server:
                bits.append(f"untrusted MCP result from {server}" + (f" ({tool_name})" if tool_name else ""))
            else:
                bits.append(f"{src.get('trust_level', 'unknown').upper()} {src.get('source_type') or 'source'} ({origin})")
        source_reason = "Influencing provenance: " + "; ".join(bits) + "."

    if decision == "blocked":
        summary = incident.get("summary") or f"Varden blocked `{tool}`."
        decision_reason = (
            "No valid delegation granted the missing authority."
            if missing
            else (incident.get("policy") or {}).get("reason") or "Policy blocked this action."
        )
    elif decision == "approval_required":
        summary = f"Approval required for `{tool}` — execution denied without a scoped token."
        decision_reason = "require_approval without a server-issued scoped approval token."
    elif decision in {"allowed", "monitored", "warned", "sanitised"}:
        summary = (
            f"The requested resource matched a permitted capability for this causal chain."
            if "READ_LOCAL" in required
            else f"Varden recorded `{tool}` as {decision}."
        )
        decision_reason = (
            "Required authority was present in the delegated set for this causal chain."
            if required and not missing
            else (incident.get("policy") or {}).get("reason") or f"Decision: {decision}."
        )
    else:
        summary = incident.get("summary") or f"Decision: {decision}"
        decision_reason = (incident.get("policy") or {}).get("reason") or ""

    paragraphs: list[str] = [summary]
    if source_reason:
        paragraphs.append(source_reason)
    if not complete:
        paragraphs.append(
            "Partial provenance: Varden observed this action but could not establish the complete causal chain. "
            "Unknown ancestry is not treated as trusted."
        )
    if required:
        paragraphs.append("Required authority: " + ", ".join(required) + ".")
    if granted:
        paragraphs.append("Delegated for this causal chain: " + ", ".join(granted) + ".")
    if missing:
        paragraphs.append("Missing: " + ", ".join(missing) + ".")
        paragraphs.append(decision_reason)
    elif decision in {"allowed", "monitored", "warned", "sanitised"}:
        paragraphs.append(decision_reason)
        if not any(str(s.get("trust_level") or "").lower() in {"untrusted", "hostile"} for s in sources if isinstance(s, dict)):
            paragraphs.append("No untrusted source increased the authority of this chain.")
    if outcome.get("detail"):
        paragraphs.append(str(outcome["detail"]))

    # Flagship narrative polish for confused deputy / cross-server.
    if primary in {"confused_deputy", "cross_server_authority_flow"} and decision == "blocked":
        paragraphs = [
            summary,
            source_reason or "An untrusted source influenced the agent.",
            f"The action required {', '.join(required) or 'elevated'} authority.",
            f"This causal chain was delegated only {', '.join(granted) or 'NONE'}.",
            "No valid delegation granted the missing authority.",
            str(outcome.get("detail") or "Varden stopped the tool before execution."),
        ]
        paragraphs = [p for p in paragraphs if p]

    return {
        "summary": summary,
        "source_reason": source_reason,
        "required_authority": required,
        "delegated_authority": granted,
        "missing_authority": missing,
        "required_reasons": reasons,
        "decision_reason": decision_reason,
        "provenance_complete": complete,
        "outcome": outcome,
        "text": "\n\n".join(paragraphs),
    }


def build_why_blocked(incident: dict[str, Any]) -> str:
    """Back-compat prose wrapper."""
    return str((build_explanation(incident).get("text") or "")).strip()


def _node(
    *,
    id: str,
    kind: str,
    label: str,
    subtitle: str = "",
    trust: str | None = None,
    sensitivity: str | None = None,
    capability: str | None = None,
    edge_to_next: str | None = None,
    technical_id: str | None = None,
    authority_required: list[str] | None = None,
    security_relevant: bool = True,
) -> dict[str, Any]:
    return {
        "id": id,
        "kind": kind,
        "label": label,
        "subtitle": subtitle,
        "trust": trust,
        "sensitivity": sensitivity,
        "capability": capability,
        "edge_to_next": edge_to_next,
        "technical_id": technical_id,
        "authority_required": authority_required or [],
        "security_relevant": security_relevant,
    }


def _source_role(stype: str, origin: str) -> str:
    st = str(stype or "").lower()
    server, tool = _parse_mcp_ref(origin)
    # Tool-bearing MCP refs are tool results; server-only MCP refs are servers —
    # even when the engine stamped source_type=mcp_tool_response on a server URI.
    if tool:
        return "tool_result"
    if server or origin.startswith("mcp://"):
        if st in {"mcp_tool_response"} and not tool:
            return "mcp_server"
        if st in {"mcp_tool_definition", "webmcp_tool", "mcp_server"} or origin.startswith("mcp://"):
            return "mcp_server"
    if st in {"mcp_tool_response"}:
        return "tool_result"
    if st in {"web_page", "http_response"}:
        return "web_content"
    if st in {"user"}:
        return "user_input"
    if st in {"email", "repository_file"}:
        return "web_content"
    return "source"


def _source_specificity(raw: dict[str, Any]) -> int:
    """Higher = more useful for the minimal security path."""
    origin = str(raw.get("origin") or "")
    stype = str(raw.get("source_type") or "")
    server, tool = _parse_mcp_ref(origin)
    score = 0
    if tool:
        score += 40
    if stype == "mcp_tool_response":
        score += 30
    elif stype in {"web_page", "email", "http_response", "repository_file"}:
        score += 25
    elif stype == "mcp_tool_definition":
        score += 10
    if raw.get("legacy_lineage") or (stype == "unknown" and origin.startswith("mcp://") and not tool):
        score -= 20  # structural/legacy duplicate of a richer MCP record
    if server:
        score += 5
    return score


def path_preview_labels(nodes: list[dict[str, Any]]) -> list[str]:
    """Shared human-readable projection used by cards, stories, and path index."""
    labels: list[str] = []
    i = 0
    while i < len(nodes):
        n = nodes[i]
        kind = str(n.get("kind") or "")
        nxt = nodes[i + 1] if i + 1 < len(nodes) else None
        # Merge destination MCP server + tool into one semantic hop.
        if kind == "mcp_server" and nxt and nxt.get("kind") == "tool":
            server = str(n.get("label") or "MCP")
            tool = str(nxt.get("label") or "tool")
            labels.append(f"{server} / {tool}")
            i += 2
            continue
        if kind in {"agent"}:
            labels.append(str(n.get("label") or "agent"))
        elif kind in {"tool_result"}:
            origin = n.get("subtitle") or ""
            tool = str(n.get("label") or "").replace(" result", "").strip()
            if origin and tool:
                labels.append(f"{origin} / {tool}")
            else:
                labels.append(str(n.get("label") or origin or "tool result"))
        elif kind in {"mcp_server"}:
            labels.append(str(n.get("label") or "MCP"))
        elif kind in {"tool"}:
            labels.append(str(n.get("label") or "tool"))
        elif kind in {"resource", "network"}:
            labels.append(str(n.get("label") or kind))
        elif kind in {"sanitiser"}:
            labels.append(str(n.get("label") or "sanitiser"))
        elif kind in {"block", "enforcement"}:
            labels.append("BLOCKED")
        elif kind in {"approval"}:
            labels.append("APPROVAL REQUIRED")
        elif kind in {"allow"}:
            labels.append(str(n.get("label") or "ALLOWED"))
        elif kind in {"source", "web_content", "user_input"}:
            labels.append(str(n.get("label") or "source"))
        else:
            if n.get("label"):
                labels.append(str(n["label"]))
        i += 1
    # Deduplicate adjacent identical labels (projection safety net).
    out: list[str] = []
    for lab in labels:
        if not out or out[-1] != lab:
            out.append(lab)
    return out


def _source_nodes(sources: list[Any], *, full: bool = False, limit: int | None = 4) -> list[dict[str, Any]]:
    """Project provenance sources into semantic path nodes.

    Minimal mode collapses structural MCP duplicates (e.g. mcp://server plus
    mcp://server/tool) into one tool_result. Full lineage keeps every record
    with distinct roles.
    """
    raw_sources = [s for s in sources if isinstance(s, dict)]
    ranked = sorted(
        raw_sources,
        key=lambda s: (
            0 if str(s.get("trust_level") or "").lower() in {"hostile", "untrusted"} else
            1 if str(s.get("trust_level") or "").lower() == "unknown" else 2,
            -_source_specificity(s),
        ),
    )

    nodes: list[dict[str, Any]] = []

    if full:
        # Full lineage: keep every distinct canonical record, but assign correct
        # semantic roles and drop exact origin+role duplicates so operators are
        # not shown three identical "tool result" cards for one MCP hop.
        seen_keys: set[str] = set()
        staged: list[dict[str, Any]] = []
        for raw in ranked:
            origin = str(raw.get("origin") or raw.get("principal") or raw.get("source_type") or "source")
            sid = str(raw.get("source_id") or origin)
            trust = str(raw.get("trust_level") or "unknown").lower()
            stype = str(raw.get("source_type") or "source")
            role = _source_role(stype, origin)
            server, tool_name = _parse_mcp_ref(origin)
            # Dedup key: same semantic hop (role + normalized origin).
            norm_origin = origin.rstrip("/")
            if role == "mcp_server" and server:
                norm_origin = f"mcp://{server}"
            elif role == "tool_result" and server:
                norm_origin = f"mcp://{server}/{tool_name or 'tool'}"
            dedup_key = f"{role}:{norm_origin.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            if role == "tool_result":
                tool_label = " ".join(part.capitalize() for part in (tool_name or "tool").replace("_", " ").split())
                staged.append(_node(
                    id=f"src:{sid}",
                    kind="tool_result",
                    label=f"{tool_label} result",
                    subtitle=server or str(raw.get("principal") or "MCP"),
                    trust=trust,
                    edge_to_next="influenced",
                    technical_id=origin if origin.startswith("mcp://") else f"mcp://{server}/{tool_name or ''}".rstrip("/"),
                ))
            elif role == "mcp_server":
                staged.append(_node(
                    id=f"src:{sid}",
                    kind="mcp_server",
                    label=server or str(raw.get("principal") or origin),
                    subtitle="MCP server",
                    trust=trust,
                    edge_to_next="returned",
                    technical_id=origin if origin.startswith("mcp://") else f"mcp://{server or origin}",
                    security_relevant=True,
                ))
            elif role == "web_content":
                staged.append(_node(
                    id=f"src:{sid}",
                    kind="web_content",
                    label=_display_host(origin) or origin,
                    subtitle=stype.replace("_", " "),
                    trust=trust,
                    edge_to_next="influenced",
                    technical_id=origin,
                ))
            elif role == "user_input":
                staged.append(_node(
                    id=f"src:{sid}",
                    kind="user_input",
                    label=str(raw.get("principal") or "user"),
                    subtitle="user input",
                    trust=trust,
                    edge_to_next="influenced",
                    technical_id=origin,
                ))
            else:
                staged.append(_node(
                    id=f"src:{sid}",
                    kind="source",
                    label=_display_host(origin) or origin,
                    subtitle=stype.replace("_", " "),
                    trust=trust,
                    edge_to_next="influenced",
                    technical_id=origin,
                ))
        # Stable order: MCP server before its tool result when both present.
        def _full_sort_key(n: dict[str, Any]) -> tuple:
            kind = n.get("kind")
            label = str(n.get("label") or "").lower()
            order = {"mcp_server": 0, "tool_result": 1, "web_content": 2, "user_input": 3, "source": 4}.get(str(kind), 5)
            return (order, label)
        # Preserve relative server→result grouping.
        servers = [n for n in staged if n.get("kind") == "mcp_server"]
        results = [n for n in staged if n.get("kind") == "tool_result"]
        others = [n for n in staged if n.get("kind") not in {"mcp_server", "tool_result"}]
        ordered: list[dict[str, Any]] = []
        used_results: set[str] = set()
        for srv in servers:
            ordered.append(srv)
            for res in results:
                rid = str(res.get("id"))
                if rid in used_results:
                    continue
                # Match by server name carried in tool_result subtitle.
                if str(res.get("subtitle") or "").lower() == str(srv.get("label") or "").lower():
                    srv["edge_to_next"] = "returned"
                    ordered.append(res)
                    used_results.add(rid)
        for res in results:
            rid = str(res.get("id"))
            if rid not in used_results:
                ordered.append(res)
        ordered.extend(others)
        return ordered

    # Minimal: collapse by MCP server / non-MCP origin key.
    best_by_key: dict[str, dict[str, Any]] = {}
    for raw in ranked:
        origin = str(raw.get("origin") or raw.get("principal") or "")
        server, tool = _parse_mcp_ref(origin)
        principal = str(raw.get("principal") or "")
        if server or principal.startswith("mcp") or str(raw.get("source_type") or "").startswith("mcp"):
            key = f"mcp:{(server or principal or origin).lower()}"
        else:
            key = f"src:{(_display_host(origin) or origin).lower()}"
        prev = best_by_key.get(key)
        if prev is None or _source_specificity(raw) > _source_specificity(prev):
            best_by_key[key] = raw

    selected = sorted(
        best_by_key.values(),
        key=lambda s: (
            0 if str(s.get("trust_level") or "").lower() in {"hostile", "untrusted"} else 1,
            -_source_specificity(s),
        ),
    )
    if limit is not None:
        selected = selected[:limit]

    for raw in selected:
        origin = str(raw.get("origin") or raw.get("principal") or raw.get("source_type") or "source")
        trust = str(raw.get("trust_level") or "unknown").lower()
        stype = str(raw.get("source_type") or "source")
        # Drop empty structural placeholders from the minimal security path.
        if origin in {"", "unknown", "source"} and stype in {"", "unknown", "source"}:
            continue
        if (_display_host(origin) or origin).lower() in {"unknown", "none", "null"}:
            continue
        role = _source_role(stype, origin)
        server, tool_name = _parse_mcp_ref(origin)
        # Prefer tool_result presentation whenever a tool segment exists.
        if server and (tool_name or role == "tool_result" or stype == "mcp_tool_response"):
            tool_label = " ".join(part.capitalize() for part in (tool_name or "tool").replace("_", " ").split())
            nodes.append(_node(
                id=f"src:{raw.get('source_id') or origin}",
                kind="tool_result",
                label=f"{tool_label} result",
                subtitle=server,
                trust=trust,
                edge_to_next="influenced",
                technical_id=origin if origin.startswith("mcp://") and tool_name else f"mcp://{server}/{tool_name or 'tool'}",
            ))
        elif server or role == "mcp_server":
            nodes.append(_node(
                id=f"src:{raw.get('source_id') or origin}",
                kind="mcp_server",
                label=server or principal_or(raw, origin),
                subtitle="MCP server",
                trust=trust,
                edge_to_next="influenced",
                technical_id=f"mcp://{server or origin}",
            ))
        elif role == "web_content" or stype in {"web_page", "email", "http_response", "repository_file"}:
            nodes.append(_node(
                id=f"src:{raw.get('source_id') or origin}",
                kind="web_content",
                label=_display_host(origin) or origin,
                subtitle=stype.replace("_", " "),
                trust=trust,
                edge_to_next="influenced",
                technical_id=origin,
            ))
        else:
            nodes.append(_node(
                id=f"src:{raw.get('source_id') or origin}",
                kind="source",
                label=_display_host(origin) or origin,
                subtitle=stype.replace("_", " "),
                trust=trust,
                edge_to_next="influenced",
                technical_id=origin,
            ))
    return nodes


def principal_or(raw: dict[str, Any], origin: str) -> str:
    return str(raw.get("principal") or origin)

def build_attack_path_nodes(
    event: dict[str, Any],
    *,
    full: bool = False,
    max_nodes: int = _FULL_LINEAGE_NODE_CAP,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Minimal (or bounded full) security-relevant path for UI rendering."""
    action = event.get("action") or {}
    meta = action.get("metadata") or {}
    provenance = meta.get("provenance") or {}
    sources = list(provenance.get("sources") or [])
    authority = meta.get("authority") or {}
    flow = meta.get("flow") or {}
    taint = meta.get("taint") or {}
    decision = _decision_label(event)
    required = list(authority.get("required") or [])
    granted = list(authority.get("granted") or [])
    tool = action.get("tool") or action.get("type") or "action"
    action_type = action.get("type")
    resource = authority.get("resource") or action.get("url") or action.get("domain") or ""
    sanitiser = meta.get("sanitiser")

    sensitivity = None
    if any(a in required for a in ("READ_SECRETS", "IDENTITY_USE")) or bool(
        (taint.get("tags") if isinstance(taint, dict) else None) and
        set(taint.get("tags") or {}) & {"secret", "credential"}
    ):
        sensitivity = "secret"
    elif any(a in required for a in ("READ_PRIVATE", "MCP_PRIVILEGED", "EXECUTE_PRIVILEGED", "ADMIN", "PAYMENT", "WRITE_DATABASE")):
        sensitivity = "private"

    capability = None
    if any(a in required for a in ("ADMIN", "MCP_PRIVILEGED", "EXECUTE_PRIVILEGED", "PAYMENT", "DELETE")):
        capability = "privileged"
    elif "MCP_UNPRIVILEGED" in required:
        capability = "unprivileged"

    nodes: list[dict[str, Any]] = []
    # Exclude destination MCP annotations from the causal *source* hop in minimal mode.
    dest_server, dest_tool = _parse_mcp_ref(str(resource))
    mcp_server = meta.get("mcp_server") or dest_server
    source_inputs = sources
    if not full and mcp_server and action_type == "mcp_call":
        filtered = []
        for s in sources:
            if not isinstance(s, dict):
                continue
            origin = str(s.get("origin") or "")
            server, _tool = _parse_mcp_ref(origin)
            principal = str(s.get("principal") or "")
            if (server or principal) == str(mcp_server) and not (
                str(s.get("source_type") or "").endswith("response") or _tool
            ):
                # Structural destination annotation — keep in full lineage only.
                continue
            if (server or principal) == str(mcp_server) and origin.rstrip("/") in {
                f"mcp://{mcp_server}",
                str(mcp_server),
            }:
                continue
            filtered.append(s)
        source_inputs = filtered or sources

    nodes.extend(_source_nodes(source_inputs, full=full, limit=None if full else 4))

    if sanitiser:
        nodes.append(_node(
            id=f"sanitiser:{sanitiser}",
            kind="sanitiser",
            label=str(sanitiser).split("@")[0].replace("_", " "),
            subtitle="typed sanitiser",
            trust="delegated",
            edge_to_next="sanitised",
            technical_id=str(sanitiser),
        ))

    agent_name = action.get("agent_name") or event.get("agent_name") or "agent"
    nodes.append(_node(
        id="agent",
        kind="agent",
        label=str(agent_name),
        subtitle="delegated " + (", ".join(granted[:4]) or "narrow"),
        trust="delegated",
        edge_to_next="requested",
    ))

    source_servers = {
        (_parse_mcp_ref(str(s.get("origin") or ""))[0] or s.get("principal"))
        for s in sources if isinstance(s, dict)
    }
    source_servers.discard(None)

    # Cross-server / privileged MCP destination as its own node.
    if action_type == "mcp_call" and mcp_server:
        edge_from_agent = "attempted"
        if nodes:
            nodes[-1]["edge_to_next"] = edge_from_agent
        nodes.append(_node(
            id=f"mcp:{mcp_server}",
            kind="mcp_server",
            label=str(mcp_server),
            subtitle="privileged MCP" if capability == "privileged" else "MCP server",
            trust="unknown" if str(mcp_server) not in {str(x) for x in source_servers} else "untrusted",
            capability=capability,
            edge_to_next="called",
            technical_id=f"mcp://{mcp_server}/{tool}",
        ))
        nodes.append(_node(
            id=f"tool:{tool}",
            kind="tool",
            label=_human_tool_label(str(tool)),
            subtitle=str(tool),
            capability=capability,
            sensitivity=sensitivity,
            edge_to_next="requires" if required else "completed",
            technical_id=f"mcp://{mcp_server}/{tool}",
            authority_required=required,
        ))
    elif action_type in {"http_request", "http_call"}:
        # Exfiltration: sensitive data marker then network destination.
        if flow.get("secret_egress") or flow.get("private_to_public") or sensitivity == "secret":
            nodes.append(_node(
                id="data:sensitive",
                kind="resource",
                label="Sensitive data",
                subtitle="secret/credential taint in causal chain",
                sensitivity="secret",
                edge_to_next="sent to",
            ))
        host = _display_host(str(resource))
        nodes.append(_node(
            id=f"network:{host or resource}",
            kind="network",
            label=host or str(resource) or "network destination",
            subtitle=f"{action.get('method') or 'HTTP'} · public" if "NETWORK_PUBLIC" in required or "WRITE_CLOUD" in required else (action.get("method") or "HTTP"),
            sensitivity="public" if "WRITE_CLOUD" in required or "NETWORK_PUBLIC" in required else sensitivity,
            edge_to_next="blocked before" if decision in {"blocked", "approval_required"} else "completed",
            technical_id=str(resource),
            authority_required=required,
        ))
    elif action_type in {"file_read", "file_write", "filesystem"} or tool == "read_file":
        nodes.append(_node(
            id=f"tool:{tool}",
            kind="tool",
            label=_human_tool_label(str(tool)),
            subtitle=str(tool),
            edge_to_next="read" if action_type != "file_write" else "write",
            authority_required=required,
        ))
        if resource:
            nodes.append(_node(
                id=f"resource:{resource}",
                kind="resource",
                label=_basename(str(resource)) or str(resource),
                subtitle=truncate_path(str(resource), 64),
                sensitivity=sensitivity or ("private" if "READ_PRIVATE" in required else "public"),
                edge_to_next="blocked before" if decision in {"blocked", "approval_required"} else "completed",
                technical_id=str(resource),
                authority_required=required,
            ))
    else:
        nodes.append(_node(
            id=f"tool:{tool}",
            kind="tool",
            label=_human_tool_label(str(tool)),
            subtitle=str(resource) if resource else str(action_type or ""),
            capability=capability,
            sensitivity=sensitivity,
            edge_to_next="blocked before" if decision in {"blocked", "approval_required"} else "completed",
            technical_id=str(resource or tool),
            authority_required=required,
        ))

    if decision == "blocked":
        if nodes:
            nodes[-1]["edge_to_next"] = "blocked before"
        nodes.append(_node(
            id="block",
            kind="enforcement",
            label="VARDEN BLOCKED",
            subtitle="Execution intercepted"
            if (meta.get("enforcement") or {}).get("side_effect_prevented") is not False
            else "Blocked by policy",
            trust=None,
            sensitivity=None,
            edge_to_next=None,
        ))
    elif decision == "approval_required":
        if nodes:
            nodes[-1]["edge_to_next"] = "blocked before"
        nodes.append(_node(
            id="approval",
            kind="approval",
            label="APPROVAL REQUIRED",
            subtitle="Denied — no scoped approval token",
            trust=None,
            edge_to_next=None,
        ))
    elif decision in {"allowed", "monitored", "warned", "sanitised"}:
        if nodes:
            nodes[-1]["edge_to_next"] = "allowed"
        nodes.append(_node(
            id="allow",
            kind="allow",
            label={"allowed": "ALLOWED", "monitored": "MONITORED", "warned": "WARNED", "sanitised": "SANITISED"}[decision],
            subtitle="Authority matched for this causal chain",
            trust="delegated",
            edge_to_next=None,
        ))

    truncated = False
    total = len(nodes)
    if full and len(nodes) > max_nodes:
        nodes = nodes[:max_nodes]
        truncated = True
    meta_out = {
        "mode": "full" if full else "minimal",
        "shown": len(nodes),
        "total_observed": total,
        "truncated": truncated,
        "bound": max_nodes if full else None,
    }
    return nodes, meta_out


def incident_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Build one incident from a persisted event, or None if not provenance-related."""
    action = event.get("action") or {}
    meta = action.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    if not (meta.get("authority") or meta.get("provenance") or meta.get("findings") or meta.get("enforcement")):
        return None

    findings_raw = list(meta.get("findings") or [])
    findings = [
        {
            "type": f.get("type"),
            "label": humanize_finding(f.get("type")),
            "blurb": finding_blurb(f.get("type")),
            "severity": f.get("severity") or "info",
            "explanation": f.get("explanation") or "",
            "evidence": {k: v for k, v in f.items() if k not in {"type", "severity", "explanation"}},
        }
        for f in findings_raw
        if isinstance(f, dict)
    ]
    authority = dict(meta.get("authority") or {})
    provenance = dict(meta.get("provenance") or {})
    decision = _decision_label(event)
    severity = _max_severity(
        findings,
        fallback="critical" if decision == "blocked" and authority.get("violation") else (
            "high" if decision == "blocked" else "info"
        ),
    )
    tool = action.get("tool") or action.get("type")
    resource = authority.get("resource") or action.get("url") or action.get("domain")
    sources = list(provenance.get("sources") or [])
    path_nodes, path_meta = build_attack_path_nodes(event, full=False)
    full_nodes, full_meta = build_attack_path_nodes(event, full=True)
    preview_labels = path_preview_labels(path_nodes)
    missing = list(authority.get("missing") or [])
    # Compact index fields for Attack Paths / Overview stories.
    route_core = [lab for lab in preview_labels if lab not in {"BLOCKED", "ALLOWED", "MONITORED", "WARNED", "SANITISED", "APPROVAL REQUIRED"}]
    path_index = {
        "source": route_core[0] if route_core else None,
        "sink": route_core[-1] if len(route_core) > 1 else (route_core[0] if route_core else None),
        "route": preview_labels,
        "missing": missing,
        "text": " → ".join(preview_labels),
    }

    outcome = _enforcement_outcome(
        event,
        decision=decision,
        action_type=action.get("type"),
        tool=tool,
        resource=resource,
    )

    matched = (event.get("decision") or {}).get("matched_rule") or {}
    policy = {
        "matched_rule": matched,
        "reason": (event.get("decision") or {}).get("reason"),
        "action": (event.get("decision") or {}).get("action"),
        "pack": (
            matched.get("pack")
            or matched.get("pack_id")
            or (matched.get("id") or "").split("/")[0]
            if isinstance(matched, dict) else None
        ),
        "rule_id": (
            matched.get("id") or matched.get("rule_id") or matched.get("name")
            if isinstance(matched, dict) else None
        ),
    }

    incident = {
        "id": f"evt-{event.get('id')}",
        "event_id": event.get("id"),
        "trace_id": event.get("trace_id") or action.get("trace_id"),
        "timestamp": event.get("timestamp"),
        "agent_name": event.get("agent_name") or action.get("agent_name"),
        "decision": decision,
        "severity": severity,
        "title": _title_for_incident(
            decision=decision,
            findings=findings_raw,
            tool=tool,
            resource=resource,
            authority=authority,
            action_type=action.get("type"),
            method=action.get("method"),
        ),
        "summary": finding_blurb(_primary_finding_type(findings_raw))
        if findings_raw else (
            "The requested file is inside the permitted workspace and the causal chain has valid READ_LOCAL authority."
            if "READ_LOCAL" in (authority.get("required") or []) and not authority.get("violation")
            else (
                "Privileged action without matching delegated authority."
                if authority.get("violation") else "Provenance-aware authority decision."
            )
        ),
        "action_type": action.get("type"),
        "tool": tool,
        "resource": resource,
        "method": action.get("method"),
        "authority": {
            "required": list(authority.get("required") or []),
            "granted": list(authority.get("granted") or []),
            "missing": list(authority.get("missing") or []),
            "violation": bool(authority.get("violation")),
            "escalation": bool(authority.get("escalation")),
            "resource": authority.get("resource"),
            "reason": authority.get("reason"),
            "required_reasons": dict(authority.get("required_reasons") or {}),
        },
        "provenance": {
            "trust": provenance.get("trust") or "unknown",
            "complete": bool(provenance.get("complete", True)),
            "source_types": provenance.get("source_types") or [],
            "origins": provenance.get("origins") or [],
        },
        "sources": sources,
        "taint": meta.get("taint") or {},
        "flow": meta.get("flow") or {},
        "causal": meta.get("causal") or {},
        "findings": findings,
        "finding_count": len(findings),
        "finding_types": [f["type"] for f in findings],
        "attack_path": path_nodes,
        "attack_path_full": full_nodes,
        "attack_path_meta": path_meta,
        "attack_path_full_meta": full_meta,
        "attack_path_preview": preview_labels,
        "path_index": path_index,
        "attack_path_labels": list(meta.get("attack_path") or []),
        "policy": policy,
        "enforcement": dict(meta.get("enforcement") or {}),
        "outcome": outcome,
        "side_effect": (
            "not_executed" if outcome.get("side_effect_prevented") is True
            else ("may_have_executed" if outcome.get("side_effect_prevented") is False else "unverified")
        ),
        "quiet": decision in {"allowed", "monitored"} and len(findings) == 0,
        "sanitiser": meta.get("sanitiser"),
    }
    # Surface typed sanitiser success without rewriting the policy action.
    if (
        meta.get("sanitiser")
        and decision in {"allowed", "monitored"}
        and not authority.get("violation")
    ):
        incident["display_decision"] = "sanitised"
        incident["title"] = incident["title"] if "sanitis" in incident["title"].lower() else (
            "Sanitised weather API request" if "weather" in str(resource or "").lower()
            else f"Sanitised {_human_tool_label(str(tool or 'request'))}"
        )
        # Quiet sanitised successes should still be readable as a positive story.
        incident["quiet"] = False
    else:
        incident["display_decision"] = decision
    incident["explanation"] = build_explanation(incident)
    incident["why"] = incident["explanation"]["text"]
    return incident


def list_incidents_from_events(events: list[dict[str, Any]], *, limit: int = 50) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for event in events:
        incident = incident_from_event(event)
        if incident is None:
            continue
        out.append(incident)
        if len(out) >= limit:
            break
    return out


def incident_metrics(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = sum(1 for i in incidents if i.get("decision") == "blocked")
    critical = sum(1 for i in incidents if str(i.get("severity") or "").lower() == "critical")
    confused = sum(1 for i in incidents if "confused_deputy" in (i.get("finding_types") or []))
    exfil = sum(1 for i in incidents if "provenance_exfiltration_chain" in (i.get("finding_types") or []))
    cross = sum(1 for i in incidents if "cross_server_authority_flow" in (i.get("finding_types") or []))
    return {
        "incidents_total": len(incidents),
        "blocked_incidents": blocked,
        "critical_incidents": critical,
        "confused_deputy_incidents": confused,
        "exfiltration_incidents": exfil,
        "cross_server_incidents": cross,
        "findings_on_incidents": sum(int(i.get("finding_count") or 0) for i in incidents),
    }


def authority_map_from_inventory(
    *,
    fingerprints: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    selected_incident: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evidence-driven reachability map — architectural exposure, not delegated authority."""
    mcp_servers: dict[str, dict[str, Any]] = {}
    for fp in fingerprints:
        server = str(fp.get("server_id") or "unknown")
        entry = mcp_servers.setdefault(
            server,
            {
                "id": f"mcp:{server}",
                "server_id": server,
                "trust": fp.get("trust_status") or "observed",
                "tools": [],
                "stale": False,
                "capabilities": set(),
                "evidence": [],
            },
        )
        entry["tools"].append({
            "name": fp.get("tool_name"),
            "fingerprint": fp.get("fingerprint"),
            "trust_status": fp.get("trust_status"),
        })
        entry["evidence"].append({
            "type": "fingerprint",
            "tool": fp.get("tool_name"),
            "fingerprint": fp.get("fingerprint"),
        })
        if fp.get("trust_status") in {"stale", "pending"}:
            entry["stale"] = True
            entry["trust"] = "stale"

    agent_name = "demo-agent"
    for i in incidents:
        if i.get("agent_name"):
            agent_name = str(i["agent_name"])
            break

    # Observed capability inventory + evidence counts.
    family_caps: dict[str, set[str]] = {
        "filesystem": set(),
        "network": set(),
        "subprocess": set(),
        "mcp": set(),
        "database": set(),
        "cloud": set(),
        "other": set(),
    }
    fs_private = False
    fs_workspace = False
    fs_secret = False
    net_public = False
    untrusted_inputs: dict[str, dict[str, Any]] = {}
    mcp_privileged_hit: set[str] = set()
    evidence_counts = {"file_read": 0, "http": 0, "mcp": 0}
    last_ts: dict[str, float] = {}

    for incident in incidents:
        required = list((incident.get("authority") or {}).get("required") or [])
        ts = float(incident.get("timestamp") or 0)
        for cap in required:
            if cap in {"READ_PRIVATE"}:
                family_caps["filesystem"].add(cap)
                fs_private = True
            elif cap in {"READ_LOCAL", "WRITE_LOCAL", "READ_PUBLIC"}:
                family_caps["filesystem"].add(cap)
                if cap == "READ_LOCAL":
                    fs_workspace = True
            elif cap == "READ_SECRETS":
                family_caps["filesystem"].add(cap)
                fs_secret = True
            elif cap.startswith("NETWORK_") or cap == "WRITE_CLOUD":
                family_caps["network"].add(cap)
                if cap in {"NETWORK_PUBLIC", "WRITE_CLOUD"}:
                    net_public = True
            elif "EXECUTE" in cap:
                family_caps["subprocess"].add(cap)
            elif cap.startswith("MCP_"):
                family_caps["mcp"].add(cap)
            elif cap == "WRITE_DATABASE":
                family_caps["database"].add(cap)
            elif "CLOUD" in cap:
                family_caps["cloud"].add(cap)
            else:
                family_caps["other"].add(cap)

        for src in incident.get("sources") or []:
            if not isinstance(src, dict):
                continue
            trust = str(src.get("trust_level") or "").lower()
            if trust not in {"untrusted", "hostile", "unknown"}:
                continue
            origin = str(src.get("origin") or src.get("principal") or "")
            server, tool = _parse_mcp_ref(origin)
            key = server or _display_host(origin) or origin
            if not key or str(key).lower() in {"unknown", "none", "null", "source"}:
                continue
            entry = untrusted_inputs.setdefault(key, {
                "id": f"input:{key}",
                "label": key,
                "trust": trust,
                "kind": "mcp_server" if server else "web_content",
                "technical_id": origin,
                "evidence": [],
            })
            entry["evidence"].append({"incident_id": incident.get("id"), "tool": tool})

        if incident.get("action_type") in {"file_read", "file_write", "filesystem"}:
            evidence_counts["file_read"] += 1
            last_ts["filesystem"] = max(last_ts.get("filesystem", 0), ts)
        if incident.get("action_type") in {"http_request", "http_call"}:
            evidence_counts["http"] += 1
            last_ts["network"] = max(last_ts.get("network", 0), ts)
        if incident.get("action_type") == "mcp_call":
            evidence_counts["mcp"] += 1
            res = str((incident.get("authority") or {}).get("resource") or "")
            server, _ = _parse_mcp_ref(res)
            server = server or (incident.get("resource") or "")
            if server and "MCP_PRIVILEGED" in required:
                mcp_privileged_hit.add(str(server).replace("mcp://", "").split("/")[0])
            # Also pull mcp from path nodes
            for n in incident.get("attack_path") or []:
                if n.get("kind") == "mcp_server" and n.get("capability") == "privileged":
                    mcp_privileged_hit.add(str(n.get("label")))

        # Attach observed caps onto fingerprint servers when tool matches.
        for n in incident.get("attack_path") or []:
            if n.get("kind") == "mcp_server":
                sid = str(n.get("label") or "")
                if sid in mcp_servers:
                    mcp_servers[sid]["capabilities"].update(required)
                    mcp_servers[sid]["evidence"].append({
                        "type": "guarded_invocation",
                        "incident_id": incident.get("id"),
                        "tool": incident.get("tool"),
                        "authority_required": required,
                    })

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    lanes = {
        "inputs": {"id": "inputs", "label": "Inputs", "node_ids": []},
        "agent": {"id": "agent", "label": "Agent", "node_ids": []},
        "domains": {"id": "domains", "label": "Capability domains", "node_ids": []},
        "destinations": {"id": "destinations", "label": "Destinations", "node_ids": []},
    }

    for key, inp in untrusted_inputs.items():
        nodes.append({
            "id": inp["id"],
            "lane": "inputs",
            "kind": inp["kind"],
            "label": inp["label"],
            "trust_boundary": "untrusted_input",
            "trust": inp["trust"],
            "technical_id": inp.get("technical_id"),
            "evidence": inp["evidence"][:5],
            "explain": {
                "title": inp["label"],
                "trust": inp["trust"],
                "detail": "Untrusted or unknown input observed influencing guarded actions.",
                "evidence": inp["evidence"][:5],
            },
        })
        lanes["inputs"]["node_ids"].append(inp["id"])
        edges.append({
            "id": f"e:{inp['id']}->agent",
            "from": inp["id"],
            "to": "agent:main",
            "relationship": "influences",
            "evidence": {"note": "Observed untrusted provenance on guarded actions"},
        })

    agent_id = "agent:main"
    nodes.append({
        "id": agent_id,
        "lane": "agent",
        "kind": "agent",
        "label": agent_name,
        "trust_boundary": "delegated_context",
        "trust": "delegated",
        "explain": {
            "title": agent_name,
            "detail": "Agent process through which observed capabilities compose.",
            "note": "Agent capability ≠ delegated authority for a specific causal chain.",
        },
    })
    lanes["agent"]["node_ids"].append(agent_id)

    def add_domain(node_id: str, label: str, family: str, boundary: str, caps: list[str], explain_detail: str, evidence: dict[str, Any]):
        nodes.append({
            "id": node_id,
            "lane": "domains",
            "kind": "domain",
            "label": label,
            "family": family,
            "trust_boundary": boundary,
            "capabilities": caps,
            "explain": {
                "title": label,
                "capabilities": caps,
                "detail": explain_detail,
                "evidence": evidence,
            },
        })
        lanes["domains"]["node_ids"].append(node_id)
        edges.append({
            "id": f"e:agent->{node_id}",
            "from": agent_id,
            "to": node_id,
            "relationship": "can_reach",
            "evidence": evidence,
        })

    if family_caps["filesystem"]:
        add_domain(
            "domain:filesystem",
            "Filesystem",
            "filesystem",
            "capability_domain",
            sorted(family_caps["filesystem"]),
            "Observed filesystem authorities from guarded actions.",
            {"guarded_reads": evidence_counts["file_read"], "last_observed": last_ts.get("filesystem")},
        )
        if fs_workspace:
            nodes.append({
                "id": "dest:workspace",
                "lane": "destinations",
                "kind": "resource",
                "label": "Workspace files",
                "trust_boundary": "sensitive_resource" if False else "delegated_context",
                "sensitivity": "public",
                "explain": {"title": "Workspace files", "capabilities": ["READ_LOCAL"], "detail": "Observed READ_LOCAL workspace reads."},
            })
            lanes["destinations"]["node_ids"].append("dest:workspace")
            edges.append({"id": "e:fs->workspace", "from": "domain:filesystem", "to": "dest:workspace", "relationship": "includes", "evidence": {"capability": "READ_LOCAL"}})
        if fs_private or fs_secret:
            nodes.append({
                "id": "dest:private-fs",
                "lane": "destinations",
                "kind": "resource",
                "label": "Private / secret files",
                "trust_boundary": "sensitive_resource",
                "sensitivity": "secret" if fs_secret else "private",
                "explain": {
                    "title": "Private filesystem",
                    "capabilities": sorted(c for c in family_caps["filesystem"] if c in {"READ_PRIVATE", "READ_SECRETS"}),
                    "detail": "Observed private/secret filesystem authority requirements.",
                    "evidence": {"guarded_reads": evidence_counts["file_read"]},
                },
            })
            lanes["destinations"]["node_ids"].append("dest:private-fs")
            edges.append({"id": "e:fs->private", "from": "domain:filesystem", "to": "dest:private-fs", "relationship": "includes", "evidence": {"capabilities": sorted(family_caps["filesystem"])}})

    if family_caps["mcp"] or mcp_servers:
        add_domain(
            "domain:mcp",
            "MCP",
            "mcp",
            "capability_domain",
            sorted(family_caps["mcp"] | ({"MCP_PRIVILEGED"} if mcp_privileged_hit else set()) | ({"MCP_UNPRIVILEGED"} if mcp_servers else set())),
            "Observed MCP servers and privileged MCP invocations.",
            {"servers": list(mcp_servers.keys()), "guarded_mcp_calls": evidence_counts["mcp"]},
        )
        for server, entry in mcp_servers.items():
            privileged = server in mcp_privileged_hit or "MCP_PRIVILEGED" in entry["capabilities"]
            nid = entry["id"]
            nodes.append({
                "id": nid,
                "lane": "destinations",
                "kind": "mcp_server",
                "label": server,
                "trust_boundary": "privileged_destination" if privileged else "unknown_destination",
                "trust": entry.get("trust") or "unknown",
                "capability": "privileged" if privileged else None,
                "capabilities": sorted(entry["capabilities"]) or (["MCP_PRIVILEGED"] if privileged else ["MCP_UNPRIVILEGED"]),
                "tools": entry["tools"],
                "explain": {
                    "title": f"{server} MCP",
                    "trust": entry.get("trust") or "unknown",
                    "capabilities": sorted(entry["capabilities"]) or [],
                    "tools": entry["tools"],
                    "evidence": entry["evidence"][:6],
                },
            })
            lanes["destinations"]["node_ids"].append(nid)
            edges.append({
                "id": f"e:mcp->{nid}",
                "from": "domain:mcp",
                "to": nid,
                "relationship": "includes",
                "evidence": {"fingerprints": len(entry["tools"]), "invocations": [e for e in entry["evidence"] if e.get("type") == "guarded_invocation"][:3]},
            })

    if family_caps["network"] or net_public:
        add_domain(
            "domain:network",
            "Network",
            "network",
            "capability_domain",
            sorted(family_caps["network"]),
            "Observed network authorities from guarded HTTP actions.",
            {"guarded_http": evidence_counts["http"], "last_observed": last_ts.get("network")},
        )
        if net_public:
            nodes.append({
                "id": "dest:public-http",
                "lane": "destinations",
                "kind": "network",
                "label": "Public HTTP",
                "trust_boundary": "public_destination",
                "sensitivity": "public",
                "explain": {
                    "title": "Public HTTP",
                    "capabilities": sorted(c for c in family_caps["network"] if c in {"NETWORK_PUBLIC", "WRITE_CLOUD"}),
                    "detail": "Observed public network egress capability.",
                    "evidence": {"guarded_http": evidence_counts["http"]},
                },
            })
            lanes["destinations"]["node_ids"].append("dest:public-http")
            edges.append({"id": "e:net->public", "from": "domain:network", "to": "dest:public-http", "relationship": "includes", "evidence": {"capability": "NETWORK_PUBLIC"}})

    for fam in ("subprocess", "database", "cloud"):
        if family_caps[fam]:
            add_domain(
                f"domain:{fam}",
                fam.capitalize(),
                fam,
                "capability_domain",
                sorted(family_caps[fam]),
                f"Observed {fam} authorities from guarded actions.",
                {"capabilities": sorted(family_caps[fam])},
            )

    exposures = []
    if untrusted_inputs and (fs_private or fs_secret):
        exposures.append({
            "id": "exp:untrusted-sensitive-read",
            "severity": "high",
            "label": "ARCHITECTURAL EXPOSURE",
            "title": "Untrusted input + sensitive read",
            "detail": (
                "Observed capabilities could permit untrusted input to influence private/secret "
                "filesystem access if authority controls were bypassed or incorrectly delegated."
            ),
            "highlight_node_ids": [i["id"] for i in untrusted_inputs.values()][:3] + [agent_id, "domain:filesystem", "dest:private-fs"],
            "potential_route": ["untrusted input", agent_name, "private filesystem"],
        })
    if (fs_private or fs_secret) and net_public:
        exposures.append({
            "id": "exp:sensitive-egress",
            "severity": "high",
            "label": "ARCHITECTURAL EXPOSURE",
            "title": "Sensitive read + external write",
            "detail": (
                "Observed capabilities could permit sensitive filesystem data to reach public "
                "network destinations if authority controls were bypassed or incorrectly delegated."
            ),
            "highlight_node_ids": [agent_id, "domain:filesystem", "dest:private-fs", "domain:network", "dest:public-http"],
            "potential_route": ["private filesystem", agent_name, "public HTTP"],
        })
    if len(mcp_servers) > 1:
        exposures.append({
            "id": "exp:multi-mcp",
            "severity": "medium",
            "label": "ARCHITECTURAL EXPOSURE",
            "title": "Multiple MCP servers via agent",
            "detail": (
                f"{len(mcp_servers)} MCP servers are reachable through the agent; "
                "cross-server confused-deputy risk depends on trust boundaries."
            ),
            "highlight_node_ids": [agent_id, "domain:mcp"] + [e["id"] for e in mcp_servers.values()],
            "potential_route": ["untrusted MCP", agent_name, "privileged MCP"],
        })

    # Delegation overlay for a selected incident (capability vs this chain).
    delegation_overlay = None
    incident_route_node_ids: list[str] = []
    if selected_incident:
        auth = selected_incident.get("authority") or {}
        required = list(auth.get("required") or [])
        granted = list(auth.get("granted") or [])
        # Approximate agent-observed capability set from inventory.
        observed_caps = sorted({c for caps in family_caps.values() for c in caps})
        delegation_overlay = {
            "incident_id": selected_incident.get("id"),
            "note": "Left: capabilities observed for this agent. Right: authority delegated to this causal chain.",
            "rows": [
                {
                    "capability": cap,
                    "agent_possesses": cap in observed_caps or cap in required,
                    "chain_delegated": cap in granted,
                }
                for cap in sorted(set(observed_caps) | set(required) | set(granted))
            ],
        }
        # Map incident path kinds onto map node ids where possible.
        for n in selected_incident.get("attack_path") or []:
            kind = n.get("kind")
            label = str(n.get("label") or "")
            subtitle = str(n.get("subtitle") or "")
            if kind in {"tool_result", "web_content", "source", "mcp_server"}:
                for inp in untrusted_inputs.values():
                    if inp["label"] in {label, subtitle} or label in inp["label"] or subtitle in inp["label"]:
                        incident_route_node_ids.append(inp["id"])
                for sid, entry in mcp_servers.items():
                    if sid in {label, subtitle}:
                        incident_route_node_ids.append(entry["id"])
            if kind == "agent":
                incident_route_node_ids.append(agent_id)
            if kind == "resource" and (n.get("sensitivity") in {"private", "secret"} or "READ_PRIVATE" in required):
                incident_route_node_ids.append("dest:private-fs")
            if kind == "network":
                incident_route_node_ids.append("dest:public-http")
            if kind == "mcp_server":
                for sid, entry in mcp_servers.items():
                    if sid == label:
                        incident_route_node_ids.append(entry["id"])
        incident_route_node_ids = list(dict.fromkeys([x for x in incident_route_node_ids if x]))

    # Serialize sets
    for entry in mcp_servers.values():
        entry["capabilities"] = sorted(entry["capabilities"])

    return {
        "layout": "lanes",
        "note": (
            "Architectural reachability from observed guarded actions and MCP fingerprints — "
            "not proof that any causal chain is delegated those capabilities."
        ),
        "lanes": [lanes["inputs"], lanes["agent"], lanes["domains"], lanes["destinations"]],
        "nodes": nodes,
        "edges": edges,
        "families": {k: sorted(v) for k, v in family_caps.items() if v},
        "mcp_servers": [
            {
                "server_id": e["server_id"],
                "trust": e["trust"],
                "tools": e["tools"],
                "stale": e["stale"],
                "capabilities": e["capabilities"],
            }
            for e in mcp_servers.values()
        ],
        "exposures": exposures,
        "compositions": exposures,  # back-compat alias
        "delegation_overlay": delegation_overlay,
        "incident_route_node_ids": incident_route_node_ids,
        "inventory": {k: sorted(v) for k, v in family_caps.items() if v},
    }
