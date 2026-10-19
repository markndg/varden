"""Authoritative action identity for security decisions.

The caller's original type, URL, domain, surface, and path are kept on
``metadata.identity`` for audit. Policy matching, default selection, and
execution use the canonical fields. Caller metadata cannot choose a
different surface or domain.

Ambiguous destinations and malformed types are rejected. An unrecognized
type is not an implicit allow: an explicit matching rule can still permit
it, and a policy deny still denies it.
"""

from __future__ import annotations

import os
import re
from typing import Any

from varden.destination_binding import address_category, worst_category
from varden.url_identity import canonicalize_destination, canonicalize_host_claim

_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")

WEBMCP_TYPES = frozenset(
    {
        "webmcp.tool_registered",
        "webmcp.tool_invocation_requested",
        "webmcp.tool_output_scanned",
        "webmcp.extension_tamper_detected",
        "webmcp.tool_registration_changed",
        "webmcp.context_replaced",
        "webmcp.surface_changed",
        "webmcp.cross_origin_flow",
    }
)

FILESYSTEM_TYPES = frozenset(
    {
        "filesystem",
        "file_read",
        "file_write",
        "filesystem_read",
        "filesystem_write",
    }
)

# Names that mean the same HTTP operation as ``http_request``.
HTTP_ALIASES = {
    "http_call": "http_request",
    "https_request": "http_request",
}

# Names that mean a subprocess tool call. Canonical type is ``tool_call``
# and the surface is ``subprocess``, which is what the SDK already emits.
SHELL_ALIASES = {
    "subprocess": "tool_call",
    "shell": "tool_call",
    "command": "tool_call",
}

RECOGNIZED_TYPES = frozenset(
    {
        "tool_call",
        "http_request",
        "llm_call",
        "filesystem",
        "mcp_call",
        *FILESYSTEM_TYPES,
        *WEBMCP_TYPES,
    }
)

# Where a recognized type is enforced. Unknown types have no owner.
ENFORCEMENT_OWNERS = {
    "http_request": "sdk:http",
    "tool_call": "sdk:tool",
    "llm_call": "sdk:llm",
    "filesystem": "sdk:filesystem",
    "file_read": "sdk:filesystem",
    "file_write": "sdk:filesystem",
    "filesystem_read": "sdk:filesystem",
    "filesystem_write": "sdk:filesystem",
    "mcp_call": "mcp_gateway",
    **{name: "webshield" for name in WEBMCP_TYPES},
}

_SUBPROCESS_TOOLS = frozenset(
    {
        "subprocess.run",
        "subprocess.popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }
)

_DENY_MODES = frozenset({"block", "require_approval", "sanitise"})
_ISSUER = "varden"


def classify_action_type(value: object) -> tuple[str | None, str]:
    """Return ``(canonical type or None, status)``.

    Status is ``ok``, ``alias``, ``malformed``, or ``unknown``.
    """
    if not isinstance(value, str) or not _TYPE_RE.fullmatch(value):
        return None, "malformed"
    folded = value.lower()
    if folded in HTTP_ALIASES:
        return HTTP_ALIASES[folded], "alias"
    if folded in SHELL_ALIASES:
        return SHELL_ALIASES[folded], "alias"
    for name in RECOGNIZED_TYPES:
        if name.lower() == folded:
            return name, "ok" if name == value else "alias"
    return value, "unknown"


def is_subprocess_tool(tool: object) -> bool:
    if not isinstance(tool, str) or not tool:
        return False
    folded = tool.strip().lower()
    if folded in _SUBPROCESS_TOOLS:
        return True
    return folded.startswith("subprocess.") or folded.startswith("asyncio.create_subprocess_")


def surface_for(action_type: object, tool: object) -> str | None:
    """Server-derived surface. Ignores caller ``runtime.surface``."""
    if not isinstance(action_type, str):
        canonical, status = None, "malformed"
    else:
        canonical, status = classify_action_type(action_type)
    if status == "malformed" or not canonical:
        if is_subprocess_tool(tool):
            return "subprocess"
        return None
    if canonical == "http_request":
        return "http"
    if canonical in FILESYSTEM_TYPES:
        return "filesystem"
    if canonical == "mcp_call":
        return "mcp"
    if canonical.startswith("webmcp."):
        return "webmcp"
    if is_subprocess_tool(tool) or status == "alias" and canonical == "tool_call" and isinstance(action_type, str) and action_type.lower() in SHELL_ALIASES:
        return "subprocess"
    return None


def types_match(actual: object, expected: object, *, mode: str, surface: str | None) -> bool:
    """Whether a rule type predicate matches the action's canonical type."""
    actual_c, actual_status = classify_action_type(actual)
    expected_c, expected_status = classify_action_type(expected)
    if actual_status == "malformed" or expected_status == "malformed":
        return False
    if actual_c and expected_c and actual_c == expected_c:
        return True
    if isinstance(actual, str) and isinstance(expected, str) and actual.lower() == expected.lower():
        return True
    expected_folded = expected.lower() if isinstance(expected, str) else ""
    actual_folded = actual.lower() if isinstance(actual, str) else ""
    # A deny written against any filesystem spelling covers the family.
    if mode in _DENY_MODES and actual_folded in FILESYSTEM_TYPES and expected_folded in FILESYSTEM_TYPES:
        return True
    # Shell aliases are tool calls. A tool_call rule matches them, and a
    # subprocess rule matches a tool call only when the surface is subprocess
    # so an allow-all-subprocess rule does not allow unrelated tools.
    if expected_folded in SHELL_ALIASES and surface == "subprocess" and actual_c == "tool_call":
        return True
    if actual_folded in SHELL_ALIASES and expected_c == "tool_call":
        return True
    return False


def _apply_connection_binding(meta: dict[str, Any], identity: dict[str, Any], dest: Any) -> None:
    """Elevate a hostname's category from addresses the SDK resolved.

    Client-supplied categories are ignored and recomputed. A literal IP
    category is never weakened by a claimed address list. Absence of the
    binding leaves the URL identity unchanged, including ``dns_rebinding``.
    """
    binding = meta.get("destination_binding")
    if not isinstance(binding, dict):
        return
    status = binding.get("status")
    if isinstance(status, str):
        identity["connection_binding"] = status
    raw_addresses = binding.get("addresses")
    if not isinstance(raw_addresses, list):
        return
    classified: list[dict[str, str]] = []
    for item in raw_addresses:
        ip = item.get("ip") if isinstance(item, dict) else None
        if not isinstance(ip, str):
            continue
        category = address_category(ip)
        if category is None:
            continue
        classified.append({"ip": ip, "category": category})
    if not classified:
        return
    identity["resolved_addresses"] = classified
    if dest is None or not getattr(dest, "ok", False) or getattr(dest, "ip", None):
        return
    proposed = worst_category([item["category"] for item in classified])
    current = identity.get("destination_category") or "hostname"
    if proposed is None:
        return
    rank = {
        "metadata": 0,
        "loopback": 1,
        "link_local": 2,
        "private": 3,
        "multicast": 4,
        "reserved": 5,
        "public": 6,
        "hostname": 7,
    }
    if rank.get(proposed, 99) < rank.get(str(current), 99):
        identity["destination_category"] = proposed


def bind_security_identity(action: Any) -> Any | None:
    """Canonicalise ``action`` in place.

    Returns a terminal ``Decision`` when the identity is rejected. Returns
    None when policy evaluation should continue. Safe to call twice.
    """
    meta = dict(getattr(action, "metadata", None) or {})
    # A client can put issuer=varden in metadata. Only an identity this
    # process already bound may short-circuit a second evaluation.
    if getattr(action, "_varden_identity_bound", False):
        existing = meta.get("identity") if isinstance(meta.get("identity"), dict) else {}
        if existing.get("issuer") == _ISSUER:
            return _decision_from_identity(existing)

    claimed_type = getattr(action, "_claimed_type", action.type)
    original_url = action.url if isinstance(action.url, str) else None
    original_domain = action.domain if isinstance(action.domain, str) else action.domain
    original_tool = action.tool
    original_method = action.method
    runtime = dict(meta.get("runtime") or {}) if isinstance(meta.get("runtime"), dict) else {}
    claimed_surface = runtime.get("surface")
    claimed_execution = meta.get("execution_surface")

    canonical, type_status = classify_action_type(claimed_type if isinstance(claimed_type, str) else "")
    if type_status in {"ok", "alias"} and canonical:
        action.type = canonical
    elif type_status == "unknown" and isinstance(claimed_type, str):
        action.type = claimed_type.lower()
    else:
        action.type = ""

    rejection: str | None = None
    decision_action: str | None = None
    dest = None
    if isinstance(original_url, str) and original_url:
        dest = canonicalize_destination(original_url)
        hard = dest.rejection and dest.rejection != "unsupported_scheme"
        httpish = canonical == "http_request" or (dest.scheme in {"http", "https"})
        if hard and httpish:
            rejection = dest.rejection
            decision_action = "block"
        elif canonical == "http_request" and dest.rejection == "unsupported_scheme":
            rejection = "unsupported_scheme"
            decision_action = "unsupported"

    if rejection is None and isinstance(original_domain, str) and original_domain:
        claim = canonicalize_host_claim(original_domain)
        if isinstance(claim, str):
            if canonical == "http_request" or (dest is not None and dest.ok):
                rejection = claim if claim != "malformed_domain" else "malformed_domain"
                decision_action = "block"
        elif dest is not None and dest.ok and dest.host:
            claim_host, claim_port = claim
            dest_port = dest.port
            if dest.scheme in {"http", "https"} and dest_port is None:
                dest_port_cmp = {"http": 80, "https": 443}[dest.scheme]
            else:
                dest_port_cmp = dest_port
            if claim_host != dest.host or (claim_port is not None and claim_port != dest_port_cmp):
                rejection = "conflicting_destination_identity"
                decision_action = "block"

    if rejection is None and isinstance(original_tool, str) and ("\x00" in original_tool or original_tool != original_tool.strip()):
        rejection = "ambiguous_tool"
        decision_action = "block"

    if type_status == "malformed" and decision_action is None:
        rejection = "malformed_action_type"
        decision_action = "unsupported"

    if dest is not None and isinstance(original_url, str) and dest.evidence_url != original_url:
        # The stored action keeps the audit copy. Userinfo is not retained.
        action.url = dest.evidence_url

    if dest is not None and dest.ok and rejection is None and (canonical == "http_request" or isinstance(original_domain, str)):
        action.domain = dest.host
    elif rejection is None and isinstance(original_domain, str) and original_domain:
        claim = canonicalize_host_claim(original_domain)
        if not isinstance(claim, str):
            action.domain = claim[0]

    if canonical == "http_request" and isinstance(action.method, str) and action.method.strip():
        action.method = action.method.strip().upper()

    surface = surface_for(claimed_type if isinstance(claimed_type, str) else action.type, action.tool)
    if canonical == "tool_call" and isinstance(claimed_type, str) and claimed_type.lower() in SHELL_ALIASES:
        surface = "subprocess"
    if surface:
        runtime["surface"] = surface
        meta["execution_surface"] = surface
    else:
        runtime.pop("surface", None)
        meta.pop("execution_surface", None)
    if runtime:
        meta["runtime"] = runtime
    elif "runtime" in meta:
        meta["runtime"] = runtime

    resource = _filesystem_resource(action) if surface == "filesystem" or action.type in FILESYSTEM_TYPES else None
    method = action.method if isinstance(action.method, str) else original_method

    identity: dict[str, Any] = {
        "issuer": _ISSUER,
        "original_type": claimed_type if isinstance(claimed_type, str) else None,
        "type": action.type or None,
        "type_status": type_status,
        "enforcement_owner": ENFORCEMENT_OWNERS.get(action.type or ""),
        "original_url": dest.evidence_url if dest is not None else original_url,
        "canonical_url": dest.canonical_url if dest is not None and dest.ok else None,
        "original_domain": original_domain if isinstance(original_domain, str) else None,
        "host": dest.host if dest is not None and dest.ok else action.domain,
        "port": dest.port if dest is not None and dest.ok else None,
        "destination_category": dest.category if dest is not None and dest.ok else None,
        "surface": surface,
        "claimed_surface": claimed_surface if isinstance(claimed_surface, str) else None,
        "claimed_execution_surface": claimed_execution if isinstance(claimed_execution, str) else None,
        "resource": resource,
        "method": method if isinstance(method, str) else None,
        "rejection": rejection,
        "decision": decision_action,
        "dns_rebinding": dest.dns_rebinding if dest is not None and dest.ok else "not_applicable",
    }
    _apply_connection_binding(meta, identity, dest)
    meta["identity"] = identity
    if dest is not None and dest.ok:
        destination = {
            "scheme": dest.scheme,
            "host": dest.host,
            "port": dest.port,
            "path": dest.path,
            "query": dest.query,
            "canonical_url": dest.canonical_url,
            "category": identity.get("destination_category") or dest.category,
            "ip": dest.ip,
            "original_url": dest.evidence_url,
            "dns_rebinding": dest.dns_rebinding,
        }
        if identity.get("connection_binding"):
            destination["connection_binding"] = identity["connection_binding"]
        if identity.get("resolved_addresses"):
            destination["resolved_addresses"] = identity["resolved_addresses"]
        meta["destination"] = destination
    action.metadata = meta
    if isinstance(original_tool, str):
        action.tool = original_tool.strip() if rejection != "ambiguous_tool" else original_tool
    action._varden_identity_bound = True
    return _decision_from_identity(identity)


def enforce_known_type(action: Any, decision: Any) -> Any:
    """Replace an implicit allow of an unknown type with ``unsupported``."""
    from varden.models import Decision

    identity = {}
    meta = getattr(action, "metadata", None) or {}
    if isinstance(meta, dict) and isinstance(meta.get("identity"), dict):
        identity = meta["identity"]
    if identity.get("type_status") != "unknown":
        return decision
    if getattr(decision, "action", None) != "allow" or getattr(decision, "matched_rule", None) is not None:
        return decision
    updated = Decision(
        action="unsupported",
        reason="unknown action type has no enforcement owner and no explicit rule",
        matched_rule={"type": "action_identity", "code": "unknown_action_type"},
        effective_action="unsupported",
        route_target=getattr(decision, "route_target", None),
    )
    identity = dict(identity)
    identity["decision"] = "unsupported"
    identity["rejection"] = "unknown_action_type"
    meta = dict(meta)
    meta["identity"] = identity
    action.metadata = meta
    return updated


def _decision_from_identity(identity: dict[str, Any]) -> Any | None:
    from varden.models import Decision

    kind = identity.get("decision")
    if kind not in {"block", "unsupported"}:
        return None
    code = str(identity.get("rejection") or kind)
    if kind == "block":
        reason = f"ambiguous destination: {code}"
    else:
        reason = f"unsupported action identity: {code}"
    return Decision(
        action=kind,
        reason=reason,
        matched_rule={"type": "action_identity", "code": code},
        effective_action=kind,
    )


def _filesystem_resource(action: Any) -> str | None:
    args = action.args if isinstance(getattr(action, "args", None), dict) else {}
    raw = None
    for key in ("path", "file", "src", "dest", "destination"):
        value = args.get(key)
        if isinstance(value, str) and value:
            raw = value
            break
    if raw is None:
        nested = args.get("args")
        if isinstance(nested, (list, tuple)) and nested and isinstance(nested[0], str):
            raw = nested[0]
    if not isinstance(raw, str) or "\x00" in raw:
        return None
    return os.path.normpath(raw)
