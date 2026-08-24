"""Provenance, taint and authority-flow data models.

These are explicit security objects — not risk-score decorations. They encode
where information came from, how trustworthy that origin is, and which
authorities a *causal chain* is permitted to exercise.

Authentication and trust are separate properties: an authenticated MCP
server is not automatically trusted, and local filesystem content is not
automatically trusted.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1"

SOURCE_TYPES = (
    "user",
    "system",
    "developer",
    "local_file",
    "repository_file",
    "mcp_tool_definition",
    "mcp_tool_response",
    "web_page",
    "webmcp_tool",
    "http_response",
    "email",
    "chat_message",
    "database_result",
    "command_output",
    "environment",
    "generated",
    "unknown",
)

TRUST_LEVELS = (
    "trusted",
    "delegated",
    "internal",
    "untrusted",
    "hostile",
    "unknown",
)

# Ordered from most to least trustworthy for lattice comparisons.
_TRUST_RANK = {
    "trusted": 5,
    "delegated": 4,
    "internal": 3,
    "unknown": 2,
    "untrusted": 1,
    "hostile": 0,
}

TAINT_TYPES = (
    "external_input",
    "untrusted_instruction",
    "untrusted_tool_metadata",
    "untrusted_tool_output",
    "cross_origin",
    "secret",
    "credential",
    "private_data",
    "internal_data",
    "user_authorised",
    "sanitised",
)

AUTHORITY_CLASSES = (
    "NONE",
    "READ_PUBLIC",
    "READ_LOCAL",
    "READ_PRIVATE",
    "READ_SECRETS",
    "WRITE_LOCAL",
    "WRITE_REPOSITORY",
    "WRITE_DATABASE",
    "WRITE_CLOUD",
    "EXECUTE_LOCAL",
    "EXECUTE_PRIVILEGED",
    "NETWORK_PUBLIC",
    "NETWORK_INTERNAL",
    "NETWORK_CREDENTIALLED",
    "MCP_UNPRIVILEGED",
    "MCP_PRIVILEGED",
    "IDENTITY_USE",
    "PAYMENT",
    "DELETE",
    "ADMIN",
)

# Privilege lattice: higher numbers are more privileged.
_AUTHORITY_RANK = {
    "NONE": 0,
    "READ_PUBLIC": 10,
    "NETWORK_PUBLIC": 15,
    "MCP_UNPRIVILEGED": 18,
    "READ_LOCAL": 20,
    "WRITE_LOCAL": 25,
    "EXECUTE_LOCAL": 30,
    "NETWORK_INTERNAL": 35,
    "READ_PRIVATE": 40,
    "INTERNAL_DATA": 40,
    "WRITE_REPOSITORY": 45,
    "WRITE_DATABASE": 50,
    "WRITE_CLOUD": 55,
    "NETWORK_CREDENTIALLED": 60,
    "MCP_PRIVILEGED": 65,
    "READ_SECRETS": 70,
    "IDENTITY_USE": 75,
    "EXECUTE_PRIVILEGED": 80,
    "PAYMENT": 85,
    "DELETE": 90,
    "ADMIN": 100,
}

NODE_TYPES = (
    "source",
    "observation",
    "llm_call",
    "tool_call",
    "tool_result",
    "http_request",
    "http_response",
    "subprocess",
    "file_read",
    "file_write",
    "mcp_call",
    "mcp_result",
    "webmcp_registration",
    "webmcp_result",
    "user_approval",
)

EDGE_TYPES = (
    "derived_from",
    "influenced_by",
    "triggered",
    "returned",
    "read_from",
    "sent_to",
    "authorised_by",
    "approved_by",
    "sanitised_from",
)

FINDING_TYPES = (
    "authority_escalation",
    "confused_deputy",
    "cross_server_authority_flow",
    "untrusted_to_privileged",
    "provenance_exfiltration_chain",
    "delegation_violation",
    "tool_trust_drift",
    "unknown_provenance_sensitive_action",
    "dangerous_capability_combination",
)


def new_id(prefix: str = "prv") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def content_hash(value: Any) -> str:
    """Stable hash of a value for correlation without storing the value."""
    text = repr(value) if not isinstance(value, (str, bytes)) else (
        value if isinstance(value, str) else value.decode("utf-8", errors="replace")
    )
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def trust_rank(level: str) -> int:
    return _TRUST_RANK.get(str(level or "unknown"), 2)


def authority_rank(name: str) -> int:
    return _AUTHORITY_RANK.get(str(name or "NONE"), 0)


def min_trust(*levels: str) -> str:
    if not levels:
        return "unknown"
    return min(levels, key=trust_rank)


def max_authority(classes: set[str] | list[str]) -> str:
    if not classes:
        return "NONE"
    return max(classes, key=authority_rank)


@dataclass
class ProvenanceSource:
    source_id: str
    source_type: str = "unknown"
    origin: str = ""
    principal: str = ""
    trust_level: str = "unknown"
    integrity: str = "unverified"  # verified | unverified | tampered
    authenticated: bool = False
    first_seen: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Completeness: False means the client/integration could not observe
    # full causal context. Never treat incomplete provenance as trusted.
    provenance_complete: bool = True

    def __post_init__(self) -> None:
        if self.source_type not in SOURCE_TYPES:
            self.source_type = "unknown"
        if self.trust_level not in TRUST_LEVELS:
            self.trust_level = "unknown"
        # Hard invariant: incomplete observation cannot claim trusted.
        if not self.provenance_complete and self.trust_level in {"trusted", "delegated"}:
            self.trust_level = "unknown"
        # Hard invariant: untrusted client assertions of "trusted"/"user" are
        # rejected at construction when integrity is unverified and no
        # server-side principal is attached. Callers with real authority
        # must set integrity="verified" after server-side validation.
        if (
            self.trust_level == "trusted"
            and self.integrity != "verified"
            and self.source_type not in {"system", "developer"}
        ):
            self.trust_level = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ProvenanceSource":
        data = data or {}
        return cls(
            source_id=str(data.get("source_id") or new_id("src")),
            source_type=str(data.get("source_type") or "unknown"),
            origin=str(data.get("origin") or ""),
            principal=str(data.get("principal") or ""),
            trust_level=str(data.get("trust_level") or "unknown"),
            integrity=str(data.get("integrity") or "unverified"),
            authenticated=bool(data.get("authenticated")),
            first_seen=float(data.get("first_seen") or time.time()),
            metadata=dict(data.get("metadata") or {}),
            provenance_complete=bool(data.get("provenance_complete", True)),
        )

    @classmethod
    def unknown(cls, *, origin: str = "", reason: str = "unobserved") -> "ProvenanceSource":
        return cls(
            source_id=new_id("src"),
            source_type="unknown",
            origin=origin or "unknown",
            trust_level="unknown",
            integrity="unverified",
            provenance_complete=False,
            metadata={"reason": reason},
        )

    @classmethod
    def user(cls, *, principal: str = "user", origin: str = "user") -> "ProvenanceSource":
        return cls(
            source_id=new_id("src"),
            source_type="user",
            origin=origin,
            principal=principal,
            trust_level="trusted",
            integrity="verified",
            authenticated=True,
            provenance_complete=True,
        )


@dataclass
class TaintSet:
    """Explicit taint markers carried by a value or action context.

    Taint never decays with depth. Only an explicit, typed sanitiser may
    remove specific taints — and even then provenance ancestry remains.
    """

    tags: set[str] = field(default_factory=set)

    def add(self, *tags: str) -> "TaintSet":
        for tag in tags:
            if tag in TAINT_TYPES:
                self.tags.add(tag)
        return self

    def merge(self, other: "TaintSet | set[str] | list[str] | None") -> "TaintSet":
        if other is None:
            return self
        tags = other.tags if isinstance(other, TaintSet) else set(other)
        self.tags |= {t for t in tags if t in TAINT_TYPES}
        return self

    def has(self, tag: str) -> bool:
        return tag in self.tags

    def has_any(self, *tags: str) -> bool:
        return bool(self.tags.intersection(tags))

    def is_untrusted(self) -> bool:
        return self.has_any(
            "external_input",
            "untrusted_instruction",
            "untrusted_tool_metadata",
            "untrusted_tool_output",
            "cross_origin",
        )

    def is_sensitive(self) -> bool:
        return self.has_any("secret", "credential", "private_data", "internal_data")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tags": sorted(self.tags),
            "untrusted": self.is_untrusted(),
            "secret": self.has("secret") or self.has("credential"),
            "external": self.has("external_input") or self.has("untrusted_tool_output"),
            "private": self.has("private_data") or self.has("internal_data"),
            "user_authorised": self.has("user_authorised"),
            "sanitised": self.has("sanitised"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | list | set | None) -> "TaintSet":
        if data is None:
            return cls()
        if isinstance(data, (list, set)):
            return cls(tags={t for t in data if t in TAINT_TYPES})
        tags = data.get("tags") or []
        return cls(tags={t for t in tags if t in TAINT_TYPES})


@dataclass
class TaintedValue:
    """A value that retains provenance and taint across transformations."""

    value: Any
    provenance: list[ProvenanceSource] = field(default_factory=list)
    taints: TaintSet = field(default_factory=TaintSet)
    derived_from: list[str] = field(default_factory=list)
    content_hash: str = ""
    sanitiser: str | None = None

    def __post_init__(self) -> None:
        if not self.content_hash and self.value is not None:
            self.content_hash = content_hash(self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "provenance": [p.to_dict() for p in self.provenance],
            "taints": self.taints.to_dict(),
            "derived_from": list(self.derived_from),
            "sanitiser": self.sanitiser,
            # Never embed the raw value in persisted evidence.
        }


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    trace_id: str = ""
    event_id: int | None = None
    label: str = ""
    source_ids: list[str] = field(default_factory=list)
    authority_required: list[str] = field(default_factory=list)
    trust_level: str = "unknown"
    taints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    edge_id: str
    edge_type: str
    from_node: str
    to_node: str
    trace_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Delegation:
    """Authority delegated to a specific causal chain / principal.

    This is the heart of Ghostjacking defence: possessing a capability is
    not the same as being authorised to exercise it in *this* causal chain.
    Untrusted data must never create or broaden a Delegation.
    """

    delegation_id: str
    principal: str
    capabilities: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)
    issued_by: str = "user"
    issued_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    trace_scope: str | None = None
    # Server-side only: clients cannot mint verified delegations.
    integrity: str = "verified"

    def is_active(self, now: float | None = None) -> bool:
        if self.integrity != "verified":
            return False
        now = time.time() if now is None else now
        if self.expires_at is not None and now > self.expires_at:
            return False
        return True

    def grants(self, authority: str, resource: str | None = None) -> bool:
        if not self.is_active():
            return False
        if authority not in self.capabilities and "ADMIN" not in self.capabilities:
            # ADMIN grants everything; otherwise require exact match or a
            # strictly less-privileged capability that covers the request
            # only when explicitly listed.
            return False
        if self.resources and resource:
            return any(_resource_matches(pattern, resource) for pattern in self.resources)
        if self.resources and not resource:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Delegation":
        data = data or {}
        caps = [c for c in (data.get("capabilities") or []) if c in AUTHORITY_CLASSES]
        return cls(
            delegation_id=str(data.get("delegation_id") or new_id("dlg")),
            principal=str(data.get("principal") or "user"),
            capabilities=caps,
            resources=list(data.get("resources") or []),
            constraints=dict(data.get("constraints") or {}),
            issued_by=str(data.get("issued_by") or "user"),
            issued_at=float(data.get("issued_at") or time.time()),
            expires_at=data.get("expires_at"),
            trace_scope=data.get("trace_scope"),
            integrity=str(data.get("integrity") or "verified"),
        )

    @classmethod
    def public_read_only(cls, *, principal: str = "agent", trace_scope: str | None = None) -> "Delegation":
        return cls(
            delegation_id=new_id("dlg"),
            principal=principal,
            capabilities=["READ_PUBLIC", "NETWORK_PUBLIC", "MCP_UNPRIVILEGED"],
            resources=["*"],
            issued_by="system",
            trace_scope=trace_scope,
            integrity="verified",
        )


def _resource_matches(pattern: str, resource: str) -> bool:
    if pattern == "*" or pattern == resource:
        return True
    if pattern.endswith("*") and resource.startswith(pattern[:-1]):
        return True
    return False


@dataclass
class AuthorityRequirement:
    required: set[str] = field(default_factory=set)
    resource: str | None = None
    reason: str = ""
    action_class: str = ""  # filesystem | http | subprocess | mcp | webmcp | tool | llm | unknown

    def to_dict(self) -> dict[str, Any]:
        return {
            "required": sorted(self.required),
            "resource": self.resource,
            "reason": self.reason,
            "action_class": self.action_class,
        }


@dataclass
class AuthorityAnalysis:
    """Result of comparing required authority against delegated authority.

    ``granted`` is what the *causal chain* may exercise — not what the agent
    process is technically able to call.
    """

    required: list[str] = field(default_factory=list)
    granted: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    escalation: bool = False
    violation: bool = False
    resource: str | None = None
    reason: str = ""
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "required": list(self.required),
            "granted": list(self.granted),
            "missing": list(self.missing),
            "escalation": self.escalation,
            "violation": self.violation,
            "resource": self.resource,
            "reason": self.reason,
            "findings": list(self.findings),
        }


@dataclass
class FlowAnalysis:
    cross_origin: bool = False
    cross_server: bool = False
    private_to_public: bool = False
    untrusted_to_privileged: bool = False
    secret_egress: bool = False
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CausalAnalysis:
    depth: int = 0
    untrusted_ancestor: bool = False
    hostile_ancestor: bool = False
    unknown_ancestor: bool = False
    user_authorised: bool = False
    ancestor_source_ids: list[str] = field(default_factory=list)
    path: list[dict[str, Any]] = field(default_factory=list)
    provenance_complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceAnalysis:
    """Full pre-execution analysis attached to an Action before PolicyEngine."""

    sources: list[ProvenanceSource] = field(default_factory=list)
    taint: TaintSet = field(default_factory=TaintSet)
    authority: AuthorityAnalysis = field(default_factory=AuthorityAnalysis)
    flow: FlowAnalysis = field(default_factory=FlowAnalysis)
    causal: CausalAnalysis = field(default_factory=CausalAnalysis)
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_path: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_metadata(self) -> dict[str, Any]:
        """Shape written onto Action.metadata for PolicyEngine predicates."""
        trust_levels = [s.trust_level for s in self.sources] or ["unknown"]
        source_types = sorted({s.source_type for s in self.sources}) or ["unknown"]
        origins = sorted({s.origin for s in self.sources if s.origin}) or ["unknown"]
        return {
            "provenance": {
                "trust": min_trust(*trust_levels),
                "source_type": source_types[0] if len(source_types) == 1 else "mixed",
                "source_types": source_types,
                "origin": origins[0] if len(origins) == 1 else "mixed",
                "origins": origins,
                "sources": [s.to_dict() for s in self.sources],
                "complete": self.causal.provenance_complete and all(s.provenance_complete for s in self.sources),
            },
            "taint": self.taint.to_dict(),
            "authority": self.authority.to_dict(),
            "flow": self.flow.to_dict(),
            "causal": self.causal.to_dict(),
            "findings": list(self.findings),
            "attack_path": list(self.attack_path),
            "explanation": list(self.explanation),
            "analysis_latency_ms": self.latency_ms,
            "schema_version": SCHEMA_VERSION,
        }
