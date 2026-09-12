"""Typed resource model for Predictive Authority.

Resources never carry raw secret material — only identifiers, hashes, and
sensitivity classifications.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class ResourceType(str, Enum):
    FILESYSTEM_PATH = "filesystem_path"
    CREDENTIAL = "credential"
    ENVIRONMENT_VARIABLE = "environment_variable"
    REPOSITORY = "repository"
    NETWORK_ORIGIN = "network_origin"
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    DATABASE = "database"
    CLOUD_ACCOUNT = "cloud_account"
    CLUSTER = "cluster"
    DEPLOYMENT = "deployment"
    BRANCH = "branch"
    SECRET = "secret"
    EXTERNAL_API = "external_api"
    UNTRUSTED_CONTENT = "untrusted_content"
    PROVENANCE_SOURCE = "provenance_source"
    APPROVAL = "approval"
    UNKNOWN = "unknown"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    SECRET = "secret"
    CREDENTIAL = "credential"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    DELEGATED = "delegated"
    INTERNAL = "internal"
    UNTRUSTED = "untrusted"
    HOSTILE = "hostile"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Resource:
    resource_type: ResourceType
    identifier: str
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    provenance_ref: str | None = None
    scope: str = ""
    mutability: str = "unknown"  # immutable | mutable | unknown
    reversibility: str = "unknown"
    external: bool = False
    authority_domain: str = ""
    content_hash: str | None = None  # never the secret itself
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier", sanitize_identifier(self.identifier))
        if not self.authority_domain:
            object.__setattr__(self, "authority_domain", infer_domain(self))

    @property
    def node_id(self) -> str:
        return f"res:{self.resource_type.value}:{stable_id(self.identifier)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_type": self.resource_type.value,
            "identifier": self.identifier,
            "sensitivity": self.sensitivity.value,
            "trust_level": self.trust_level.value,
            "provenance_ref": self.provenance_ref,
            "scope": self.scope,
            "mutability": self.mutability,
            "reversibility": self.reversibility,
            "external": self.external,
            "authority_domain": self.authority_domain,
            "content_hash": self.content_hash,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Resource:
        return cls(
            resource_type=ResourceType(str(data.get("resource_type") or "unknown")),
            identifier=str(data.get("identifier") or ""),
            sensitivity=Sensitivity(str(data.get("sensitivity") or "internal")),
            trust_level=TrustLevel(str(data.get("trust_level") or "unknown")),
            provenance_ref=data.get("provenance_ref"),
            scope=str(data.get("scope") or ""),
            mutability=str(data.get("mutability") or "unknown"),
            reversibility=str(data.get("reversibility") or "unknown"),
            external=bool(data.get("external")),
            authority_domain=str(data.get("authority_domain") or ""),
            content_hash=data.get("content_hash"),
            metadata=dict(data.get("metadata") or {}),
        )


_SECRET_LIKE = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|authorization|credential|private[_-]?key)"
)


def sanitize_identifier(value: str, *, max_len: int = 240) -> str:
    """Redact secret-looking substrings and bound length for graph safety."""
    text = str(value or "")
    # Strip NULs / control chars.
    text = "".join(ch for ch in text if ch >= " " or ch in "\t")
    if _SECRET_LIKE.search(text) and "=" in text:
        # Keep key name, drop value.
        left, _, _right = text.partition("=")
        text = f"{left}=<redacted>"
    if len(text) > max_len:
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]
        text = text[: max_len - 16] + f"…#{digest}"
    return text


def stable_id(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:16]


def hash_content(value: Any) -> str:
    """Hash content for correlation without retaining secrets."""
    if value is None:
        raw = b""
    elif isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def infer_domain(resource: Resource) -> str:
    if resource.resource_type == ResourceType.CREDENTIAL:
        ident = resource.identifier.lower()
        if "aws" in ident:
            return "aws"
        if "github" in ident or "gh" in ident:
            return "github"
        if "ssh" in ident:
            return "ssh"
        if "db" in ident or "database" in ident or "postgres" in ident:
            return "database"
        return "credential"
    if resource.resource_type == ResourceType.NETWORK_ORIGIN:
        return "network"
    if resource.resource_type in {ResourceType.MCP_SERVER, ResourceType.MCP_TOOL}:
        return "mcp"
    if resource.resource_type == ResourceType.FILESYSTEM_PATH:
        return "filesystem"
    return resource.resource_type.value


_SENSITIVE_PATH_HINTS = (
    ".aws",
    ".ssh",
    ".env",
    "credentials",
    "id_rsa",
    "id_ed25519",
    ".kube",
    ".docker/config",
    ".netrc",
    ".npmrc",
    ".pypirc",
)


def filesystem_resource(path: str, *, trust: TrustLevel = TrustLevel.UNKNOWN) -> Resource:
    text = sanitize_identifier(path)
    # If the "path" looks like an inline secret assignment, never retain the value.
    if _SECRET_LIKE.search(text) and "=" in text:
        left, _, _ = text.partition("=")
        text = f"{left}=<redacted>"
    lowered = text.lower()
    sensitivity = Sensitivity.INTERNAL
    external = False
    rev = "conditionally_reversible"
    if any(h in lowered for h in _SENSITIVE_PATH_HINTS):
        sensitivity = Sensitivity.CREDENTIAL if ("credential" in lowered or ".aws" in lowered or ".ssh" in lowered or ".env" in lowered) else Sensitivity.SECRET
        rev = "unknown"
    # Heuristic: absolute paths outside common workspace markers.
    if text.startswith("/") and "/tmp/" not in lowered and "workspace" not in lowered:
        # Still may be workspace; leave external False unless clearly outside.
        pass
    return Resource(
        resource_type=ResourceType.FILESYSTEM_PATH,
        identifier=text,
        sensitivity=sensitivity,
        trust_level=trust,
        mutability="mutable",
        reversibility=rev,
        external=external,
        content_hash=hash_content(text),
    )


def credential_resource(name: str, *, known_scope: bool = False) -> Resource:
    return Resource(
        resource_type=ResourceType.CREDENTIAL,
        identifier=sanitize_identifier(name),
        sensitivity=Sensitivity.CREDENTIAL,
        trust_level=TrustLevel.UNKNOWN,
        scope="known" if known_scope else "unknown",
        mutability="immutable",
        reversibility="unknown",
        external=False,
        content_hash=hash_content(name),
        metadata={"scope_known": known_scope},
    )


def network_origin_resource(url_or_host: str, *, write: bool = False) -> Resource:
    raw = str(url_or_host or "")
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or raw).lower()
    except Exception:
        host = sanitize_identifier(raw).lower()
    host = sanitize_identifier(host)
    return Resource(
        resource_type=ResourceType.NETWORK_ORIGIN,
        identifier=host,
        sensitivity=Sensitivity.INTERNAL,
        trust_level=TrustLevel.UNTRUSTED,
        mutability="immutable",
        reversibility="irreversible" if write else "reversible",
        external=True,
        authority_domain="network",
        content_hash=hash_content(host),
        metadata={"write": write, "sink": write},
    )


def untrusted_content_resource(source_id: str, *, trust: TrustLevel = TrustLevel.UNTRUSTED) -> Resource:
    return Resource(
        resource_type=ResourceType.UNTRUSTED_CONTENT,
        identifier=sanitize_identifier(source_id),
        sensitivity=Sensitivity.INTERNAL,
        trust_level=trust,
        mutability="immutable",
        reversibility="unknown",
        external=True,
        authority_domain="provenance",
        content_hash=hash_content(source_id),
    )


def mcp_server_resource(server: str, *, trust: TrustLevel = TrustLevel.UNKNOWN) -> Resource:
    return Resource(
        resource_type=ResourceType.MCP_SERVER,
        identifier=sanitize_identifier(server),
        sensitivity=Sensitivity.INTERNAL,
        trust_level=trust,
        mutability="immutable",
        reversibility="unknown",
        external=True,
        authority_domain=f"mcp:{sanitize_identifier(server)}",
        content_hash=hash_content(server),
    )


def mcp_tool_resource(server: str, tool: str, *, privileged: bool = False) -> Resource:
    ident = f"{sanitize_identifier(server)}/{sanitize_identifier(tool)}"
    return Resource(
        resource_type=ResourceType.MCP_TOOL,
        identifier=ident,
        sensitivity=Sensitivity.SENSITIVE if privileged else Sensitivity.INTERNAL,
        trust_level=TrustLevel.UNKNOWN,
        mutability="immutable",
        reversibility="unknown",
        external=True,
        authority_domain=f"mcp:{sanitize_identifier(server)}",
        content_hash=hash_content(ident),
        metadata={"privileged": privileged, "server": sanitize_identifier(server), "tool": sanitize_identifier(tool)},
    )
