from __future__ import annotations

import hashlib
import json
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1"

# Canonical WebMCP API surfaces Varden understands. Unknown surfaces are still
# scanned (see ``imperative_unknown``) rather than rejected, so a new draft
# does not silently disable protection.
API_SURFACES = (
    "document_model_context",
    "navigator_model_context",
    "declarative",
    "imperative_unknown",
)
ApiSurface = str


def _canonical_json(value: Any) -> str:
    """Deterministic JSON serialisation: sorted keys, no insignificant whitespace.

    Semantically irrelevant key ordering must not change the resulting hash.
    """

    def _default(obj: Any) -> Any:
        if isinstance(obj, (set, frozenset)):
            return sorted(obj)
        return str(obj)

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=_default, ensure_ascii=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


_ZERO_WIDTH_AND_CONTROL = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x00AD,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
}


def _strip_hidden_chars(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if code in _ZERO_WIDTH_AND_CONTROL:
            continue
        if unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\n\t\r":
            continue
        out.append(ch)
    return "".join(out)


def normalize_for_identity(text: str | None) -> str:
    """NFKC-normalise and strip hidden/control characters for identity comparison.

    Used to build the *sanitised canonical hash* so cosmetic or obfuscation-only
    edits (zero-width insertion, alternate compatibility form) do not appear as
    a "new" tool identity while still being flagged as a finding in their own right.
    """

    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _strip_hidden_chars(normalized)
    return " ".join(normalized.split()).strip().lower()


@dataclass
class WebMCPToolDefinition:
    """Canonical, versioned, cross-draft representation of a WebMCP tool.

    Adapted from the brief's suggested model to this project's dataclass +
    ``to_dict`` convention (see ``varden/models.py``). Unknown/draft-specific
    fields are preserved verbatim in ``extension_metadata`` so a newer or
    older WebMCP draft never silently loses security-relevant metadata.
    """

    name: str
    description: str = ""
    schema_version: str = SCHEMA_VERSION
    api_surface: ApiSurface = "imperative_unknown"
    title: str | None = None
    input_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    extension_metadata: dict[str, Any] = field(default_factory=dict)
    owner_origin: str = ""
    top_origin: str = ""
    registration_source: str | None = None
    registered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_raw(
        cls,
        raw: dict[str, Any],
        *,
        owner_origin: str,
        top_origin: str = "",
        api_surface: ApiSurface = "imperative_unknown",
        registration_source: str | None = None,
        registered_at: float | None = None,
    ) -> "WebMCPToolDefinition":
        """Build a canonical definition from an arbitrary observed object.

        Anything not in the known field set is preserved in
        ``extension_metadata`` rather than discarded, so draft-specific or
        vendor-specific fields remain part of the security surface.
        """

        raw = raw if isinstance(raw, dict) else {}
        known = {
            "name", "title", "description", "inputSchema", "input_schema",
            "annotations", "schemaVersion", "schema_version",
        }
        extension_metadata = {k: v for k, v in raw.items() if k not in known}
        name = str(raw.get("name") or "").strip()
        input_schema = raw.get("inputSchema") if isinstance(raw.get("inputSchema"), dict) else raw.get("input_schema")
        return cls(
            name=name,
            title=raw.get("title") if isinstance(raw.get("title"), str) else None,
            description=str(raw.get("description") or ""),
            input_schema=input_schema if isinstance(input_schema, dict) else None,
            annotations=raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {},
            extension_metadata=extension_metadata,
            owner_origin=owner_origin,
            top_origin=top_origin or owner_origin,
            api_surface=api_surface,
            registration_source=registration_source,
            registered_at=registered_at if registered_at is not None else time.time(),
        )

    def identity_key(self) -> str:
        """Stable identity for a tool within an origin, independent of metadata drift."""
        return f"{self.owner_origin}::{normalize_for_identity(self.name)}"

    def _sanitized_projection(self) -> dict[str, Any]:
        return {
            "name": normalize_for_identity(self.name),
            "title": normalize_for_identity(self.title),
            "description": normalize_for_identity(self.description),
            "input_schema": self.input_schema or {},
            "annotations": self.annotations or {},
        }

    def compute_hashes(self) -> tuple[str, str]:
        """Return (exact_observed_hash, sanitised_canonical_hash).

        Both hashes exclude ``registered_at``: it is an observation timestamp,
        not tool metadata, and including it would make the hash of otherwise
        byte-identical metadata differ on every observation, defeating its
        purpose for lifecycle diffing ("did the metadata actually change?").
        """
        payload = self.to_dict()
        payload.pop("registered_at", None)
        exact = sha256_hex(_canonical_json(payload))
        canonical = sha256_hex(_canonical_json(self._sanitized_projection()))
        return exact, canonical


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str  # info | low | medium | high | critical
    field_path: str
    evidence: str
    explanation: str
    confidence: float = 1.0
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskDriver:
    rule_id: str
    contribution: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskResult:
    score: int
    band: str
    profile_version: str
    drivers: list[RiskDriver] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "profile_version": self.profile_version,
            "drivers": [d.to_dict() for d in self.drivers],
        }


@dataclass
class CapabilityProfile:
    mutates_state: bool = False
    declared_readonly: bool | None = None
    mentions_payment: bool = False
    mentions_credential: bool = False
    mentions_destructive: bool = False
    mentions_clipboard: bool = False
    mentions_filesystem: bool = False
    mentions_network: bool = False
    sensitive_schema_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanContext:
    """Optional context available when scanning inside a live session.

    A static CLI scan (no browser, no session) supplies none of this and the
    engine degrades gracefully rather than fabricating lifecycle/provenance
    findings it has no evidence for.
    """

    is_third_party_frame: bool = False
    https: bool = True
    session_started_at: float | None = None
    session_already_active: bool = False
    existing_tool_names: list[str] = field(default_factory=list)
    previous_exact_hash: str | None = None
    previous_canonical_hash: str | None = None
    first_seen: bool = True
    registration_count_recent: int = 0
    trust_state: str | None = None  # "trusted" | "blocked" | None
    prior_violation_count: int = 0


@dataclass
class ScanResult:
    tool: WebMCPToolDefinition
    findings: list[Finding]
    risk: RiskResult
    capability: CapabilityProfile
    exact_hash: str
    canonical_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk": self.risk.to_dict(),
            "capability": self.capability.to_dict(),
            "exact_hash": self.exact_hash,
            "canonical_hash": self.canonical_hash,
        }


@dataclass
class SanitizeResult:
    sanitized_tool: WebMCPToolDefinition
    diff: dict[str, dict[str, Any]]
    unrepairable_fields: list[str]
    blocked: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "sanitized_tool": self.sanitized_tool.to_dict(),
            "diff": self.diff,
            "unrepairable_fields": self.unrepairable_fields,
            "blocked": self.blocked,
        }


@dataclass
class EnforcementOutcome:
    """Distinguishes what policy asked for from what was actually achievable.

    Browsers do not give Varden a universal interception primitive (see
    docs/web-shield-architecture.md §3), so "policy said block" and "block was
    actually achieved" are different facts and must not be collapsed.
    """

    policy_decision: str  # allow | monitor | warn | require_approval | sanitise | block
    requested_enforcement: str
    achieved_enforcement: str
    limitation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
