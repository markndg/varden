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

    Used to build the *security-normalised hash* so cosmetic or obfuscation-only
    edits (zero-width insertion, alternate compatibility form) do not appear as
    a "new" tool identity while still being flagged as a finding in their own right.
    """

    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _strip_hidden_chars(normalized)
    return " ".join(normalized.split()).strip().lower()


_MAX_CANONICALIZE_DEPTH = 25


def _security_normalize(value: Any, depth: int = 0) -> Any:
    """Recursively normalise every security-relevant text fragment in an
    arbitrary (possibly hostile) nested structure, for security-hash
    purposes only — never for storage or display.

    Rules (docs/web-shield-hardening-review.md #7):
      * every string leaf (dict keys included) is Unicode/zero-width/whitespace
        normalised via ``normalize_for_identity``, so e.g. a schema property
        description obfuscated with zero-width characters normalises the same
        as its clean equivalent;
      * dict keys are normalised but never merged/overwritten even if two
        distinct original keys normalise to the same string — collapsing them
        into an ordinary dict would silently discard one of the two values,
        which this function must never do. Instead maps become a sorted list
        of ``[normalized_key, normalized_value]`` pairs, so duplicates remain
        individually visible to the hash;
      * arrays preserve their original order (order can be semantically
        meaningful — e.g. an ordered list of steps or examples);
      * non-string primitives (numbers, booleans, ``None``) keep a
        type-tagged wrapper so ``1``, ``"1"`` and ``True`` can never collide;
      * recursion is depth-bounded so hostile deeply-nested input cannot
        cause unbounded recursion or a crash.
    """

    if depth > _MAX_CANONICALIZE_DEPTH:
        return {"__truncated__": True}
    if isinstance(value, str):
        return normalize_for_identity(value)
    if isinstance(value, bool):
        return {"__bool__": value}
    if isinstance(value, (int, float)):
        return {"__num__": value}
    if value is None:
        return {"__null__": True}
    if isinstance(value, dict):
        pairs = [(normalize_for_identity(str(k)), _security_normalize(v, depth + 1)) for k, v in value.items()]
        # Sort by normalized key only: values may be dicts/lists, which are
        # unorderable in Python and would raise TypeError if used as a sort
        # tiebreaker. Original insertion order is a stable, deterministic
        # tiebreaker for two distinct keys that normalise to the same string.
        pairs.sort(key=lambda pair: pair[0])
        return {"__map__": [[k, v] for k, v in pairs]}
    if isinstance(value, (list, tuple)):
        return {"__seq__": [_security_normalize(v, depth + 1) for v in value]}
    return {"__other__": str(value)}


@dataclass
class ToolHashes:
    """The three distinct hashes computed over a ``WebMCPToolDefinition``.

    See docs/web-shield-hardening-review.md #7 for the full rationale. Each
    hash answers a different question and must not be substituted for
    another:

    * ``observed_hash`` — did the exact, byte/value-level observed
      representation change at all (including whitespace-only or
      zero-width-only edits)? Used for tamper/drift forensics where every
      byte matters.
    * ``structural_hash`` — did the *transport-level* representation change,
      independent of non-semantic fields (the observation timestamp) but
      without any text normalisation? Two observations that differ only in
      when they were captured hash identically.
    * ``security_normalised_hash`` — did anything *security-relevant*
      change, after recursively normalising Unicode/zero-width/whitespace
      obfuscation across every text-bearing field (name, title, description,
      schema keys/descriptions/examples/defaults, annotations, extension
      metadata)? Used for lifecycle drift detection and trust/metadata
      pinning so obfuscation-only edits cannot evade detection while
      genuine content changes are never silently normalised away.
    """

    observed_hash: str
    structural_hash: str
    security_normalised_hash: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


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

    def _security_relevant_fields(self) -> dict[str, Any]:
        """Every field that can carry an attacker-controlled security-relevant
        payload — i.e. everything except transport/observation bookkeeping
        (origin/timestamps/registration provenance, which are handled by
        identity and provenance scoring separately, not by content hashing)."""

        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_schema or {},
            "annotations": self.annotations or {},
            "extension_metadata": self.extension_metadata or {},
        }

    def compute_hashes(self) -> "ToolHashes":
        """Return the three canonical hashes (see ``ToolHashes``).

        All three exclude ``registered_at``: it is an observation timestamp,
        not tool metadata, and including it would make the hash of otherwise
        byte-identical metadata differ on every observation, defeating its
        purpose for lifecycle diffing ("did the metadata actually change?").
        """
        payload = self.to_dict()
        payload.pop("registered_at", None)
        observed_hash = sha256_hex(_canonical_json(payload))

        structural_payload = dict(payload)
        structural_payload.pop("registration_source", None)
        structural_hash = sha256_hex(_canonical_json(structural_payload))

        security_normalised_hash = sha256_hex(
            _canonical_json(_security_normalize(self._security_relevant_fields()))
        )
        return ToolHashes(
            observed_hash=observed_hash,
            structural_hash=structural_hash,
            security_normalised_hash=security_normalised_hash,
        )


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
class RiskComponents:
    """Explicit decomposition of a risk score (docs/web-shield-hardening-review.md #5).

    Origin trust may reduce ``provenance_risk`` only. It must never reduce
    ``content_risk`` (prompt-injection / exfiltration / credential-access /
    payment / security-bypass language), ``capability_risk`` (mutation,
    sensitive-schema, declared-vs-inferred capability mismatch),
    ``lifecycle_risk`` (registration anomalies, confusable names) or
    ``impact_risk`` (output contamination, cross-origin flow, resource
    abuse). A confirmed critical finding in any of those four components
    therefore remains critical regardless of trust state.
    """

    content_risk: int = 0
    capability_risk: int = 0
    lifecycle_risk: int = 0
    provenance_risk: int = 0
    impact_risk: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskResult:
    score: int
    band: str
    profile_version: str
    drivers: list[RiskDriver] = field(default_factory=list)
    components: RiskComponents = field(default_factory=RiskComponents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "profile_version": self.profile_version,
            "drivers": [d.to_dict() for d in self.drivers],
            "components": self.components.to_dict(),
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
    structural_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk": self.risk.to_dict(),
            "capability": self.capability.to_dict(),
            "exact_hash": self.exact_hash,
            "canonical_hash": self.canonical_hash,
            "structural_hash": self.structural_hash,
            "observed_hash": self.exact_hash,
            "security_normalised_hash": self.canonical_hash,
        }


#: The three possible outcomes for a single candidate fragment (a sentence,
#: bullet, semicolon-clause, line, or HTML comment) considered for removal.
#: See docs/web-shield-hardening-review.md #9 and varden/webshield/sanitize.py.
SANITIZE_DECISION_SAFE = "safe_to_sanitise"
SANITIZE_DECISION_UNSAFE = "unsafe_to_sanitise"
SANITIZE_DECISION_NO_OP = "no_sanitisation_needed"


@dataclass
class FragmentDecision:
    """The full audit trail for one candidate fragment within a sanitised field.

    Every sanitisation must be individually explainable: which exact text was
    considered, what (if anything) was removed, which deterministic rule(s)
    fired, how confident the classifier is, and — critically — whether
    removing this fragment could have changed what the tool actually does
    (``semantics_changed``). A fragment is only ever removed outright
    (``safe_to_sanitise``); this codebase never rewrites/paraphrases text, so
    "resulting_fragment" for a safe removal is always the empty string.
    """

    field_path: str
    original_fragment: str
    resulting_fragment: str
    decision: str  # safe_to_sanitise | unsafe_to_sanitise | no_sanitisation_needed
    rule_ids: list[str] = field(default_factory=list)
    confidence: float = 1.0
    reason: str = ""
    semantics_changed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizeResult:
    sanitized_tool: WebMCPToolDefinition
    diff: dict[str, dict[str, Any]]
    unrepairable_fields: list[str]
    blocked: bool
    decisions: list[FragmentDecision] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sanitized_tool": self.sanitized_tool.to_dict(),
            "diff": self.diff,
            "unrepairable_fields": self.unrepairable_fields,
            "blocked": self.blocked,
            "decisions": [d.to_dict() for d in self.decisions],
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
