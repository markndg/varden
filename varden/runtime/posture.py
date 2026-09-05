"""Authoritative runtime security posture attestation.

coverage  = what execution surfaces Varden can currently observe/enforce
readiness = whether configured runtime requirements are satisfied
posture   = Varden's authoritative interpretation of the current enforcement state

Agents must report posture results; they must not invent or upgrade them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from varden.runtime.coverage import (
    ENFORCED,
    NOT_ROUTED,
    OBSERVATIONAL,
    PARTIAL,
    UNCOVERED,
    UNSUPPORTED,
    CoverageRegistry,
    CoverageSurface,
    get_coverage_registry,
)
from varden.runtime.modes import is_enforcing, normalize_mode

SCHEMA_VERSION = "1"

# Stable machine-readable vocabulary (lowercase in JSON).
PROTECTED = "protected"
PROTECTED_WITH_GAPS = "protected_with_gaps"
NOT_FULLY_ROUTED = "not_fully_routed"
NOT_READY = "not_ready"
NOT_PROTECTED = "not_protected"

VALID_RESULTS = frozenset(
    {PROTECTED, PROTECTED_WITH_GAPS, NOT_FULLY_ROUTED, NOT_READY, NOT_PROTECTED}
)

# Human display labels for Result line.
RESULT_LABELS = {
    PROTECTED: "PROTECTED",
    PROTECTED_WITH_GAPS: "PROTECTED WITH GAPS",
    NOT_FULLY_ROUTED: "NOT FULLY ROUTED",
    NOT_READY: "NOT READY",
    NOT_PROTECTED: "NOT PROTECTED",
}

# Gap states that prevent PROTECTED (when applicable).
_GAP_STATUSES = frozenset({PARTIAL, OBSERVATIONAL, UNCOVERED, UNSUPPORTED, NOT_ROUTED})

# Precedence (first match wins when evaluating candidate flags):
#   NOT_PROTECTED → NOT_READY → NOT_FULLY_ROUTED → PROTECTED_WITH_GAPS → PROTECTED
#
# Semantics:
# - NOT_PROTECTED: no meaningful active enforcing boundary for this runtime
# - NOT_READY: active/configured runtime fails its own readiness contract
# - NOT_FULLY_ROUTED: material protection path exists but an applicable surface
#   is explicitly NOT_ROUTED (e.g. discovered/required MCP outside the gateway)
# - PROTECTED_WITH_GAPS: enforcing runtime is active but applicable surfaces have
#   incomplete coverage (PARTIAL / UNCOVERED / UNSUPPORTED / OBSERVATIONAL)
# - PROTECTED: enforcing runtime is ready and every applicable surface is ENFORCED

CATEGORY_ORDER = ("http", "subprocess", "filesystem", "mcp", "tools", "llm")
CATEGORY_LABELS = {
    "http": "Network",
    "subprocess": "Subprocess",
    "filesystem": "Filesystem",
    "mcp": "MCP",
    "tools": "Tools",
    "llm": "LLM",
}

MCP_REMEDIATION = "Route MCP through the Varden gateway using `varden mcp wrap`."


@dataclass
class PostureGap:
    surface: str
    state: str
    severity: str
    reason: str
    component: str | None = None
    remediation_available: bool = False
    remediation: str | None = None
    accepted_exception: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "surface": self.surface,
            "state": self.state.lower(),
            "severity": self.severity,
            "reason": self.reason,
            "remediation_available": self.remediation_available,
        }
        if self.component:
            out["component"] = self.component
        if self.remediation:
            out["remediation"] = self.remediation
        if self.accepted_exception:
            out["accepted_exception"] = True
        return out


@dataclass
class PostureReport:
    schema_version: str
    result: str
    runtime: dict[str, Any]
    verification: dict[str, Any]
    surfaces: dict[str, dict[str, Any]]
    gaps: list[PostureGap] = field(default_factory=list)
    # Internal/debug: do not put secrets here.
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "result": self.result,
            "runtime": self.runtime,
            "verification": self.verification,
            "surfaces": self.surfaces,
            "gaps": [g.to_dict() for g in self.gaps],
        }

    def format_human(self) -> str:
        lines: list[str] = []
        lines.append("Varden Security Posture")
        lines.append("")
        lines.append("Runtime")
        lines.append(f"  Mode: {self.runtime.get('mode') or 'unknown'}")
        lines.append(f"  Fail mode: {self.runtime.get('fail_mode') or 'unknown'}")
        ready_label = str(self.runtime.get("readiness") or "unknown").upper().replace("_", " ")
        lines.append(f"  Readiness: {ready_label}")
        lines.append("")
        lines.append("Protection")
        for cat in CATEGORY_ORDER:
            row = self.surfaces.get(cat)
            if not row:
                continue
            label = CATEGORY_LABELS.get(cat, cat.upper())
            state = str(row.get("state") or "unknown").upper()
            lines.append(f"  {label:<12} {state}")
        if not self.surfaces:
            lines.append("  (no applicable surfaces)")
        lines.append("")
        lines.append("Verification")
        lines.append(f"  Attestation: {str(self.verification.get('attestation') or 'unknown').upper()}")
        lines.append(f"  Readiness: {str(self.verification.get('readiness') or 'unknown').upper().replace('_', ' ')}")
        lines.append(f"  Self-test: {str(self.verification.get('self_test') or 'not_run').upper().replace('_', ' ')}")
        material = [g for g in self.gaps if not g.accepted_exception]
        if material:
            lines.append("")
            lines.append("Critical gaps")
            for gap in material:
                lines.append(f"  {gap.reason}")
                if gap.remediation_available and gap.remediation:
                    lines.append(f"    Remediation: {gap.remediation}")
        lines.append("")
        lines.append("Result")
        lines.append(f"  {RESULT_LABELS.get(self.result, self.result.upper())}")
        return "\n".join(lines) + "\n"


def _status_rank(status: str) -> int:
    order = {
        ENFORCED: 0,
        "ENFORCED VIA GATEWAY": 0,
        PARTIAL: 1,
        OBSERVATIONAL: 2,
        NOT_ROUTED: 3,
        UNCOVERED: 4,
        UNSUPPORTED: 5,
    }
    return order.get(status, 99)


def _worst_status(statuses: list[str]) -> str:
    if not statuses:
        return UNCOVERED
    return sorted(statuses, key=_status_rank, reverse=True)[0]


def _is_accepted(name: str, category: str, allow_uncovered: set[str]) -> bool:
    key = name.lower()
    cat = category.lower()
    return key in allow_uncovered or cat in allow_uncovered or key.split(".", 1)[0] in allow_uncovered


def _severity_for(surface: str, state: str, *, mode: str, required: bool) -> str:
    state_u = state.upper()
    if state_u == NOT_ROUTED:
        return "high"
    if required and state_u in {UNCOVERED, UNSUPPORTED, NOT_ROUTED, PARTIAL}:
        return "critical" if mode == "strict" else "high"
    if state_u in {UNCOVERED, UNSUPPORTED} and surface.startswith("http."):
        return "medium"
    if state_u == PARTIAL:
        return "medium"
    if state_u == OBSERVATIONAL:
        return "info"
    return "medium"


def _gap_reason(surface: CoverageSurface | dict[str, Any]) -> str:
    if isinstance(surface, CoverageSurface):
        name = surface.name
        status = surface.status
        limitations = surface.limitations
    else:
        name = str(surface.get("name") or "")
        status = str(surface.get("status") or "")
        limitations = list(surface.get("limitations") or [])
    if name == "mcp" and status == NOT_ROUTED:
        return "MCP traffic is not routed through Varden"
    if limitations:
        return limitations[0]
    pretty = name.replace(".", " ")
    return f"{pretty} is {status.lower().replace('_', ' ')}"


def _mcp_remediation(surface: CoverageSurface | dict[str, Any]) -> tuple[bool, str | None]:
    if isinstance(surface, CoverageSurface):
        name, status = surface.name, surface.status
        evidence = surface.evidence or {}
    else:
        name = str(surface.get("name") or "")
        status = str(surface.get("status") or "")
        evidence = surface.get("evidence") or {}
    if name != "mcp" or status != NOT_ROUTED:
        return False, None
    paths = evidence.get("paths") if isinstance(evidence, dict) else None
    if isinstance(paths, list) and paths:
        shown = paths[0]
        return True, f"Route MCP through the Varden gateway: `varden mcp wrap {shown}` (write a wrapped copy; do not mutate the original from posture)."
    return True, MCP_REMEDIATION


def _surface_from_dict(data: dict[str, Any]) -> CoverageSurface:
    return CoverageSurface(
        name=str(data.get("name") or ""),
        category=str(data.get("category") or str(data.get("name") or "").split(".", 1)[0]),
        status=str(data.get("status") or UNCOVERED),
        enforcement_mode=str(data.get("enforcement_mode") or "none"),
        interceptor=data.get("interceptor"),
        active=bool(data.get("active")),
        applicable=bool(data.get("applicable", True)),
        limitations=list(data.get("limitations") or []),
        evidence=dict(data.get("evidence") or {}),
        last_verified=data.get("last_verified"),
    )


def _collect_surfaces(attestation: dict[str, Any]) -> list[CoverageSurface]:
    raw = attestation.get("surfaces") or []
    return [_surface_from_dict(s) for s in raw if isinstance(s, dict)]


def _runtime_active(attestation: dict[str, Any], surfaces: list[CoverageSurface]) -> bool:
    if attestation.get("mode_locked"):
        return True
    if any(s.active for s in surfaces):
        return True
    # Gateway-only MCP enforcement without full protect() session lock
    mcp = next((s for s in surfaces if s.name == "mcp"), None)
    if mcp and mcp.active and mcp.status == ENFORCED:
        return True
    return False


def _build_gaps(
    surfaces: list[CoverageSurface],
    *,
    mode: str,
    require_coverage: list[str],
    allow_uncovered: set[str],
) -> list[PostureGap]:
    required_keys = {str(x).strip().lower() for x in require_coverage}
    gaps: list[PostureGap] = []
    for surface in surfaces:
        if not surface.applicable:
            continue
        if surface.status not in _GAP_STATUSES:
            continue
        accepted = _is_accepted(surface.name, surface.category, allow_uncovered)
        required = (
            surface.name.lower() in required_keys
            or surface.category.lower() in required_keys
            or surface.name.lower().split(".", 1)[0] in required_keys
        )
        remediation_available, remediation = _mcp_remediation(surface)
        component = None
        surface_key = surface.category
        if "." in surface.name and surface.category != surface.name:
            component = surface.name.split(".", 1)[1]
            # Prefer category as surface for JSON; keep component for detail
            if surface.name.startswith("http."):
                surface_key = "network" if surface.category == "http" else surface.category
            else:
                surface_key = surface.category
        if surface.name == "mcp":
            surface_key = "mcp"
            component = None
        gaps.append(
            PostureGap(
                surface=surface_key if surface_key != "http" else "network",
                state=surface.status,
                severity=_severity_for(surface.name, surface.status, mode=mode, required=required),
                reason=_gap_reason(surface),
                component=component if surface.name != "mcp" else None,
                remediation_available=remediation_available,
                remediation=remediation,
                accepted_exception=accepted,
            )
        )
    # Deterministic order: severity then surface/component
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    gaps.sort(key=lambda g: (severity_rank.get(g.severity, 9), g.surface, g.component or "", g.reason))
    return gaps


def _category_states(surfaces: list[CoverageSurface]) -> dict[str, dict[str, Any]]:
    by_cat: dict[str, list[CoverageSurface]] = {}
    for s in surfaces:
        if not s.applicable and not (s.name == "mcp" and s.active and s.status == ENFORCED):
            continue
        by_cat.setdefault(s.category, []).append(s)
    out: dict[str, dict[str, Any]] = {}
    for cat in CATEGORY_ORDER:
        items = by_cat.get(cat) or []
        if not items:
            continue
        if cat == "mcp":
            mcp = next((s for s in items if s.name == "mcp"), items[0])
            state = mcp.status
        elif cat == "http":
            primary = [s for s in items if s.name in {"http.requests", "http.httpx", "http.urllib"} and s.active]
            if primary and all(s.status == ENFORCED for s in primary):
                extras = [s for s in items if s.name not in {"http.requests", "http.httpx", "http.urllib"}]
                if extras and any(s.status in {UNCOVERED, UNSUPPORTED, PARTIAL} for s in extras):
                    state = PARTIAL
                else:
                    state = ENFORCED
            else:
                state = _worst_status([s.status for s in items if s.applicable or s.active])
        elif cat == "tools":
            py = next((s for s in items if s.name == "tools.python"), None)
            if py and py.active:
                state = py.status
            else:
                state = _worst_status([s.status for s in items])
        elif cat == "llm":
            active = [s for s in items if s.active or s.applicable]
            if not active:
                continue
            state = _worst_status([s.status for s in active])
        else:
            state = _worst_status([s.status for s in items if s.applicable or s.active])
        key = "network" if cat == "http" else cat
        out[key] = {"state": state.lower()}
    return out


def _readiness_is_routing_only(
    readiness: dict[str, Any],
    surfaces: list[CoverageSurface],
) -> bool:
    """True when readiness failed only because applicable surfaces are NOT_ROUTED."""
    missing = list(readiness.get("required_coverage_missing") or [])
    blocking = list(readiness.get("discovered_blocking") or [])
    if not missing and not blocking:
        return False
    if blocking and not all(str(b.get("state") or "") == NOT_ROUTED for b in blocking):
        return False
    for item in missing:
        key = str(item).strip().lower()
        matches = [
            s
            for s in surfaces
            if s.name == key or s.category == key or s.name.startswith(f"{key}.")
        ]
        if not matches:
            return False
        if not all(s.status == NOT_ROUTED for s in matches):
            return False
    return True


def evaluate_posture(
    registry: CoverageRegistry | None = None,
    *,
    attestation: dict[str, Any] | None = None,
    self_test: str = "not_run",
    attestation_valid: bool | None = None,
) -> PostureReport:
    """Deterministic posture evaluation from coverage + readiness state.

    Prefer ``registry`` (authoritative process-local state). ``attestation`` may
    be supplied for evaluating a previously captured attestation dict (e.g. API).
    """
    notes: list[str] = []
    if attestation is None:
        reg = registry if registry is not None else get_coverage_registry()
        attestation = reg.attestation()
        if attestation_valid is None:
            attestation_valid = True
    elif attestation_valid is None:
        attestation_valid = bool(attestation) and ("surfaces" in attestation or "categories" in attestation)

    surfaces = _collect_surfaces(attestation)
    readiness = dict(attestation.get("strict_readiness") or {})
    mode_raw = attestation.get("mode") or readiness.get("mode") or "observe"
    try:
        mode = normalize_mode(str(mode_raw))
    except ValueError:
        mode = "observe"
        notes.append(f"unrecognized mode {mode_raw!r}; treating as observe")
    fail_mode = str(attestation.get("fail_mode") or readiness.get("fail_mode") or "open")
    allow = {str(x).strip().lower() for x in (attestation.get("accepted_exceptions") or readiness.get("accepted_exceptions") or [])}
    require_coverage: list[str] = []
    if registry is not None:
        require_coverage = list(getattr(registry, "_require_coverage", []) or [])
    elif isinstance(attestation.get("require_coverage"), list):
        require_coverage = list(attestation["require_coverage"])

    active = _runtime_active(attestation, surfaces)
    ready = bool(readiness.get("ready", False)) if readiness else False
    readiness_status = str(readiness.get("status") or ("READY" if ready else "UNKNOWN")).upper()
    if not active:
        verification_readiness = "n/a"
    elif readiness_status.startswith("READY"):
        verification_readiness = "ready"
    elif readiness_status in {"NOT READY", "NOT_READY"}:
        verification_readiness = "not_ready"
    else:
        verification_readiness = readiness_status.lower().replace(" ", "_")

    verification_attestation = "valid" if attestation_valid else "invalid"
    self_test_norm = (self_test or "not_run").strip().lower().replace(" ", "_")

    gaps = _build_gaps(surfaces, mode=mode, require_coverage=require_coverage, allow_uncovered=allow)
    if not active:
        # Catalog defaults are not material gaps when no runtime is active.
        gaps = []
    material_gaps = [g for g in gaps if not g.accepted_exception]
    not_routed = [g for g in material_gaps if g.state.upper() == NOT_ROUTED]
    incomplete = [g for g in material_gaps if g.state.upper() != NOT_ROUTED]

    # --- Result precedence ---
    if not attestation_valid:
        result = NOT_PROTECTED
        notes.append("attestation invalid or unavailable")
    elif not active or not is_enforcing(mode):
        # Observe mode or never-activated runtime: installed ≠ protected.
        result = NOT_PROTECTED
    elif (not ready or verification_readiness == "not_ready") and not _readiness_is_routing_only(
        readiness, surfaces
    ):
        result = NOT_READY
    elif not_routed or _readiness_is_routing_only(readiness, surfaces):
        result = NOT_FULLY_ROUTED
    elif incomplete:
        result = PROTECTED_WITH_GAPS
    else:
        # Conservatively require at least one applicable ENFORCED surface.
        enforced_applicable = [
            s for s in surfaces if s.applicable and s.status in {ENFORCED, "ENFORCED VIA GATEWAY"} and (s.active or s.name == "mcp")
        ]
        if enforced_applicable:
            result = PROTECTED
        else:
            result = NOT_PROTECTED
            notes.append("no applicable enforced surfaces")

    surface_map = _category_states(surfaces) if active else {}

    report = PostureReport(
        schema_version=SCHEMA_VERSION,
        result=result,
        runtime={
            "active": active,
            "mode": mode,
            "fail_mode": fail_mode,
            "readiness": verification_readiness,
        },
        verification={
            "attestation": verification_attestation,
            "readiness": verification_readiness,
            "self_test": self_test_norm,
        },
        surfaces=surface_map,
        gaps=gaps,
        notes=notes,
    )
    return report


def report_posture(
    registry: CoverageRegistry | None = None,
    *,
    self_test: str = "not_run",
) -> PostureReport:
    """Evaluate posture from the process-local coverage registry."""
    return evaluate_posture(registry if registry is not None else get_coverage_registry(), self_test=self_test)
