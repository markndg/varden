"""Runtime coverage attestation — honest status of active instrumentation."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

# Status vocabulary (do not invent percentages without a defined denominator).
ENFORCED = "ENFORCED"
PARTIAL = "PARTIAL"
OBSERVATIONAL = "OBSERVATIONAL"
UNCOVERED = "UNCOVERED"
UNSUPPORTED = "UNSUPPORTED"
NOT_ROUTED = "NOT_ROUTED"

VALID_STATUSES = frozenset({ENFORCED, PARTIAL, OBSERVATIONAL, UNCOVERED, UNSUPPORTED, NOT_ROUTED})

# Stale SDK / docs names → catalogue canonical surfaces.
# ``llm.openai`` / ``llm.anthropic`` are transport aliases only — never cognition coverage.
SURFACE_ALIASES: dict[str, str] = {
    "llm.openai": "llm.openai_transport",
    "llm.anthropic": "llm.anthropic_transport",
}


def canonical_surface_name(name: str) -> str:
    """Resolve a coverage surface name (or documented alias) to the catalogue name."""
    key = str(name or "").strip().lower()
    return SURFACE_ALIASES.get(key, key)


@dataclass
class CoverageSurface:
    name: str
    category: str
    status: str
    enforcement_mode: str = "none"
    interceptor: str | None = None
    active: bool = False
    # Installed = patch recorded for this process; verified = last probe passed.
    # Attestation may only report ENFORCED when verified is True (see verify()).
    installed: bool = False
    verified: bool | None = None
    # When False, the surface exists in the catalog but is not relevant to this
    # runtime (e.g. MCP with no discovered config). Posture must not treat
    # NOT_ROUTED on a non-applicable surface as a material gap.
    applicable: bool = True
    limitations: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    last_verified: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Baseline catalog: what Varden *can* cover. Active status is filled by the registry.
_CATALOG: list[dict[str, Any]] = [
    {
        "name": "http.requests",
        "category": "http",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": ["Saved pre-patch Session.request references bypass monkeypatching."],
    },
    {
        "name": "http.httpx",
        "category": "http",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": ["Custom transports / mounts may bypass Client.send wrapping."],
    },
    {
        "name": "http.urllib",
        "category": "http",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": ["urllib.request.urlopen only; lower-level handlers may differ."],
    },
    {
        "name": "http.raw_sockets",
        "category": "http",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": ["socket / ssl sockets are not monkeypatched."],
    },
    {
        "name": "http.aiohttp",
        "category": "http",
        "default_status": UNSUPPORTED,
        "applicable": False,
        "limitations": ["aiohttp is not automatically intercepted."],
    },
    {
        "name": "http.urllib3",
        "category": "http",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": ["Direct urllib3 PoolManager calls bypass requests/httpx patches."],
    },
    {
        "name": "subprocess",
        "category": "subprocess",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": [
            "Saved pre-patch function references bypass monkeypatching.",
            "Native forks from extensions are outside Python hooks.",
        ],
    },
    {
        "name": "filesystem",
        "category": "filesystem",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": [
            "Python filesystem APIs only.",
            "Native extensions / external processes: PARTIAL at best.",
            "OS-global filesystem isolation is NOT GUARANTEED.",
        ],
    },
    {
        "name": "mcp",
        "category": "mcp",
        # NOT_ROUTED is only meaningful once MCP is applicable (discovered /
        # required / gateway-enforced). Default catalog entry is not applicable.
        "default_status": NOT_ROUTED,
        "applicable": False,
        "limitations": ["Direct MCP stdio connections outside the gateway are uncovered."],
    },
    {
        "name": "tools.python",
        "category": "tools",
        "default_status": PARTIAL,
        "applicable": False,
        "limitations": [
            "Python tool dispatch: PARTIAL — requires @varden.tool / guard_tool / register_tool.",
            "Model cognition itself is never covered.",
        ],
    },
    {
        "name": "tools.langchain",
        "category": "tools",
        "default_status": OBSERVATIONAL,
        "applicable": False,
        "limitations": [
            "LangChain tool dispatch: PARTIAL when wrapped; callbacks alone are OBSERVATIONAL.",
        ],
    },
    {
        "name": "llm.openai_transport",
        "category": "llm",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": [
            "OpenAI API transport: covered only when HTTP client patches apply to the SDK transport.",
            "Does not cover model cognition or tool-choice reasoning.",
        ],
    },
    {
        "name": "llm.anthropic_transport",
        "category": "llm",
        "default_status": UNCOVERED,
        "applicable": False,
        "limitations": [
            "Anthropic API transport: covered only when HTTP client patches apply to the SDK transport.",
            "Does not cover model cognition or tool-choice reasoning.",
        ],
    },
    {
        "name": "llm.framework_callbacks",
        "category": "llm",
        "default_status": OBSERVATIONAL,
        "applicable": False,
        "limitations": ["Framework callbacks are observational unless dispatch is wrapped."],
    },
]


def catalogue_surface_names() -> frozenset[str]:
    return frozenset(str(item["name"]) for item in _CATALOG)


# Category → primary surfaces used when ``require_coverage`` lists a category key.
REQUIREMENT_CATEGORY_SURFACES: dict[str, tuple[str, ...]] = {
    "http": ("http.requests", "http.httpx", "http.urllib"),
    "network": ("http.requests", "http.httpx", "http.urllib"),
    "subprocess": ("subprocess",),
    "filesystem": ("filesystem",),
    "tools": ("tools.python",),
    "mcp": ("mcp",),
    "llm": ("llm.openai_transport", "llm.anthropic_transport"),
}


class CoverageRegistry:
    """Process-local registry of *active* instrumentation (not static marketing claims)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._surfaces: dict[str, CoverageSurface] = {}
        self._mode: str = "guarded"
        self._fail_mode: str = "closed"
        self._session_id: str | None = None
        self._attested_at: float | None = None
        self._require_coverage: list[str] = []
        self._allow_uncovered: set[str] = set()
        self._discovered: dict[str, dict[str, Any]] = {}
        self._mode_locked: bool = False
        self._interceptor_checks: dict[str, Any] = {}
        self._interceptor_sealed: set[str] = set()
        self.reset()

    def reset(self, *, release_enforcement_lock: bool = False) -> None:
        """Full process-local teardown after runtime unpatch / session end.

        Clears surfaces, discovery, interceptor checks, *and* the security
        contract (mode, fail mode, session id, require_coverage, exceptions,
        attestation timestamp, mode lock).

        While enforcement mode is locked, ``reset()`` refuses unless
        ``release_enforcement_lock=True`` (used only by ``unpatch_runtime``).
        Callers must not clear the lock while interceptors remain installed.
        """
        with self._lock:
            if self._mode_locked and not release_enforcement_lock:
                raise RuntimeError(
                    "cannot reset coverage registry while enforcement mode is locked; "
                    "call unpatch_runtime() first"
                )
            self._surfaces = {}
            for item in _CATALOG:
                self._surfaces[item["name"]] = CoverageSurface(
                    name=item["name"],
                    category=item["category"],
                    status=item["default_status"],
                    applicable=bool(item.get("applicable", True)),
                    limitations=list(item.get("limitations") or []),
                    active=False,
                    installed=False,
                    verified=None,
                )
            self._allow_uncovered = set()
            self._discovered = {}
            self._mode_locked = False
            self._interceptor_checks = {}
            self._interceptor_sealed = set()
            self._require_coverage = []
            self._mode = "guarded"
            self._fail_mode = "closed"
            self._session_id = None
            self._attested_at = None

    def set_session(
        self,
        *,
        mode: str,
        fail_mode: str,
        session_id: str | None = None,
        require_coverage: list[str] | None = None,
        allow_uncovered: list[str] | None = None,
        lock_mode: bool = False,
    ) -> None:
        with self._lock:
            require = list(require_coverage or [])
            allow = {str(x).strip().lower() for x in (allow_uncovered or [])}
            if self._mode_locked:
                # Locked contract is immutable: mode, fail_mode, coverage requirements
                # and accepted exceptions cannot change (including silent expansion of
                # allow_uncovered). Identical re-entry is a no-op.
                if (
                    mode != self._mode
                    or fail_mode != self._fail_mode
                    or require != self._require_coverage
                    or allow != self._allow_uncovered
                ):
                    raise RuntimeError(
                        f"security mode locked after activation ({self._mode}/{self._fail_mode}); "
                        "silent downgrade refused"
                    )
                if session_id is not None:
                    self._session_id = session_id
                return
            self._mode = mode
            self._fail_mode = fail_mode
            self._session_id = session_id
            self._require_coverage = require
            self._allow_uncovered = allow
            if lock_mode:
                self._mode_locked = True
            self._apply_requirement_applicability()

    def enforcement_contract(self) -> dict[str, Any]:
        """Authoritative process-local enforcement configuration.

        When ``mode_locked`` is true this is the single source of truth for
        interceptor enforce/observe decisions (not mutable guard attributes).
        """
        with self._lock:
            return {
                "mode": self._mode,
                "fail_mode": self._fail_mode,
                "mode_locked": self._mode_locked,
                "require_coverage": list(self._require_coverage),
                "allow_uncovered": sorted(self._allow_uncovered),
                "session_id": self._session_id,
            }
    def _apply_requirement_applicability(self) -> None:
        """Surfaces explicitly required by the coverage contract become applicable."""
        primary_for_category = REQUIREMENT_CATEGORY_SURFACES
        for item in self._require_coverage:
            key = canonical_surface_name(item)
            if key in primary_for_category:
                for name in primary_for_category[key]:
                    surface = self._surfaces.get(name)
                    if surface is not None:
                        surface.applicable = True
                continue
            for surface in self._surfaces.values():
                if surface.name == key:
                    surface.applicable = True

    def register_interceptor_check(self, name: str, checker: Any) -> None:
        """Register a callable that returns True if the interceptor is still active.

        After mode lock, sealed probes cannot be replaced (prevents false ENFORCED
        attestation via poisoned always-true checkers). Prefer
        ``install_interceptor`` from patch install paths.
        """
        key = canonical_surface_name(name)
        with self._lock:
            if self._mode_locked and key in self._interceptor_sealed:
                raise RuntimeError(
                    f"cannot replace sealed interceptor probe for {key!r} while "
                    "enforcement mode is locked"
                )
            self._interceptor_checks[key] = checker
            if self._mode_locked:
                self._interceptor_sealed.add(key)

    def install_interceptor(
        self,
        name: str,
        *,
        checker: Any,
        interceptor: str | None = None,
        limitations: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        status: str = ENFORCED,
    ) -> CoverageSurface:
        """Record an installed interceptor + sealed probe (patch_runtime path).

        This is the only supported way to claim ENFORCED after mode lock: the
        probe must pass at install time. Subsequent attestation/verify cannot
        retain ENFORCED if the probe fails.
        """
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid coverage status: {status}")
        key = canonical_surface_name(name)
        try:
            ok = bool(checker())
        except Exception:
            ok = False
        if status == ENFORCED and not ok:
            raise RuntimeError(
                f"cannot install ENFORCED interceptor for {key!r}: live probe failed"
            )
        with self._lock:
            if self._mode_locked and key in self._interceptor_sealed:
                # Same-contract re-entry: refresh probe only while still live.
                if not ok:
                    raise RuntimeError(
                        f"cannot refresh sealed interceptor for {key!r}: probe failed"
                    )
            self._interceptor_checks[key] = checker
            self._interceptor_sealed.add(key)
            return self._mark_unlocked(
                key,
                status=status,
                interceptor=interceptor,
                active=ok,
                installed=True,
                verified=ok,
                limitations=limitations,
                evidence=evidence,
                applicable=True,
                enforcement_mode="enforced" if status == ENFORCED else None,
            )

    def discover(self, name: str, *, detail: dict[str, Any] | None = None) -> None:
        """Record a discovered relevant surface (e.g. MCP config present)."""
        with self._lock:
            self._discovered[name] = {"name": name, "detail": detail or {}, "at": time.time()}
            surface = self._surfaces.get(name)
            if surface is not None:
                surface.applicable = True

    def _mark_unlocked(
        self,
        resolved: str,
        *,
        status: str,
        interceptor: str | None = None,
        active: bool = True,
        installed: bool | None = None,
        verified: bool | None = None,
        limitations: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        enforcement_mode: str | None = None,
        applicable: bool | None = None,
    ) -> CoverageSurface:
        surface = self._surfaces.get(resolved)
        if surface is None:
            category = resolved.split(".", 1)[0]
            surface = CoverageSurface(name=resolved, category=category, status=status)
            self._surfaces[resolved] = surface
        surface.status = status
        surface.active = active
        if installed is not None:
            surface.installed = bool(installed)
        if verified is not None:
            surface.verified = verified
        surface.interceptor = interceptor or surface.interceptor
        surface.enforcement_mode = enforcement_mode or ("enforced" if status == ENFORCED else status.lower())
        if applicable is not None:
            surface.applicable = bool(applicable)
        if limitations is not None:
            surface.limitations = list(limitations)
        if evidence:
            surface.evidence = {**(surface.evidence or {}), **evidence}
        if verified is True:
            surface.last_verified = time.time()
        return surface

    def mark(
        self,
        name: str,
        *,
        status: str,
        interceptor: str | None = None,
        active: bool = True,
        limitations: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        enforcement_mode: str | None = None,
        applicable: bool | None = None,
        installed: bool | None = None,
        verified: bool | None = None,
    ) -> CoverageSurface:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid coverage status: {status}")
        resolved = canonical_surface_name(name)
        with self._lock:
            existing = self._surfaces.get(resolved)
            if self._mode_locked and status == ENFORCED:
                # Locked sessions cannot mint false ENFORCED via mark(): require a
                # sealed live probe (install_interceptor). Downgrades remain OK.
                checker = self._interceptor_checks.get(resolved)
                ok = False
                if checker is not None:
                    try:
                        ok = bool(checker())
                    except Exception:
                        ok = False
                if not ok:
                    raise RuntimeError(
                        f"cannot mark {resolved!r} ENFORCED while mode is locked without "
                        "a live sealed interceptor probe; use install_interceptor()"
                    )
                return self._mark_unlocked(
                    resolved,
                    status=ENFORCED,
                    interceptor=interceptor,
                    active=True,
                    installed=True if installed is None else installed,
                    verified=True,
                    limitations=limitations,
                    evidence=evidence,
                    enforcement_mode=enforcement_mode or "enforced",
                    applicable=applicable if applicable is not None else True,
                )
            return self._mark_unlocked(
                resolved,
                status=status,
                interceptor=interceptor,
                active=active,
                installed=installed
                if installed is not None
                else (True if status == ENFORCED else (existing.installed if existing else False)),
                verified=verified
                if verified is not None
                else (True if status == ENFORCED else (existing.verified if existing else None)),
                limitations=limitations,
                evidence=evidence,
                enforcement_mode=enforcement_mode,
                applicable=applicable,
            )

    def verify(self) -> dict[str, Any]:
        """Live-check whether registered interceptors still wrap their targets.

        If an interceptor was removed, downgrade that surface from ENFORCED.
        Attestation and readiness must call this before reporting ENFORCED.
        """
        changes: list[dict[str, Any]] = []
        with self._lock:
            checks = dict(self._interceptor_checks)
        for name, checker in checks.items():
            try:
                ok = bool(checker())
            except Exception:
                ok = False
            surface = self.get(name)
            if surface and surface.status == ENFORCED and not ok:
                with self._lock:
                    self._mark_unlocked(
                        canonical_surface_name(name),
                        status=UNCOVERED,
                        active=False,
                        installed=True,
                        verified=False,
                        interceptor=surface.interceptor,
                        limitations=list(surface.limitations)
                        + ["Interceptor tamper detected — wrapper no longer installed."],
                        evidence={**(surface.evidence or {}), "tamper_detected": True},
                    )
                changes.append({"surface": name, "from": ENFORCED, "to": UNCOVERED, "reason": "tamper"})
            elif surface and ok and surface.status == ENFORCED:
                with self._lock:
                    surface.verified = True
                    surface.installed = True
                    surface.active = True
                    surface.last_verified = time.time()
            elif surface and not ok and surface.installed:
                with self._lock:
                    surface.verified = False
                    surface.active = False
                    if surface.status == ENFORCED:
                        surface.status = UNCOVERED
        return {"verified_at": time.time(), "changes": changes, "ok": not changes}

    def get(self, name: str) -> CoverageSurface | None:
        with self._lock:
            return self._surfaces.get(canonical_surface_name(name))

    def list_surfaces(self) -> list[CoverageSurface]:
        with self._lock:
            return [self._surfaces[k] for k in sorted(self._surfaces)]

    def by_category(self) -> dict[str, list[CoverageSurface]]:
        out: dict[str, list[CoverageSurface]] = {}
        for s in self.list_surfaces():
            out.setdefault(s.category, []).append(s)
        return out

    def category_rollup(self) -> list[dict[str, Any]]:
        """Roll surfaces into product-facing category rows (no vanity score)."""
        order = ["http", "subprocess", "filesystem", "mcp", "tools", "llm"]
        labels = {
            "http": "Network",
            "subprocess": "Subprocess",
            "filesystem": "Filesystem",
            "mcp": "MCP",
            "tools": "Tools",
            "llm": "LLM",
        }
        by_cat = self.by_category()
        rows = []
        for cat in order:
            surfaces = by_cat.get(cat) or []
            if not surfaces:
                continue
            status = _worst_status([s.status for s in surfaces])
            if cat == "mcp":
                mcp = next((s for s in surfaces if s.name == "mcp"), None)
                if mcp and not mcp.applicable and not (mcp.active and mcp.status == ENFORCED):
                    continue  # omit non-applicable MCP from rollup
                if mcp and mcp.status == ENFORCED:
                    status = "ENFORCED VIA GATEWAY"
                elif mcp:
                    status = mcp.status
            if cat == "tools":
                py = next((s for s in surfaces if s.name == "tools.python"), None)
                if py and py.active and py.status in {ENFORCED, PARTIAL}:
                    status = py.status
            if cat == "http":
                primary = [s for s in surfaces if s.name in {"http.requests", "http.httpx"} and s.active]
                if primary and all(s.status == ENFORCED for s in primary):
                    extras = [s for s in surfaces if s.name not in {"http.requests", "http.httpx"}]
                    if extras and any(s.status in {UNCOVERED, UNSUPPORTED} for s in extras):
                        status = PARTIAL
                    else:
                        status = ENFORCED
                elif any(s.active and s.status == ENFORCED for s in surfaces if s.name in {"http.requests", "http.httpx", "http.urllib"}):
                    status = PARTIAL if any(s.status in {UNCOVERED, UNSUPPORTED} for s in surfaces) else ENFORCED
            if cat == "llm":
                # Model API transport vs callbacks — never claim "model cognition covered".
                transports = [
                    s
                    for s in surfaces
                    if s.name in {"llm.openai_transport", "llm.anthropic_transport"}
                    and s.active
                ]
                if transports and all(s.status == ENFORCED for s in transports):
                    status = PARTIAL  # transport only — not cognition
                elif any(s.status == OBSERVATIONAL for s in surfaces):
                    status = OBSERVATIONAL
            limitations: list[str] = []
            for s in surfaces:
                for lim in s.limitations:
                    if lim not in limitations:
                        limitations.append(lim)
            rows.append(
                {
                    "category": cat,
                    "label": labels.get(cat, cat.upper()),
                    "status": status,
                    "surfaces": [s.to_dict() for s in surfaces],
                    "limitations": limitations,
                    "active_count": sum(1 for s in surfaces if s.active),
                }
            )
        return rows

    def missing_required(self, require: list[str] | None = None) -> list[str]:
        """Surfaces listed in ``require_coverage`` that are not actively ENFORCED.

        ``PARTIAL``, ``OBSERVATIONAL``, ``NOT_ROUTED``, ``UNCOVERED``, and
        ``UNSUPPORTED`` never satisfy an explicit requirement. Operators who
        intentionally accept incomplete coverage must list the surface (or its
        category) in ``allow_uncovered`` — those appear as accepted exceptions,
        never as ENFORCED.
        """
        needed = list(require if require is not None else self._require_coverage)
        missing = []
        with self._lock:
            for item in needed:
                key = canonical_surface_name(item)
                if key in self._allow_uncovered or key.split(".", 1)[0] in self._allow_uncovered:
                    continue
                if key in REQUIREMENT_CATEGORY_SURFACES:
                    names = REQUIREMENT_CATEGORY_SURFACES[key]
                    ok = any(
                        (surf := self._surfaces.get(name)) is not None
                        and surf.status == ENFORCED
                        and surf.active
                        and (not self._mode_locked or surf.verified is True)
                        for name in names
                    )
                else:
                    surf = self._surfaces.get(key)
                    ok = bool(
                        surf is not None
                        and surf.status == ENFORCED
                        and surf.active
                        and (not self._mode_locked or surf.verified is True)
                    )
                if not ok:
                    missing.append(item)
        return missing

    def discovered_blocking(self) -> list[dict[str, Any]]:
        """Discovered relevant surfaces that remain unenforced without exception."""
        blocking = []
        with self._lock:
            for name, info in self._discovered.items():
                key = name.lower()
                if key in self._allow_uncovered or key.split(".", 1)[0] in self._allow_uncovered:
                    continue
                surface = self._surfaces.get(name) or self._surfaces.get(key)
                status = surface.status if surface else NOT_ROUTED
                if status in {ENFORCED} or (status == "ENFORCED VIA GATEWAY"):
                    continue
                if name == "mcp" and surface and surface.status == ENFORCED and surface.active:
                    continue
                blocking.append(
                    {
                        "surface": name,
                        "state": status if surface else NOT_ROUTED,
                        "reason": (info.get("detail") or {}).get("reason")
                        or f"discovered but {status if surface else NOT_ROUTED}",
                        "detail": info.get("detail") or {},
                    }
                )
        return blocking

    def strict_readiness(self, require: list[str] | None = None) -> dict[str, Any]:
        missing = self.missing_required(require)
        blocking = self.discovered_blocking()
        ready = not missing and not blocking
        accepted = sorted(self._allow_uncovered)
        if ready and accepted:
            status = "READY WITH EXCEPTIONS"
        elif ready:
            status = "READY"
        else:
            status = "NOT READY"
        return {
            "ready": ready,
            "status": status,
            "required_coverage_missing": missing,
            "discovered_blocking": blocking,
            "accepted_exceptions": accepted,
            "mode": self._mode,
            "fail_mode": self._fail_mode,
            "mode_locked": self._mode_locked,
        }

    def strict_readiness_report(self) -> dict[str, Any]:
        self.verify()
        ready = self.strict_readiness()
        surfaces = []
        for s in self.list_surfaces():
            surfaces.append(
                {
                    "name": s.name,
                    "status": s.status,
                    "accepted_exception": s.name in self._allow_uncovered
                    or s.category in self._allow_uncovered
                    or s.name.split(".", 1)[0] in self._allow_uncovered,
                    "limitations": s.limitations,
                }
            )
        return {**ready, "surfaces": surfaces, "discovered": list(self._discovered.values())}

    def attestation(self) -> dict[str, Any]:
        self.verify()
        with self._lock:
            self._attested_at = time.time()
            return {
                "session_id": self._session_id,
                "mode": self._mode,
                "fail_mode": self._fail_mode,
                "mode_locked": self._mode_locked,
                "attested_at": self._attested_at,
                "surfaces": [s.to_dict() for s in self.list_surfaces()],
                "categories": self.category_rollup(),
                "strict_readiness": self.strict_readiness(),
                "require_coverage": list(self._require_coverage),
                "accepted_exceptions": sorted(self._allow_uncovered),
                "discovered": list(self._discovered.values()),
                "known_bypass_surfaces": [
                    s.to_dict()
                    for s in self.list_surfaces()
                    if s.applicable
                    and s.status in {UNCOVERED, UNSUPPORTED, NOT_ROUTED, OBSERVATIONAL, PARTIAL}
                ],
            }

    def startup_log_lines(self) -> list[str]:
        rows = self.category_rollup()
        overall = _worst_status([r["status"] for r in rows if r["status"] in VALID_STATUSES] or [PARTIAL])
        if any(r["status"] == "ENFORCED VIA GATEWAY" for r in rows):
            pass
        lines = [f"Varden protection active — {overall} COVERAGE", ""]
        buckets: dict[str, list[str]] = {
            "Enforced": [],
            "Partial": [],
            "Not routed": [],
            "Uncovered": [],
            "Observational": [],
        }
        for s in self.list_surfaces():
            label = s.name
            if s.status == ENFORCED:
                buckets["Enforced"].append(label)
            elif s.status == PARTIAL:
                buckets["Partial"].append(label)
            elif s.status == NOT_ROUTED:
                buckets["Not routed"].append(label)
            elif s.status in {UNCOVERED, UNSUPPORTED}:
                buckets["Uncovered"].append(label)
            elif s.status == OBSERVATIONAL:
                buckets["Observational"].append(label)
        for title, items in buckets.items():
            if not items:
                continue
            lines.append(f"{title}:")
            for item in items:
                lines.append(f"- {item}")
            lines.append("")
        lines.append(f"Mode: {self._mode.upper()}")
        lines.append(f"Fail mode: {self._fail_mode.upper()}")
        if self._allow_uncovered:
            lines.append("Accepted exceptions: " + ", ".join(sorted(self._allow_uncovered)))
        return lines


def _worst_status(statuses: list[str]) -> str:
    rank = {
        UNSUPPORTED: 0,
        UNCOVERED: 1,
        NOT_ROUTED: 2,
        OBSERVATIONAL: 3,
        PARTIAL: 4,
        ENFORCED: 5,
    }
    if not statuses:
        return UNCOVERED
    return min(statuses, key=lambda s: rank.get(s, 1))


# Process singleton used by protect() / patches.
_REGISTRY = CoverageRegistry()


def get_coverage_registry() -> CoverageRegistry:
    return _REGISTRY


def format_startup_attestation(registry: CoverageRegistry | None = None) -> str:
    reg = registry or _REGISTRY
    return "\n".join(reg.startup_log_lines())
