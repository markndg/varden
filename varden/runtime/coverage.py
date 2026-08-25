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


@dataclass
class CoverageSurface:
    name: str
    category: str
    status: str
    enforcement_mode: str = "none"
    interceptor: str | None = None
    active: bool = False
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
        "limitations": ["Saved pre-patch Session.request references bypass monkeypatching."],
    },
    {
        "name": "http.httpx",
        "category": "http",
        "default_status": UNCOVERED,
        "limitations": ["Custom transports / mounts may bypass Client.send wrapping."],
    },
    {
        "name": "http.urllib",
        "category": "http",
        "default_status": UNCOVERED,
        "limitations": ["urllib.request.urlopen only; lower-level handlers may differ."],
    },
    {
        "name": "http.raw_sockets",
        "category": "http",
        "default_status": UNCOVERED,
        "limitations": ["socket / ssl sockets are not monkeypatched."],
    },
    {
        "name": "http.aiohttp",
        "category": "http",
        "default_status": UNSUPPORTED,
        "limitations": ["aiohttp is not automatically intercepted."],
    },
    {
        "name": "http.urllib3",
        "category": "http",
        "default_status": UNCOVERED,
        "limitations": ["Direct urllib3 PoolManager calls bypass requests/httpx patches."],
    },
    {
        "name": "subprocess",
        "category": "subprocess",
        "default_status": UNCOVERED,
        "limitations": [
            "Saved pre-patch function references bypass monkeypatching.",
            "Native forks from extensions are outside Python hooks.",
        ],
    },
    {
        "name": "filesystem",
        "category": "filesystem",
        "default_status": UNCOVERED,
        "limitations": [
            "Python filesystem APIs only.",
            "Native extensions / external processes: PARTIAL at best.",
            "OS-global filesystem isolation is NOT GUARANTEED.",
        ],
    },
    {
        "name": "mcp",
        "category": "mcp",
        "default_status": NOT_ROUTED,
        "limitations": ["Direct MCP stdio connections outside the gateway are uncovered."],
    },
    {
        "name": "tools.python",
        "category": "tools",
        "default_status": PARTIAL,
        "limitations": [
            "Python tool dispatch: PARTIAL — requires @varden.tool / guard_tool / register_tool.",
            "Model cognition itself is never covered.",
        ],
    },
    {
        "name": "tools.langchain",
        "category": "tools",
        "default_status": OBSERVATIONAL,
        "limitations": [
            "LangChain tool dispatch: PARTIAL when wrapped; callbacks alone are OBSERVATIONAL.",
        ],
    },
    {
        "name": "llm.openai_transport",
        "category": "llm",
        "default_status": UNCOVERED,
        "limitations": [
            "OpenAI API transport: covered only when HTTP client patches apply to the SDK transport.",
            "Does not cover model cognition or tool-choice reasoning.",
        ],
    },
    {
        "name": "llm.anthropic_transport",
        "category": "llm",
        "default_status": UNCOVERED,
        "limitations": [
            "Anthropic API transport: covered only when HTTP client patches apply to the SDK transport.",
            "Does not cover model cognition or tool-choice reasoning.",
        ],
    },
    {
        "name": "llm.framework_callbacks",
        "category": "llm",
        "default_status": OBSERVATIONAL,
        "limitations": ["Framework callbacks are observational unless dispatch is wrapped."],
    },
]


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
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._surfaces = {}
            for item in _CATALOG:
                self._surfaces[item["name"]] = CoverageSurface(
                    name=item["name"],
                    category=item["category"],
                    status=item["default_status"],
                    limitations=list(item.get("limitations") or []),
                    active=False,
                )
            self._allow_uncovered = set()
            self._discovered = {}
            self._mode_locked = False
            self._interceptor_checks = {}

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
            if self._mode_locked and (mode != self._mode or fail_mode != self._fail_mode):
                raise RuntimeError(
                    f"security mode locked after activation ({self._mode}/{self._fail_mode}); "
                    "silent downgrade refused"
                )
            self._mode = mode
            self._fail_mode = fail_mode
            self._session_id = session_id
            self._require_coverage = list(require_coverage or [])
            self._allow_uncovered = {str(x).strip().lower() for x in (allow_uncovered or [])}
            if lock_mode or mode == "strict":
                self._mode_locked = True

    def register_interceptor_check(self, name: str, checker: Any) -> None:
        """Register a callable that returns True if the interceptor is still active."""
        with self._lock:
            self._interceptor_checks[name] = checker

    def discover(self, name: str, *, detail: dict[str, Any] | None = None) -> None:
        """Record a discovered relevant surface (e.g. MCP config present)."""
        with self._lock:
            self._discovered[name] = {"name": name, "detail": detail or {}, "at": time.time()}

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
    ) -> CoverageSurface:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid coverage status: {status}")
        with self._lock:
            surface = self._surfaces.get(name)
            if surface is None:
                category = name.split(".", 1)[0]
                surface = CoverageSurface(name=name, category=category, status=status)
                self._surfaces[name] = surface
            surface.status = status
            surface.active = active
            surface.interceptor = interceptor or surface.interceptor
            surface.enforcement_mode = enforcement_mode or ("enforced" if status == ENFORCED else status.lower())
            if limitations is not None:
                surface.limitations = list(limitations)
            if evidence:
                surface.evidence = {**(surface.evidence or {}), **evidence}
            surface.last_verified = time.time()
            return surface

    def verify(self) -> dict[str, Any]:
        """Live-check whether registered interceptors still wrap their targets.

        If an interceptor was removed, downgrade that surface from ENFORCED.
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
                self.mark(
                    name,
                    status=UNCOVERED,
                    active=False,
                    interceptor=surface.interceptor,
                    limitations=list(surface.limitations) + ["Interceptor tamper detected — wrapper no longer installed."],
                    evidence={"tamper_detected": True},
                )
                changes.append({"surface": name, "from": ENFORCED, "to": UNCOVERED, "reason": "tamper"})
            elif surface and ok and surface.status == ENFORCED:
                surface.last_verified = time.time()
        return {"verified_at": time.time(), "changes": changes, "ok": not changes}

    def get(self, name: str) -> CoverageSurface | None:
        with self._lock:
            return self._surfaces.get(name)

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
                    if s.name in {"llm.openai_transport", "llm.anthropic_transport", "llm.openai", "llm.anthropic"}
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
        needed = list(require if require is not None else self._require_coverage)
        missing = []
        with self._lock:
            for item in needed:
                key = item.strip().lower()
                if key in self._allow_uncovered or key.split(".", 1)[0] in self._allow_uncovered:
                    continue
                matches = [
                    s
                    for s in self._surfaces.values()
                    if s.name == key or s.category == key or s.name.startswith(f"{key}.")
                ]
                if not matches:
                    missing.append(item)
                    continue
                ok = any(s.status in {ENFORCED, PARTIAL} and s.active for s in matches)
                if key == "mcp":
                    ok = any(s.name == "mcp" and s.status == ENFORCED and s.active for s in matches)
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
                "accepted_exceptions": sorted(self._allow_uncovered),
                "discovered": list(self._discovered.values()),
                "known_bypass_surfaces": [
                    s.to_dict()
                    for s in self.list_surfaces()
                    if s.status in {UNCOVERED, UNSUPPORTED, NOT_ROUTED, OBSERVATIONAL}
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
