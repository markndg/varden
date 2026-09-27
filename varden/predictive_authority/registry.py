"""Session registry for AuthorityState instances.

The registry is process-local and bounded. 1.0.0 kept one entry per trace id
forever; the SDK mints a fresh trace id for every action without trace
context, so a long-running control plane grew without limit (~15 KB/session).

Bounds (environment, read when the registry is created):

- ``VARDEN_PA_MAX_SESSIONS`` (default 10000): hard cap on live sessions.
- ``VARDEN_PA_SESSION_IDLE_SECONDS`` (default 86400): sessions idle longer
  than this are dropped.

When the cap is hit, eviction prefers (1) idle-expired sessions, then
(2) sessions that never accumulated authority beyond their initial state,
least recently used first, and only then (3) the least recently used of the
rest. Evicting a session discards its accumulated authority, so its next
action is analysed from a fresh state; evictions are counted in ``stats()``
so operators can size the cap. Durable per-event snapshots in the database
are unaffected.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from typing import Any

from .config import PredictiveAuthorityConfig
from .graph import CapabilityGraph
from .state import AuthorityState
from .budget import AuthorityBudget, budget_from_state


class AuthorityRegistry:
    """Process-local registry keyed by session/trace identity."""

    DEFAULT_MAX_SESSIONS = 10_000
    DEFAULT_IDLE_SECONDS = 86_400.0

    def __init__(self, *, max_sessions: int | None = None, idle_seconds: float | None = None) -> None:
        self._lock = threading.RLock()
        # Insertion/access ordered: first item is least recently used.
        self._states: OrderedDict[str, AuthorityState] = OrderedDict()
        self._budgets: dict[str, AuthorityBudget] = {}
        self._configs: dict[str, PredictiveAuthorityConfig] = {}
        self._last_explanations: dict[str, dict[str, Any]] = {}
        self._event_views: dict[str, list[dict[str, Any]]] = {}
        self._last_access: dict[str, float] = {}
        self.max_sessions = max(1, int(max_sessions if max_sessions is not None else _env_int(
            "VARDEN_PA_MAX_SESSIONS", self.DEFAULT_MAX_SESSIONS)))
        self.idle_seconds = float(idle_seconds if idle_seconds is not None else _env_float(
            "VARDEN_PA_SESSION_IDLE_SECONDS", self.DEFAULT_IDLE_SECONDS))
        self._evictions = {"idle": 0, "no_authority": 0, "lru": 0}

    # -- bounds -----------------------------------------------------------

    def _touch(self, key: str) -> None:
        self._last_access[key] = time.monotonic()
        if key in self._states:
            self._states.move_to_end(key)

    def _drop(self, key: str) -> None:
        self._states.pop(key, None)
        self._budgets.pop(key, None)
        self._configs.pop(key, None)
        self._last_explanations.pop(key, None)
        self._event_views.pop(key, None)
        self._last_access.pop(key, None)

    @staticmethod
    def _has_accumulated_authority(state: AuthorityState) -> bool:
        return bool(
            state.history
            or set(state.capabilities) - set(state.initial_capability_names)
            or state.resources
            or state.irreversible_actions
        )

    def _make_room(self) -> None:
        """Called with the lock held, before inserting one new session."""
        if len(self._states) < self.max_sessions:
            return
        now = time.monotonic()
        # 1. idle-expired
        if self.idle_seconds > 0:
            for key in [k for k in self._states if now - self._last_access.get(k, now) > self.idle_seconds]:
                self._drop(key)
                self._evictions["idle"] += 1
        # Free ~10% at once so eviction scans stay amortised O(1) per insert.
        target = self.max_sessions - max(1, self.max_sessions // 10)
        if len(self._states) <= target:
            return
        # 2. sessions with nothing accumulated, least recently used first
        for key in [k for k, st in self._states.items() if not self._has_accumulated_authority(st)]:
            if len(self._states) <= target:
                return
            self._drop(key)
            self._evictions["no_authority"] += 1
        # 3. plain LRU
        while len(self._states) > target:
            key = next(iter(self._states))
            self._drop(key)
            self._evictions["lru"] += 1

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "sessions": len(self._states),
                "max_sessions": self.max_sessions,
                "idle_seconds": self.idle_seconds,
                "evictions": dict(self._evictions),
            }

    def session_key(self, *, tenant_id: str | None, trace_id: str | None, workflow_id: str | None = None) -> str:
        tenant = str(tenant_id or "default")
        trace = str(trace_id or workflow_id or "default")
        return f"{tenant}:{trace}"

    def get_or_create(
        self,
        key: str,
        config: PredictiveAuthorityConfig,
    ) -> AuthorityState:
        with self._lock:
            state = self._states.get(key)
            if state is None:
                self._make_room()
                state = AuthorityState(
                    session_key=key,
                    graph=CapabilityGraph(max_nodes=config.max_nodes, max_edges=config.max_edges),
                )
                state.mark_initial()
                self._states[key] = state
                self._budgets[key] = budget_from_state(state, config.max_authority_units)
                self._configs[key] = config
            else:
                self._configs[key] = config
            self._touch(key)
            return state

    def get(self, key: str) -> AuthorityState | None:
        return self._states.get(key)

    def budget(self, key: str) -> AuthorityBudget | None:
        return self._budgets.get(key)

    def set_budget(self, key: str, budget: AuthorityBudget) -> None:
        with self._lock:
            if key in self._states:  # never resurrect side-data for an evicted session
                self._budgets[key] = budget

    def remember_explanation(self, key: str, payload: dict[str, Any]) -> None:
        with self._lock:
            if key in self._states:
                self._last_explanations[key] = payload

    def remember_event_view(self, key: str, payload: dict[str, Any], *, max_events: int = 100) -> None:
        with self._lock:
            if key not in self._states:
                return
            rows = self._event_views.setdefault(key, [])
            rows.append(payload)
            if len(rows) > max_events:
                self._event_views[key] = rows[-max_events:]

    def stamp_last_event_id(self, key: str, event_id: int) -> None:
        """Attach durable audit event_id to the most recent in-memory event view."""
        with self._lock:
            rows = self._event_views.get(key) or []
            if rows:
                rows[-1]["event_id"] = int(event_id)

    def event_views(self, key: str) -> list[dict[str, Any]]:
        return list(self._event_views.get(key) or [])

    def config_for(self, key: str) -> PredictiveAuthorityConfig | None:
        return self._configs.get(key)

    def last_explanation(self, key: str) -> dict[str, Any] | None:
        return self._last_explanations.get(key)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._states.clear()
                self._budgets.clear()
                self._configs.clear()
                self._last_explanations.clear()
                self._event_views.clear()
                self._last_access.clear()
            else:
                self._drop(key)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


_REGISTRY = AuthorityRegistry()


# Separate store for the dashboard/CLI demo fixture. Running the demo must
# never touch live enforcement state (1.0.0 reset the live registry).
DEMO_TENANT_ID = "demo"
_DEMO_REGISTRY = AuthorityRegistry(max_sessions=16, idle_seconds=0)


def get_authority_registry() -> AuthorityRegistry:
    return _REGISTRY


def get_demo_registry() -> AuthorityRegistry:
    return _DEMO_REGISTRY


def reset_authority_registry(key: str | None = None) -> None:
    _REGISTRY.reset(key)
