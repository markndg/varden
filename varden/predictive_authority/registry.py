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
rest.

Evicting a session that had accumulated authority records a bounded
tombstone for that session key. Recreating the same key marks the new
``AuthorityState.continuity_broken`` so enforce mode can fail-safe rather
than treating monitoring-state loss as a clean slate. Tombstones themselves
are capped (``2 * max_sessions``) to keep memory bounded.

**Impossibility:** with only bounded process-local state, forgetting a
tombstone means a reintroduced session key cannot be distinguished from a
genuinely new session. Therefore any tombstone-table drop sets
``continuity_degraded`` (also persisted when a ``ContinuityStore`` is bound)
and enforce mode must fail-safe for the remainder of the process lifetime
(until explicit ``reset()``), rather than silently restoring trust.

When bound to the control-plane SQLite database via ``attach_continuity_store``,
tombstones and ``had_authority`` markers survive process restart, and worker
leases detect multiple OS processes sharing the same DB even when worker-count
env vars are unset. Durable per-event snapshots remain separate (audit / UI)
and are not reloaded as live graphs.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from typing import Any, TYPE_CHECKING

from .config import PredictiveAuthorityConfig
from .graph import CapabilityGraph
from .state import AuthorityState
from .budget import AuthorityBudget, budget_from_state

if TYPE_CHECKING:
    from .continuity_store import ContinuityStore


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
        # Session keys whose accumulated authority was discarded. Recreate →
        # continuity_broken. OrderedDict keeps insertion order for LRU trim.
        self._authority_tombstones: OrderedDict[str, str] = OrderedDict()
        self.max_sessions = max(1, int(max_sessions if max_sessions is not None else _env_int(
            "VARDEN_PA_MAX_SESSIONS", self.DEFAULT_MAX_SESSIONS)))
        self.idle_seconds = float(idle_seconds if idle_seconds is not None else _env_float(
            "VARDEN_PA_SESSION_IDLE_SECONDS", self.DEFAULT_IDLE_SECONDS))
        self._evictions = {"idle": 0, "no_authority": 0, "lru": 0}
        self._tombstone_drops = 0
        # Once any tombstone is forgotten under the cap, this process can no
        # longer prove that a reintroduced session key is genuinely new.
        self._continuity_degraded = False
        self._continuity_degraded_reason: str | None = None
        self._continuity_store: ContinuityStore | None = None

    def attach_continuity_store(self, store: ContinuityStore | None) -> None:
        """Bind durable continuity signals (tombstones / leases / restart).

        Attach never raises into callers: a broken / read-only / missing store
        still binds the handle when provided, but marks the process
        ``continuity_degraded`` so enforce cannot treat unknown continuity as
        a clean authority graph.
        """
        with self._lock:
            self._continuity_store = store
            if store is None:
                return
            try:
                store.probe()
                if store.continuity_degraded():
                    self._continuity_degraded = True
                    self._continuity_degraded_reason = (
                        store.get_meta("continuity_degraded_reason") or "TOMBSTONE_HISTORY_INCOMPLETE"
                    )
            except Exception:
                self._continuity_degraded = True
                if not self._continuity_degraded_reason:
                    self._continuity_degraded_reason = "CONTINUITY_STORE_ATTACH_FAILED"

    def continuity_store(self) -> ContinuityStore | None:
        with self._lock:
            return self._continuity_store

    def mark_continuity_degraded(self, reason: str) -> None:
        """Process-local degrade (used when bind/init fails before attach)."""
        with self._lock:
            self._continuity_degraded = True
            self._continuity_degraded_reason = reason

    def active_worker_count(self) -> int | None:
        """Active leases on the bound DB, or None when continuity store unbound.

        When the store is bound but lease renew/count fails, this degrades the
        process and returns ``2`` so topology checks cannot race into a
        temporary single-worker allow. Unknown continuity is never treated as
        verified single-worker completeness.
        """
        store = self.continuity_store()
        if store is None:
            return None
        try:
            return store.touch_lease_and_count()
        except Exception:
            with self._lock:
                self._continuity_degraded = True
                self._continuity_degraded_reason = "CONTINUITY_STORE_LEASE_FAILED"
            # Conservative: force multi-worker unsupported path in deployment.
            return 2

    # -- bounds -----------------------------------------------------------

    def _tombstone_cap(self) -> int:
        return max(2, self.max_sessions * 2)

    def _record_authority_tombstone(self, key: str, reason: str) -> None:
        """Remember that ``key`` lost accumulated authority (lock held)."""
        self._authority_tombstones.pop(key, None)
        self._authority_tombstones[key] = reason
        store = self._continuity_store
        if store is not None:
            try:
                store.record_tombstone(key, reason)
            except Exception:
                # Durable write failure → degrade; never silently forget.
                self._continuity_degraded = True
                self._continuity_degraded_reason = "CONTINUITY_STORE_WRITE_FAILED"
        while len(self._authority_tombstones) > self._tombstone_cap():
            self._authority_tombstones.popitem(last=False)
            self._tombstone_drops += 1
            self._continuity_degraded = True
            self._continuity_degraded_reason = "TOMBSTONE_HISTORY_INCOMPLETE"
            if store is not None:
                try:
                    store.set_continuity_degraded("TOMBSTONE_HISTORY_INCOMPLETE")
                except Exception:
                    pass

    def note_accumulated_authority(self, key: str, state: AuthorityState) -> None:
        """Persist that live session ``key`` holds security-relevant authority."""
        if not self._has_accumulated_authority(state):
            return
        store = self.continuity_store()
        if store is None:
            return
        try:
            store.record_authority(key)
        except Exception:
            with self._lock:
                self._continuity_degraded = True
                self._continuity_degraded_reason = "CONTINUITY_STORE_WRITE_FAILED"

    def continuity_degraded(self) -> bool:
        with self._lock:
            if self._continuity_degraded:
                return True
        store = self.continuity_store()
        if store is not None:
            try:
                if store.continuity_degraded():
                    with self._lock:
                        self._continuity_degraded = True
                        self._continuity_degraded_reason = (
                            store.get_meta("continuity_degraded_reason") or "TOMBSTONE_HISTORY_INCOMPLETE"
                        )
                    return True
            except Exception:
                return True
        return False

    def continuity_status(self) -> dict[str, Any]:
        degraded = self.continuity_degraded()
        with self._lock:
            store = self._continuity_store
            status = {
                "continuity_degraded": degraded,
                "continuity_degraded_reason": self._continuity_degraded_reason,
                "authority_tombstones": len(self._authority_tombstones),
                "tombstone_drops": self._tombstone_drops,
                "tombstone_cap": self._tombstone_cap(),
                # Durable fail-safes are not full graph replay / verified continuity.
                "cross_restart_continuity_verified": False,
                "continuity_scope": (
                    "process_lifetime_plus_durable_failsafe" if store else "process_lifetime_only"
                ),
                "durable_store_bound": store is not None,
            }
        if store is not None:
            try:
                status["active_workers"] = store.active_worker_count()
                status["worker_id"] = store.worker_id
            except Exception:
                status["active_workers"] = None
                status["lease_query_failed"] = True
                with self._lock:
                    self._continuity_degraded = True
                    if not self._continuity_degraded_reason:
                        self._continuity_degraded_reason = "CONTINUITY_STORE_LEASE_FAILED"
                status["continuity_degraded"] = True
                status["continuity_degraded_reason"] = self._continuity_degraded_reason
        return status

    def _touch(self, key: str) -> None:
        self._last_access[key] = time.monotonic()
        if key in self._states:
            self._states.move_to_end(key)

    def _drop(self, key: str, *, reason: str = "evicted") -> None:
        state = self._states.get(key)
        if state is not None and self._has_accumulated_authority(state):
            self._record_authority_tombstone(key, reason)
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
            or state.provenance_refs
            or state.delegated_authority
        )

    def _make_room(self) -> None:
        """Called with the lock held, before inserting one new session."""
        if len(self._states) < self.max_sessions:
            return
        now = time.monotonic()
        # 1. idle-expired
        if self.idle_seconds > 0:
            for key in [k for k in self._states if now - self._last_access.get(k, now) > self.idle_seconds]:
                self._drop(key, reason="idle")
                self._evictions["idle"] += 1
        # Free ~10% at once so eviction scans stay amortised O(1) per insert.
        target = self.max_sessions - max(1, self.max_sessions // 10)
        if len(self._states) <= target:
            return
        # 2. sessions with nothing accumulated, least recently used first
        for key in [k for k, st in self._states.items() if not self._has_accumulated_authority(st)]:
            if len(self._states) <= target:
                return
            self._drop(key, reason="no_authority")
            self._evictions["no_authority"] += 1
        # 3. plain LRU
        while len(self._states) > target:
            key = next(iter(self._states))
            self._drop(key, reason="lru")
            self._evictions["lru"] += 1

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "sessions": len(self._states),
                "max_sessions": self.max_sessions,
                "idle_seconds": self.idle_seconds,
                "evictions": dict(self._evictions),
                "authority_tombstones": len(self._authority_tombstones),
                "tombstone_drops": self._tombstone_drops,
                "continuity_degraded": self._continuity_degraded,
                "continuity_degraded_reason": self._continuity_degraded_reason,
                "cross_restart_continuity_verified": False,
                "continuity_scope": (
                    "process_lifetime_plus_durable_failsafe"
                    if self._continuity_store is not None
                    else "process_lifetime_only"
                ),
                "durable_store_bound": self._continuity_store is not None,
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
            store = self._continuity_store
            if store is not None:
                try:
                    store.touch_lease_and_count()
                except Exception:
                    self._continuity_degraded = True
                    self._continuity_degraded_reason = "CONTINUITY_STORE_WRITE_FAILED"
            state = self._states.get(key)
            if state is None:
                self._make_room()
                tombstone_reason = self._authority_tombstones.pop(key, None)
                durable_broken = False
                durable_reason: str | None = None
                if store is not None:
                    try:
                        durable_broken, durable_reason = store.consume_recreate_signal(key)
                    except Exception:
                        durable_broken = True
                        durable_reason = "CONTINUITY_STORE_READ_FAILED"
                        self._continuity_degraded = True
                        self._continuity_degraded_reason = durable_reason
                broken = tombstone_reason is not None or durable_broken
                reason = tombstone_reason or durable_reason
                state = AuthorityState(
                    session_key=key,
                    graph=CapabilityGraph(max_nodes=config.max_nodes, max_edges=config.max_edges),
                    continuity_broken=broken,
                    continuity_break_reason=reason,
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
            store = self._continuity_store
            if key is None:
                self._states.clear()
                self._budgets.clear()
                self._configs.clear()
                self._last_explanations.clear()
                self._event_views.clear()
                self._last_access.clear()
                self._authority_tombstones.clear()
                # Operator-wide reset clears degradation (intentional re-attestation).
                self._continuity_degraded = False
                self._continuity_degraded_reason = None
                if store is not None:
                    try:
                        store.clear_all_sessions()
                    except Exception:
                        pass
            else:
                # Explicit operator reset is intentional — do not tombstone.
                self._authority_tombstones.pop(key, None)
                self._states.pop(key, None)
                self._budgets.pop(key, None)
                self._configs.pop(key, None)
                self._last_explanations.pop(key, None)
                self._event_views.pop(key, None)
                self._last_access.pop(key, None)
                if store is not None:
                    try:
                        store.clear_session(key)
                    except Exception:
                        pass


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


def configure_authority_registry(*, db_path: str | None) -> AuthorityRegistry:
    """Bind (or clear) durable continuity for the process-wide live registry.

    Bind failures degrade the live registry rather than leaving enforce with
    silently unbound continuity (unknown continuity ≠ clean authority).
    """
    if db_path:
        from .continuity_store import ContinuityStore

        try:
            store = ContinuityStore(db_path)
        except Exception:
            _REGISTRY.attach_continuity_store(None)
            _REGISTRY.mark_continuity_degraded("CONTINUITY_STORE_BIND_FAILED")
            return _REGISTRY
        _REGISTRY.attach_continuity_store(store)
    else:
        _REGISTRY.attach_continuity_store(None)
    return _REGISTRY


def reset_authority_registry(key: str | None = None) -> None:
    _REGISTRY.reset(key)
