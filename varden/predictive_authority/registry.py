"""Session registry for AuthorityState instances."""

from __future__ import annotations

import threading
from typing import Any

from .config import PredictiveAuthorityConfig
from .graph import CapabilityGraph
from .state import AuthorityState
from .budget import AuthorityBudget, budget_from_state


class AuthorityRegistry:
    """Process-local registry keyed by session/trace identity."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: dict[str, AuthorityState] = {}
        self._budgets: dict[str, AuthorityBudget] = {}
        self._configs: dict[str, PredictiveAuthorityConfig] = {}
        self._last_explanations: dict[str, dict[str, Any]] = {}
        self._event_views: dict[str, list[dict[str, Any]]] = {}

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
            return state

    def get(self, key: str) -> AuthorityState | None:
        return self._states.get(key)

    def budget(self, key: str) -> AuthorityBudget | None:
        return self._budgets.get(key)

    def set_budget(self, key: str, budget: AuthorityBudget) -> None:
        with self._lock:
            self._budgets[key] = budget

    def remember_explanation(self, key: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self._last_explanations[key] = payload

    def remember_event_view(self, key: str, payload: dict[str, Any], *, max_events: int = 100) -> None:
        with self._lock:
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
            else:
                self._states.pop(key, None)
                self._budgets.pop(key, None)
                self._configs.pop(key, None)
                self._last_explanations.pop(key, None)
                self._event_views.pop(key, None)


_REGISTRY = AuthorityRegistry()


def get_authority_registry() -> AuthorityRegistry:
    return _REGISTRY


def reset_authority_registry(key: str | None = None) -> None:
    _REGISTRY.reset(key)
