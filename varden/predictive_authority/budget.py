"""Optional Authority Budget — derived from structural graph expansion."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .authority_delta import AuthorityDelta
from .state import AuthorityState


@dataclass
class AuthorityBudget:
    """Optional cap on structural authority expansion units for a session."""

    max_units: int | None = None
    initial_units: int = 0
    consumed_units: int = 0
    high_impact: list[dict[str, Any]] = field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return self.max_units is not None

    @property
    def current_units(self) -> int:
        return self.initial_units + self.consumed_units

    @property
    def remaining(self) -> int | None:
        if self.max_units is None:
            return None
        return max(0, int(self.max_units) - self.current_units)

    def would_exceed(self, delta: AuthorityDelta) -> bool:
        if self.max_units is None:
            return False
        return self.current_units + delta.structural_units() > int(self.max_units)

    def apply(self, delta: AuthorityDelta, *, summary: str = "") -> None:
        units = delta.structural_units()
        self.consumed_units += units
        if units >= 8 or delta.added_hazardous_paths or delta.added_irreversible_actions:
            self.high_impact.append(
                {
                    "summary": summary,
                    "units": units,
                    "domains": list(delta.added_privilege_domains),
                    "hazardous": len(delta.added_hazardous_paths),
                }
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_units": self.max_units,
            "initial_units": self.initial_units,
            "consumed_units": self.consumed_units,
            "current_units": self.current_units,
            "remaining": self.remaining,
            "high_impact": list(self.high_impact),
            "derivation": (
                "Units derive from AuthorityDelta.structural_units(): "
                "confirmed capability sensitivity//10, potential sensitivity//20, "
                "+2 sensitive resource, +3 sink, +5 hazardous path, +4 irreversible, +3 domain."
            ),
        }


def budget_from_state(state: AuthorityState, max_units: int | None) -> AuthorityBudget:
    # Initial units = structural weight of initial confirmed capabilities.
    initial = 0
    for name in state.initial_capability_names:
        cap = state.capabilities.get(name)
        if cap is not None:
            initial += max(1, int(cap.sensitivity) // 10)
    return AuthorityBudget(max_units=max_units, initial_units=initial, consumed_units=0)
