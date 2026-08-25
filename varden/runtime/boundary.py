"""Canonical runtime boundary decision + shared pre/post execution hooks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BoundaryDecision:
    decision: str
    blocked: bool
    side_effect_prevented: bool | None
    approval_required: bool = False
    approval_id: str | None = None
    approval_token: str | None = None
    policy: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    authority: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    event_id: int | None = None
    action: dict[str, Any] = field(default_factory=dict)
    executed: bool | None = None
    outcome: str | None = None
    runtime: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_guard_result(
        cls,
        *,
        decision: dict[str, Any] | None,
        action: dict[str, Any] | None = None,
        event_id: int | None = None,
        surface: str,
        mode: str,
        observational: bool = False,
        approval_id: str | None = None,
    ) -> "BoundaryDecision":
        d = dict(decision or {})
        action_name = str(d.get("action") or "allow").lower()
        approval_required = action_name in {"require_approval", "approval_required"}
        blocked = action_name in {"block", "require_approval", "approval_required"}
        if observational:
            side_effect = None
            executed = None
        else:
            side_effect = True if blocked else False
            executed = False if blocked else None
        meta = (action or {}).get("metadata") or {}
        return cls(
            decision=action_name,
            blocked=blocked,
            side_effect_prevented=side_effect,
            approval_required=approval_required,
            approval_id=approval_id or d.get("approval_id") or meta.get("approval_id"),
            policy=d,
            provenance=dict(meta.get("provenance") or {}),
            authority=dict(meta.get("authority") or {}),
            coverage={"surface": surface},
            explanation=str(d.get("reason") or ""),
            event_id=event_id,
            action=dict(action or {}),
            executed=executed,
            runtime={
                "boundary": True,
                "surface": surface,
                "mode": mode,
                "pre_execution": not observational,
                "observational": observational,
            },
        )


def enrich_action_runtime_metadata(
    metadata: dict[str, Any] | None,
    *,
    surface: str,
    mode: str,
    pre_execution: bool = True,
    coverage_status: str | None = None,
    approval_token: str | None = None,
) -> dict[str, Any]:
    meta = dict(metadata or {})
    runtime = dict(meta.get("runtime") or {})
    runtime.update(
        {
            "boundary": True,
            "surface": surface,
            "mode": mode,
            "pre_execution": pre_execution,
            "coverage": coverage_status,
        }
    )
    if approval_token:
        runtime["approval_token"] = approval_token
        meta["approval_token"] = approval_token
    meta["runtime"] = runtime
    return meta
