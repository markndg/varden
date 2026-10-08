"""Historical replay of a candidate rule.

Replay re-evaluates stored audit events with ``PolicyEngine.evaluate``. It does
not execute tools, open sockets, or write policy.
"""

from __future__ import annotations

import copy
from typing import Any

from varden.models import Action
from varden.policy import PolicyEngine

INSUFFICIENT = "INSUFFICIENT_REPLAY_DATA"
BOUNDED = "BOUNDED"
PARTIAL = "PARTIAL_EVIDENCE"
COMPLETE = "COMPLETE"


def decision_class(name: str | None) -> str:
    text = str(name or "").strip().lower()
    if text in {"block", "blocked"}:
        return "deny"
    if text in {"require_approval"}:
        return "require_approval"
    if text in {"warn", "warned"}:
        return "challenge"
    if text in {"allow", "allowed", "monitor", "sanitise", "sanitize"}:
        return "allow"
    return "unknown"


def replay_candidate(
    *,
    candidate: dict[str, Any],
    events: list[dict[str, Any]],
    policy: dict[str, Any],
    limit: int,
) -> dict[str, Any]:
    """Classify stored events under the candidate. No side effects."""
    analysed_events = list(events[: max(0, limit)])
    truncated = len(events) > len(analysed_events)
    if not candidate.get("possible") or not isinstance(candidate.get("rule"), dict):
        return {
            "status": INSUFFICIENT,
            "operations_analysed": 0,
            "unaffected": 0,
            "would_allow": 0,
            "would_challenge": 0,
            "would_require_approval": 0,
            "would_deny": 0,
            "unknown": 0,
            "affected": [],
            "truncated": False,
            "reason": "No candidate rule to replay.",
        }

    proposed = copy.deepcopy(policy or {"block": [], "warn": [], "monitor": [], "allow": []})
    for bucket in ("block", "require_approval", "sanitise", "warn", "monitor", "allow"):
        proposed.setdefault(bucket, [])
    action = str(candidate.get("expected_action") or "require_approval")
    proposed.setdefault(action, [])
    proposed[action] = list(proposed.get(action) or []) + [copy.deepcopy(candidate["rule"])]

    engine = PolicyEngine(":memory:", proposed)
    base_engine = PolicyEngine(":memory:", copy.deepcopy(policy or {}))
    counts = {
        "would_allow": 0,
        "would_challenge": 0,
        "would_require_approval": 0,
        "would_deny": 0,
        "unknown": 0,
    }
    unaffected = 0
    affected: list[dict[str, Any]] = []
    class_to_count = {
        "allow": "would_allow",
        "challenge": "would_challenge",
        "require_approval": "would_require_approval",
        "deny": "would_deny",
        "unknown": "unknown",
    }
    for event in analysed_events:
        action_data = event.get("action") if isinstance(event, dict) else None
        if not isinstance(action_data, dict) or not action_data.get("type"):
            counts["unknown"] += 1
            affected.append(
                {
                    "event_id": (event or {}).get("id") if isinstance(event, dict) else None,
                    "before": "unknown",
                    "after": "unknown",
                    "reason": "stored event has no action type",
                }
            )
            continue
        try:
            model = Action(**{key: action_data.get(key) for key in Action.__dataclass_fields__ if key in action_data})
            before = decision_class(base_engine.evaluate(model).effective_action)
            after_decision = engine.evaluate(model)
            after = decision_class(after_decision.effective_action)
        except (TypeError, ValueError):
            counts["unknown"] += 1
            continue
        counts[class_to_count[after]] += 1
        if before == after:
            unaffected += 1
        else:
            affected.append(
                {
                    "event_id": event.get("id"),
                    "before": before,
                    "after": after,
                    "reason": after_decision.reason,
                    "tool": action_data.get("tool"),
                    "type": action_data.get("type"),
                }
            )

    analysed = len(analysed_events)
    if analysed == 0 or counts["unknown"] == analysed:
        status = INSUFFICIENT
    elif truncated:
        status = BOUNDED
    elif counts["unknown"]:
        status = PARTIAL
    else:
        status = COMPLETE
    return {
        "status": status,
        "operations_analysed": analysed,
        "unaffected": unaffected,
        "would_allow": counts["would_allow"],
        "would_challenge": counts["would_challenge"],
        "would_require_approval": counts["would_require_approval"],
        "would_deny": counts["would_deny"],
        "unknown": counts["unknown"],
        "affected": affected[:200],
        "affected_total": len(affected),
        "truncated": truncated,
        "limit": limit,
        "reason": None if status == COMPLETE else _status_reason(status, truncated, limit),
    }


def _status_reason(status: str, truncated: bool, limit: int) -> str:
    if status == INSUFFICIENT:
        return "Historical telemetry is missing or cannot be evaluated. No confidence is claimed."
    if status == BOUNDED:
        return f"Replay stopped at the configured limit of {limit} events. Counts are not exhaustive."
    if truncated:
        return "Replay was truncated."
    return "Some stored events could not be evaluated."
