"""Interpret control-plane ``/sdk/guard`` bodies.

Only the policy decision object is authoritative. That object is the top-level
``decision`` field, or the same field inside one FastAPI ``detail`` wrapper.
``decision.action`` and ``decision.effective_action`` are the only action
fields that count.

Agent-controlled JSON echoed on the action (``args``, ``metadata``, nested
``decision`` / ``detail`` objects) is not a policy decision. A bare string is
not a policy decision. HTTP 403 is a deny even when the body is unreadable.
"""

from __future__ import annotations

from typing import Any

# Aliases the decision engine and status mapping already use.
DENY_ACTIONS = frozenset({"block", "blocked", "require_approval", "approval_required"})

# Policy vocabulary that may execute (``sanitise`` modifies output; it does not block).
_NON_DENY_ACTIONS = frozenset({"allow", "warn", "warned", "monitor", "sanitise"})

POLICY_ACTIONS = DENY_ACTIONS | _NON_DENY_ACTIONS


def _policy_action(obj: Any, key: str) -> str | None:
    if not isinstance(obj, dict):
        return None
    value = obj.get(key)
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text not in POLICY_ACTIONS:
        return None
    return text


def _is_decision(obj: Any) -> bool:
    return _policy_action(obj, "action") is not None


def candidate_decisions(payload: Any) -> list[dict[str, Any]]:
    """Return decision objects from known slots. Does not walk arbitrary JSON."""
    if not isinstance(payload, dict):
        return []
    found: list[dict[str, Any]] = []
    direct = payload.get("decision")
    if isinstance(direct, dict) and _is_decision(direct):
        found.append(direct)
    elif "decision" not in payload and _is_decision(payload) and not isinstance(payload.get("action"), dict):
        # GuardResult stores the decision object itself. An action envelope's
        # ``action`` value is a dict, so it is not mistaken for a decision.
        found.append(payload)
    detail = payload.get("detail")
    if isinstance(detail, dict):
        nested = detail.get("decision")
        if isinstance(nested, dict) and _is_decision(nested):
            found.append(nested)
        elif "decision" not in detail and _is_decision(detail) and not isinstance(detail.get("action"), dict):
            found.append(detail)
    return found


def _slot_denies(decision: dict[str, Any]) -> bool:
    action = _policy_action(decision, "action")
    effective = _policy_action(decision, "effective_action")
    return action in DENY_ACTIONS or effective in DENY_ACTIONS


def response_denies_execution(payload: Any) -> bool:
    """True when a recognized decision slot says the operation must not execute.

    If ``action`` and ``effective_action`` disagree, a deny wins. Nested objects
    under other keys are ignored.
    """
    return any(_slot_denies(decision) for decision in candidate_decisions(payload))


def response_decision_ambiguous(payload: Any) -> bool:
    """True when a decision slot is present but is not a recognized policy action.

    Missing decision (transport / non-JSON) is not ambiguous; callers keep the
    fail-mode behaviour for that case. A present but unreadable decision is not
    treated as allow.
    """
    if not isinstance(payload, dict):
        return False
    slots: list[Any] = []
    if "decision" in payload:
        slots.append(payload.get("decision"))
    detail = payload.get("detail")
    if isinstance(detail, dict) and "decision" in detail:
        slots.append(detail.get("decision"))
    if not slots:
        return False
    return any(not _is_decision(slot) for slot in slots)


def guard_response_blocks(payload: Any, *, status_code: int | None = None) -> bool:
    """Whether this HTTP result must not execute."""
    if status_code == 403:
        return True
    if response_denies_execution(payload):
        return True
    return response_decision_ambiguous(payload)
