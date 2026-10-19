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
DENY_ACTIONS = frozenset({"block", "blocked", "require_approval", "approval_required", "unsupported"})

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


def response_authorizes_execution(payload: Any) -> bool:
    """True only when a recognized non-deny decision was delivered.

    A missing decision is not permission. An ambiguous slot is not permission.
    A deny in any recognized slot wins, including when another slot says allow.
    Transport failure is not decided here: callers apply fail-open only when
    no HTTP result was delivered.
    """
    if response_denies_execution(payload) or response_decision_ambiguous(payload):
        return False
    decisions = candidate_decisions(payload)
    if not decisions:
        return False
    for decision in decisions:
        action = _policy_action(decision, "action")
        if action not in _NON_DENY_ACTIONS:
            return False
        effective = _policy_action(decision, "effective_action")
        if effective is not None and effective not in _NON_DENY_ACTIONS:
            return False
    return True


# Shared classification for every caller that reads ``/sdk/guard``.
AUTHORITATIVE_ALLOW = "authoritative_allow"
AUTHORITATIVE_DENY = "authoritative_deny"
APPROVAL_REQUIRED = "approval_required"
INVALID_DECISION = "invalid_decision"
NO_DECISION = "no_decision"
SERVICE_FAILURE = "service_failure"
SERVICE_FAILURE_WITH_ALLOW = "service_failure_with_allow"
TRANSPORT_FAILURE = "transport_failure"

_APPROVAL_ACTIONS = frozenset({"require_approval", "approval_required"})
_HARD_DENY_ACTIONS = frozenset({"block", "blocked", "unsupported"})

# Fail-open is only these. A completed HTTP response is not a transport failure.
_FAIL_OPEN_CLASSIFICATIONS = frozenset({TRANSPORT_FAILURE, SERVICE_FAILURE_WITH_ALLOW})


def _decision_labels(payload: Any) -> list[str]:
    labels: list[str] = []
    for decision in candidate_decisions(payload):
        action = _policy_action(decision, "action")
        effective = _policy_action(decision, "effective_action")
        if action is not None:
            labels.append(action)
        if effective is not None:
            labels.append(effective)
    return labels


def classify_guard_response(payload: Any, *, status_code: int | None = None) -> str:
    """Classify a completed HTTP response. Transport failure is not a response.

    A 2xx body with no recognized decision is ``no_decision``, not an allow.
    A 4xx/5xx body with no recognized decision is ``service_failure``.
    An authoritative allow on a non-success status is
    ``service_failure_with_allow``: fail-open may proceed, fail-closed may not.
    HTTP 403 and any deny or approval action never authorize.
    """
    labels = _decision_labels(payload)
    if status_code == 403 or response_denies_execution(payload):
        if any(label in _APPROVAL_ACTIONS for label in labels) and not any(
            label in _HARD_DENY_ACTIONS for label in labels
        ):
            return APPROVAL_REQUIRED
        return AUTHORITATIVE_DENY
    if response_decision_ambiguous(payload):
        return INVALID_DECISION
    if response_authorizes_execution(payload):
        if status_code is not None and status_code >= 400:
            return SERVICE_FAILURE_WITH_ALLOW
        return AUTHORITATIVE_ALLOW
    if status_code is not None and status_code >= 400:
        return SERVICE_FAILURE
    return NO_DECISION


def fail_open_applies(classification: str) -> bool:
    """True only for a transport outage or a non-success response that is an allow.

    Empty success bodies, malformed decisions, and HTTP errors without a
    decision are not outages.
    """
    return classification in _FAIL_OPEN_CLASSIFICATIONS


def is_transport_failure(exc: BaseException) -> bool:
    """True when no HTTP response was obtained.

    ``HTTPStatusError`` and JSON decode errors are delivered responses.
    Programming errors are not outages.
    """
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        return False
    try:
        import httpx
    except Exception:
        httpx = None  # type: ignore[assignment]
    if httpx is not None and isinstance(exc, httpx.TransportError):
        return True
    return isinstance(exc, (TimeoutError, ConnectionError, BrokenPipeError))
