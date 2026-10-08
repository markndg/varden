"""Explicit, validated lifecycle for a threat-intelligence item.

Applicability (PROTECTED / EXPOSED / NOT_APPLICABLE / REVIEW) is not a
lifecycle state. Those are assessment results. Lifecycle records what the
pipeline and the operator have done with the item.
"""

from __future__ import annotations

DISCOVERED = "DISCOVERED"
NORMALIZED = "NORMALIZED"
CONTRACT_GENERATED = "CONTRACT_GENERATED"
ASSESSED = "ASSESSED"
CANDIDATE = "CANDIDATE"
BACKTESTED = "BACKTESTED"
AWAITING_APPROVAL = "AWAITING_APPROVAL"
APPROVED = "APPROVED"
OBSERVE = "OBSERVE"
ENFORCED = "ENFORCED"
NOT_APPLICABLE = "NOT_APPLICABLE"
DISMISSED = "DISMISSED"
SUPERSEDED = "SUPERSEDED"
SOURCE_WITHDRAWN = "SOURCE_WITHDRAWN"
ERROR = "ERROR"
REVIEW = "REVIEW"

TERMINAL = frozenset({DISMISSED, SUPERSEDED, SOURCE_WITHDRAWN})

# Enforced rules are not silently reopened when upstream text changes.
LOCKED = frozenset({APPROVED, OBSERVE, ENFORCED})

_TRANSITIONS: dict[str, frozenset[str]] = {
    DISCOVERED: frozenset({NORMALIZED, ERROR}),
    NORMALIZED: frozenset({CONTRACT_GENERATED, REVIEW, ERROR, SOURCE_WITHDRAWN}),
    CONTRACT_GENERATED: frozenset({ASSESSED, ERROR}),
    ASSESSED: frozenset({CANDIDATE, NOT_APPLICABLE, REVIEW, DISMISSED, ERROR}),
    CANDIDATE: frozenset({BACKTESTED, REVIEW, ERROR}),
    BACKTESTED: frozenset({AWAITING_APPROVAL, REVIEW, ERROR}),
    AWAITING_APPROVAL: frozenset({APPROVED, DISMISSED, NOT_APPLICABLE, REVIEW, ERROR}),
    APPROVED: frozenset({OBSERVE, ENFORCED, ERROR}),
    OBSERVE: frozenset({ENFORCED, DISMISSED}),
    ENFORCED: frozenset({SUPERSEDED}),
    REVIEW: frozenset({DISMISSED, NOT_APPLICABLE, CANDIDATE, ASSESSED}),
    NOT_APPLICABLE: frozenset({DISMISSED, REVIEW}),
    DISMISSED: frozenset(),
    SUPERSEDED: frozenset(),
    SOURCE_WITHDRAWN: frozenset(),
    ERROR: frozenset({REVIEW, DISCOVERED}),
}


class InvalidTransition(ValueError):
    def __init__(self, current: str, new: str):
        self.current = current
        self.new = new
        super().__init__(f"illegal threat lifecycle transition {current} -> {new}")


def can_transition(current: str, new: str) -> bool:
    if current == new:
        return True
    return new in _TRANSITIONS.get(current, frozenset())


def transition(current: str, new: str) -> str:
    if current == new:
        return current
    if not can_transition(current, new):
        raise InvalidTransition(current, new)
    return new
