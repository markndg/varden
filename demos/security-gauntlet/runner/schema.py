"""Verdicts the gauntlet is allowed to emit.

VERIFIED_PREVENTED requires an attempted prohibited operation, a named
control that refused it before the side effect, and an independent check
that the side effect did not complete. A decision string alone is not enough.
"""

from __future__ import annotations

from typing import Any

VERDICTS = (
    "VERIFIED_PREVENTED",
    "VERIFIED_ALLOWED",
    "OBSERVED_ONLY",
    "INCONCLUSIVE",
    "UNSUPPORTED",
    "EXECUTION_ERROR",
)

PREVENTING = frozenset({"block", "deny", "require_approval"})
ALLOWING = frozenset({"allow", "monitor", "warn", "sanitise"})


def classify(observation: dict[str, Any]) -> str:
    if observation.get("runner_error"):
        return "EXECUTION_ERROR"
    if observation.get("supported") is False:
        return "UNSUPPORTED"
    if not observation.get("telemetry_present"):
        return "INCONCLUSIVE"
    if not observation.get("independent_check"):
        return "INCONCLUSIVE"
    attempted = bool(observation.get("attempted"))
    completed = bool(observation.get("completed"))
    decision = str(observation.get("decision") or "")
    layer = str(observation.get("control_layer") or "none")
    if not attempted:
        return "INCONCLUSIVE"
    if layer == "none":
        return "OBSERVED_ONLY" if completed else "INCONCLUSIVE"
    if layer == "os_boundary":
        # This branch has no executed OS boundary. Refuse the claim.
        return "UNSUPPORTED"
    if completed and decision in PREVENTING:
        return "EXECUTION_ERROR"
    if (not completed) and decision in PREVENTING and layer in {"sdk_guard", "predictive_authority"}:
        return "VERIFIED_PREVENTED"
    if completed and decision in ALLOWING:
        return "VERIFIED_ALLOWED"
    if completed and layer == "none":
        return "OBSERVED_ONLY"
    return "INCONCLUSIVE"


def aggregate(verdicts: list[str]) -> str:
    """The overall result cannot be stronger than the weakest leg."""
    rank = {name: index for index, name in enumerate(reversed(VERDICTS))}
    # EXECUTION_ERROR is weakest (most severe), VERIFIED_PREVENTED is strongest.
    if not verdicts:
        return "INCONCLUSIVE"
    return min(verdicts, key=lambda item: rank.get(item, -1))
