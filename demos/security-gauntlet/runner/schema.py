"""Verdicts the gauntlet is allowed to emit.

A scenario has three scopes. They are computed from the legs and then sealed.
The summary, the detail view, the JSON export, and the HTML report all read
that sealed object. A baseline that was allowed and a protected step that was
prevented stay separate.
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
MEDIATED = frozenset({"sdk_guard", "predictive_authority", "os_boundary"})
SCOPES = ("baseline", "protected", "overall")

# Lower rank is a weaker claim. Prevention is not assigned by mixing scopes.
_RANK = {name: index for index, name in enumerate(reversed(VERDICTS))}


def classify(observation: dict[str, Any]) -> str:
    if observation.get("runner_error"):
        return "EXECUTION_ERROR"
    if observation.get("supported") is False:
        return "UNSUPPORTED"
    layer = str(observation.get("control_layer") or "none")
    # An OS label without a host execution is a claim, not a result.
    if layer == "os_boundary" and not observation.get("executed_on_host"):
        return "UNSUPPORTED"
    if not observation.get("telemetry_present"):
        return "INCONCLUSIVE"
    if not observation.get("independent_check"):
        return "INCONCLUSIVE"
    if not observation.get("attempted"):
        return "INCONCLUSIVE"
    completed = bool(observation.get("completed"))
    decision = str(observation.get("decision") or "")
    if layer == "none":
        return "OBSERVED_ONLY" if completed else "INCONCLUSIVE"
    if layer not in MEDIATED:
        return "INCONCLUSIVE"
    if completed and decision in PREVENTING:
        return "EXECUTION_ERROR"
    if (not completed) and decision in PREVENTING:
        return "VERIFIED_PREVENTED"
    if completed and decision in ALLOWING:
        return "VERIFIED_ALLOWED"
    return "INCONCLUSIVE"


def aggregate(verdicts: list[str]) -> str:
    """Weakest verdict inside one scope. Do not pass legs from two scopes."""
    if not verdicts:
        return "INCONCLUSIVE"
    return min(verdicts, key=lambda item: _RANK.get(item, -1))


def _scope(scope: str, verdict: str, legs: list[str], **extra: Any) -> dict[str, Any]:
    body = {"scope": scope, "verdict": verdict, "legs": legs}
    body.update(extra)
    return body


def build_outcomes(
    *,
    baseline_legs: list[dict[str, Any]],
    protected_legs: list[dict[str, Any]],
    claim_leg: str,
    basis: str,
    overall_verdict: str | None = None,
) -> dict[str, Any]:
    """Protected and overall follow the named claim leg, not the baseline."""
    protected_claim = next((leg for leg in protected_legs if leg.get("name") == claim_leg), None)
    if protected_claim is not None:
        protected_verdict = str(protected_claim["verdict"])
    elif protected_legs:
        protected_verdict = aggregate([str(leg["verdict"]) for leg in protected_legs])
    else:
        protected_verdict = "INCONCLUSIVE"
    baseline_verdict = aggregate([str(leg["verdict"]) for leg in baseline_legs]) if baseline_legs else "INCONCLUSIVE"
    overall = overall_verdict or protected_verdict
    if overall not in VERDICTS:
        overall = "INCONCLUSIVE"
    return {
        "baseline": _scope("baseline", baseline_verdict, [str(leg["name"]) for leg in baseline_legs]),
        "protected": _scope(
            "protected",
            protected_verdict,
            [str(leg["name"]) for leg in protected_legs],
            claim_leg=claim_leg,
        ),
        "overall": _scope(
            "overall",
            overall,
            [claim_leg] if claim_leg else [],
            claim_leg=claim_leg,
            basis=basis,
            excludes_baseline=True,
        ),
    }


def _denied_exit(leg: dict[str, Any]) -> bool:
    returncode = (leg.get("probe") or {}).get("returncode")
    return isinstance(returncode, int) and returncode != 0


def _downgrade(outcomes: dict[str, Any], verdict: str, basis: str) -> None:
    outcomes["overall"]["verdict"] = verdict
    outcomes["overall"]["basis"] = basis


def seal(record: dict[str, Any]) -> dict[str, Any]:
    """Reject a success claim that the legs do not support."""
    outcomes = record.get("outcomes")
    legs = list(record.get("legs") or []) + list(record.get("comparison") or [])
    by_name = {str(leg.get("name")): leg for leg in legs}
    if not isinstance(outcomes, dict) or any(scope not in outcomes for scope in SCOPES):
        record["outcomes"] = build_outcomes(baseline_legs=[], protected_legs=[], claim_leg="", basis="outcomes were missing")
        _downgrade(record["outcomes"], "INCONCLUSIVE", "outcomes were missing")
        record["verdict"] = "INCONCLUSIVE"
        return record
    for scope in SCOPES:
        item = outcomes.get(scope)
        if not isinstance(item, dict) or item.get("scope") != scope or item.get("verdict") not in VERDICTS:
            _downgrade(outcomes, "INCONCLUSIVE", f"{scope} verdict was absent or unlabeled")
            record["verdict"] = "INCONCLUSIVE"
            return record
    overall = outcomes["overall"]
    claim_name = str(overall.get("claim_leg") or "")
    claim = by_name.get(claim_name)
    if overall["verdict"] == "VERIFIED_PREVENTED":
        protected_names = set(outcomes["protected"].get("legs") or [])
        if claim is None or claim_name not in protected_names or claim.get("verdict") != "VERIFIED_PREVENTED":
            _downgrade(outcomes, "INCONCLUSIVE", "overall prevention did not match a protected leg")
        elif claim.get("completed") or not (claim.get("observation") or {}).get("independent_check", False):
            _downgrade(outcomes, "EXECUTION_ERROR" if claim.get("completed") else "INCONCLUSIVE", "prevention lacked an independent stopped side effect")
        elif claim.get("control_layer") == "os_boundary" and not (claim.get("observation") or {}).get("executed_on_host"):
            _downgrade(outcomes, "UNSUPPORTED", "OS prevention was labeled without a host execution")
        elif claim.get("control_layer") == "os_boundary" and (
            not claim.get("before_sha256") or claim.get("before_sha256") != claim.get("after_sha256")
        ):
            _downgrade(outcomes, "INCONCLUSIVE", "OS prevention did not show an unchanged protected hash")
        elif claim.get("control_layer") == "os_boundary" and not _denied_exit(claim):
            _downgrade(outcomes, "INCONCLUSIVE", "OS prevention lacked a non-zero process exit")
        elif not overall.get("excludes_baseline"):
            _downgrade(outcomes, "INCONCLUSIVE", "baseline was folded into the protected prevention claim")
    # A mandatory-enforcement headline cannot be prevention when the only
    # preventing leg is SDK interception and an unguarded write completed.
    if record.get("scenario_id") == "mandatory-enforcement" and overall["verdict"] == "VERIFIED_PREVENTED":
        outside = [leg for leg in legs if leg.get("control_layer") in {None, "none", ""} and leg.get("completed")]
        os_prevented = [
            leg for leg in legs
            if leg.get("control_layer") == "os_boundary" and leg.get("verdict") == "VERIFIED_PREVENTED"
        ]
        if outside:
            _downgrade(outcomes, "UNSUPPORTED", "A same-user or unguarded write completed. Contained OS denial does not cover that process.")
        elif not os_prevented:
            _downgrade(outcomes, "UNSUPPORTED", "SDK interception is not mandatory OS enforcement")
    record["verdict"] = outcomes["overall"]["verdict"]
    return record
