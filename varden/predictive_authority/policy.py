"""Predictive policy recommendation and decision strengthening.

Enforce mode may strengthen but NEVER weaken an existing Varden decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import Action, Decision
from .authority_delta import AuthorityDelta
from .hazardous import HazardousFinding


# Strongest → weakest numeric rank (mirrors PolicyEngine.MODES priority).
DECISION_RANK: dict[str, int] = {
    "block": 50,
    "require_approval": 40,
    "approval_required": 40,
    "sanitise": 30,
    "warn": 20,
    "monitor": 10,
    "allow": 0,
}


def decision_rank(action: str | None) -> int:
    return DECISION_RANK.get(str(action or "allow").lower(), 0)


def strongest_decision(a: str, b: str) -> str:
    return a if decision_rank(a) >= decision_rank(b) else b


@dataclass
class PredictiveRecommendation:
    action: str  # allow | monitor | warn | require_approval | block
    reason: str
    matched_predicates: list[str]
    authority_expands: bool
    structural_units: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "matched_predicates": list(self.matched_predicates),
            "authority_expands": self.authority_expands,
            "structural_units": self.structural_units,
        }


def recommend(
    *,
    delta: AuthorityDelta,
    findings: list[HazardousFinding],
    policy: dict[str, Any] | None = None,
    budget_exceeded: bool = False,
    irreversible: bool = False,
) -> PredictiveRecommendation:
    """Deterministic recommendation from structural delta + hazardous findings.

    Optional policy fragment under ``predictive_authority.rules`` may raise
    thresholds; defaults are conservative security defaults.
    """
    policy = policy or {}
    pa = policy.get("predictive_authority") if isinstance(policy.get("predictive_authority"), dict) else policy
    rules = (pa or {}).get("rules") if isinstance(pa, dict) else None
    rules = rules if isinstance(rules, dict) else {}

    matched: list[str] = []
    recommendation = "allow"

    def escalate(level: str, predicate: str) -> None:
        nonlocal recommendation
        matched.append(predicate)
        recommendation = strongest_decision(recommendation, level)

    if delta.authority_expands:
        escalate("monitor", "authority_expands")

    cap_threshold = int(rules.get("authority_delta_capabilities") or 2)
    if len(delta.added_capabilities) > cap_threshold:
        escalate("warn", "authority_delta_capabilities")

    if delta.added_sinks:
        escalate("warn", "new_external_sink_reachable")

    if delta.added_sensitive_resources:
        escalate("warn", "new_sensitive_sink_reachable")

    if any(c.name.startswith("credential.") for c in delta.confirmed_added()):
        escalate("require_approval", "credential_acquired")

    if any(
        c.name.startswith(("aws.", "cloud.", "database.admin", "subprocess.execute.privileged"))
        for c in delta.added_capabilities
    ):
        escalate("require_approval", "privileged_capability_acquired")

    if findings:
        escalate("require_approval", "reachable_path_matches")
        for f in findings:
            if f.pattern in {
                "untrusted_to_sensitive_to_external",
                "untrusted_to_credential_to_privileged",
                "cross_mcp_trust_domain",
            }:
                escalate("require_approval", f.pattern)
                if f.pattern == "untrusted_to_sensitive_to_external":
                    matched.append("untrusted_to_external_path")
                    matched.append("secret_exfiltration")
                elif f.pattern == "untrusted_to_credential_to_privileged":
                    matched.append("untrusted_to_sensitive_path")
                    matched.append("provenance_specific_hazard")
                elif f.pattern == "cross_mcp_trust_domain":
                    matched.append("cross_trust_domain_path")
                    matched.append("provenance_specific_hazard")
            if f.pattern == "credential_to_cloud_mutation":
                # May co-occur with provenance paths; not itself secret_exfiltration.
                matched.append("privileged_authority_hazard")
                escalate("require_approval", f.pattern)

    if irreversible or delta.added_irreversible_actions:
        escalate("require_approval", "irreversible_action_reachable")

    if budget_exceeded:
        escalate("block", "authority_budget_exceeded")

    # Policy may request block on specific patterns.
    block_patterns = rules.get("block_patterns") or []
    if isinstance(block_patterns, list):
        for f in findings:
            if f.pattern in block_patterns:
                escalate("block", f"block_pattern:{f.pattern}")

    reason = (
        "; ".join(dict.fromkeys(matched))
        if matched
        else "no predictive escalation"
    )
    return PredictiveRecommendation(
        action=recommendation,
        reason=reason,
        matched_predicates=list(dict.fromkeys(matched)),
        authority_expands=delta.authority_expands,
        structural_units=delta.structural_units(),
    )


def strengthen_decision(existing: Decision, recommendation: PredictiveRecommendation) -> Decision:
    """Return the stronger of existing vs predictive. Never weakens."""
    if decision_rank(recommendation.action) <= decision_rank(existing.action):
        return existing
    return Decision(
        action=recommendation.action,
        reason=f"predictive_authority: {recommendation.reason}",
        matched_rule={
            "type": "predictive_authority",
            "predicates": recommendation.matched_predicates,
            "prior_decision": existing.action,
            "prior_reason": existing.reason,
        },
        effective_action=recommendation.action,
        route_target=existing.route_target,
    )


def annotate_action_predicates(action: Action, *, delta: AuthorityDelta, findings: list[HazardousFinding], recommendation: PredictiveRecommendation) -> None:
    """Attach predictive classifiers/metadata for policy predicates."""
    classifiers = dict(action.classifiers or {})
    classifiers["authority_expands"] = bool(delta.authority_expands)
    classifiers["credential_acquired"] = any(c.name.startswith("credential.") for c in delta.confirmed_added())
    classifiers["privileged_capability_acquired"] = any(
        c.name.startswith(("aws.", "cloud.", "database.admin", "subprocess.execute.privileged"))
        for c in delta.added_capabilities
    )
    classifiers["new_external_sink_reachable"] = bool(delta.added_sinks)
    classifiers["new_sensitive_sink_reachable"] = bool(delta.added_sensitive_resources)
    classifiers["irreversible_action_reachable"] = bool(delta.added_irreversible_actions)
    classifiers["cross_trust_domain_path"] = any(f.pattern == "cross_mcp_trust_domain" for f in findings)
    classifiers["untrusted_to_sensitive_path"] = any("untrusted" in f.pattern and "sensitive" in f.pattern for f in findings)
    classifiers["untrusted_to_external_path"] = any("untrusted" in f.pattern and "external" in f.pattern for f in findings)
    classifiers["reachable_path_matches"] = bool(findings)
    action.classifiers = classifiers

    meta = dict(action.metadata or {})
    pa = dict(meta.get("predictive_authority") or {})
    pa["authority_delta_capabilities"] = len(delta.added_capabilities)
    pa["max_reachability_depth"] = pa.get("max_reachability_depth")
    pa["recommendation"] = recommendation.action
    pa["predicates"] = recommendation.matched_predicates
    meta["predictive_authority"] = pa
    action.metadata = meta
