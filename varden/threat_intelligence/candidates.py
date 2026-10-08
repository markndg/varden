"""Deterministic candidate rules.

Candidates are ordinary Varden policy rules. They are not active until an
operator approves them. External description text is never copied into a rule.
"""

from __future__ import annotations

import time
from typing import Any

from varden.policy import PolicyEngine

from .contracts import contract_template
from .models import GENERATION_VERSION


def generate_candidate(
    *,
    item: dict[str, Any],
    contract: dict[str, Any],
    assessment: dict[str, Any],
    policy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return a candidate document. ``rule`` is None when none should be proposed."""
    now = time.time()
    base = {
        "id": f"cand-{item.get('id')}-{contract.get('id') or 'none'}",
        "contract_id": contract.get("id"),
        "item_id": item.get("id"),
        "source_refs": [
            {"source": item.get("source"), "source_id": item.get("source_id"), "raw_content_hash": item.get("raw_content_hash")}
        ],
        "rule": None,
        "explanation": "",
        "affected_surfaces": list(contract.get("enforcement_surfaces") or []),
        "expected_action": None,
        "confidence": "none",
        "assumptions": [],
        "conflicts": [],
        "generation_version": GENERATION_VERSION,
        "created_at": now,
        "possible": False,
        "reason_code": "",
    }
    result = assessment.get("result")
    if result == "PROTECTED":
        base["explanation"] = "Existing enforcement already proves the invariant. No additional rule is proposed."
        base["reason_code"] = "ALREADY_PROTECTED"
        return base
    if result == "NOT_APPLICABLE":
        base["explanation"] = "The contract does not apply to this installation. No rule is proposed."
        base["reason_code"] = "NOT_APPLICABLE"
        return base
    if result == "REVIEW" or contract.get("review_only") or not contract.get("id"):
        base["explanation"] = contract.get("review_reason") or "No deterministic candidate can be synthesised."
        base["reason_code"] = "NO_DETERMINISTIC_CANDIDATE"
        return base

    template = contract_template(str(contract.get("id")))
    if template is None:
        base["explanation"] = "This contract has no Varden rule template."
        base["reason_code"] = "NO_TEMPLATE"
        return base

    surfaces = assessment.get("surfaces") or []
    applicable = [row for row in surfaces if row.get("applicable")]
    incomplete = [
        row for row in applicable if row.get("coverage") not in {"ENFORCED", "ENFORCED VIA GATEWAY"}
    ]
    policy_gap = not assessment.get("policy_proves_invariant")
    if incomplete and not policy_gap:
        names = ", ".join(f"{row.get('name')} ({row.get('coverage')})" for row in incomplete)
        base["explanation"] = (
            f"The gap is coverage ({names}), not a missing policy rule. "
            "A candidate rule would not bind paths that never reach enforcement, "
            "and partial coverage is not closed by another policy predicate."
        )
        base["reason_code"] = "GAP_IS_COVERAGE"
        base["assumptions"] = [f"{row.get('name')} is {row.get('coverage')}" for row in incomplete]
        return base

    rule = dict(template["rule"])
    expected = template["expected_action"]
    wrapper = {"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []}
    wrapper[expected] = [rule]
    validation = PolicyEngine(":memory:").validate(wrapper)
    if not validation["valid"]:
        base["explanation"] = "The template rule failed Varden policy validation: " + "; ".join(validation["errors"])
        base["reason_code"] = "INVALID_RULE"
        return base

    conflicts = _conflicts(policy or {}, rule)
    assumptions: list[str] = [
        "The candidate uses Varden's existing policy language and does nothing until it is approved.",
        "External threat text was not copied into the rule.",
    ]
    confidence = "high"
    if incomplete:
        assumptions.append(
            "Coverage is incomplete on "
            + ", ".join(f"{row.get('name')}={row.get('coverage')}" for row in incomplete)
            + ". This rule does not close that gap."
        )
        confidence = "low"
    if conflicts:
        assumptions.append("An existing allow or monitor rule matches the same predicates. Precedence still lets block and require_approval win, but the operator should read the conflict.")
        confidence = "medium" if confidence == "high" else confidence
    unknown_obs = [
        row.get("name")
        for row in (assessment.get("observability") or [])
        if row.get("available") is not True
    ]
    if unknown_obs:
        assumptions.append("Observability is not fully proven for " + ", ".join(str(name) for name in unknown_obs) + ".")
        if confidence == "high":
            confidence = "medium"

    base.update(
        {
            "rule": rule,
            "explanation": contract.get("explanation") or "Proposed installation-specific hold for the contract invariant.",
            "expected_action": expected,
            "confidence": confidence,
            "assumptions": assumptions,
            "conflicts": conflicts,
            "possible": True,
            "reason_code": "CANDIDATE",
        }
    )
    return base


def _conflicts(policy: dict[str, Any], rule: dict[str, Any]) -> list[dict[str, Any]]:
    from varden.policy import RULE_META_KEYS

    wanted = {
        key: value
        for key, value in rule.items()
        if key not in RULE_META_KEYS and value is not None and value != ""
    }
    found: list[dict[str, Any]] = []
    for bucket in ("allow", "monitor", "warn"):
        for existing in policy.get(bucket) or []:
            if not isinstance(existing, dict):
                continue
            predicates = {
                key: value
                for key, value in existing.items()
                if key not in RULE_META_KEYS and value is not None and value != ""
            }
            if predicates and predicates == wanted:
                found.append(
                    {
                        "bucket": bucket,
                        "id": existing.get("id"),
                        "note": "Same predicates exist in a non-enforcing bucket. Approval would add an enforcing rule; it would not delete this one.",
                    }
                )
    return found


def validate_candidate(doc: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["candidate must be an object"]
    for key in ("id", "generation_version", "reason_code"):
        if not doc.get(key):
            errors.append(f"candidate.{key} is required")
    if doc.get("possible"):
        rule = doc.get("rule")
        action = doc.get("expected_action")
        if not isinstance(rule, dict):
            errors.append("possible candidate requires a rule object")
        elif action not in {"block", "require_approval", "warn", "monitor"}:
            errors.append("candidate.expected_action is not a Varden decision")
        else:
            wrapper = {"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []}
            wrapper[action] = [rule]
            validation = PolicyEngine(":memory:").validate(wrapper)
            errors.extend(validation["errors"])
        description = str((rule or {}).get("description") or "")
        if "ignore previous" in description.lower() or "system prompt" in description.lower():
            errors.append("candidate rule description must not carry external instructions")
    return errors
