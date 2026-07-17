from __future__ import annotations

from typing import Any

from .token_budget import TokenBudgetRule


def parse_budget_rule(raw: dict[str, Any]) -> TokenBudgetRule | None:
    if not isinstance(raw, dict):
        return None
    rule_type = str(raw.get("type") or "token_budget")
    if rule_type != "token_budget":
        return None
    return TokenBudgetRule.from_dict(raw)


def load_budget_rules(policy: dict[str, Any] | None) -> list[TokenBudgetRule]:
    rules: list[TokenBudgetRule] = []
    for raw in (policy or {}).get("budget_rules") or []:
        rule = parse_budget_rule(raw)
        if rule and rule.enabled:
            rules.append(rule)
    return rules


def validate_budget_rules(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    rows = policy.get("budget_rules")
    if rows is None:
        return errors
    if not isinstance(rows, list):
        return ["budget_rules must be a list"]
    for idx, raw in enumerate(rows):
        if not isinstance(raw, dict):
            errors.append(f"budget_rules[{idx}] must be an object")
            continue
        rule = parse_budget_rule(raw)
        if rule is None:
            errors.append(f"budget_rules[{idx}] must have type token_budget")
            continue
        errors.extend(rule.validate())
    return errors
