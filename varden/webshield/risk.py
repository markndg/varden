from __future__ import annotations

from .models import Finding, RiskDriver, RiskResult

RISK_PROFILE_VERSION = "1"

SEVERITY_WEIGHT: dict[str, int] = {"critical": 42, "high": 34, "medium": 16, "low": 6, "info": 0}

# Diminishing returns so that many trivial findings cannot outweigh one
# strong, well-evidenced finding. Position 0 = strongest finding at full
# weight; later positions contribute progressively less.
DIMINISHING_FACTORS = (1.0, 0.6, 0.35, 0.2)
TAIL_FACTOR = 0.08

BANDS: tuple[tuple[int, int, str], ...] = (
    (0, 19, "low"),
    (20, 39, "guarded"),
    (40, 59, "suspicious"),
    (60, 79, "high"),
    (80, 100, "critical"),
)


def band_for_score(score: int) -> str:
    for low, high, name in BANDS:
        if low <= score <= high:
            return name
    return "critical" if score > 100 else "low"


def compute_risk(
    findings: list[Finding],
    *,
    mutates_state: bool = False,
    sensitive_data_involved: bool = False,
    cross_origin_implicated: bool = False,
    trust_state: str | None = None,
) -> RiskResult:
    """Deterministic, explainable, versioned risk scoring.

    Score is built from bounded, capped contributions rather than raw
    summation so that dozens of low-severity findings cannot manufacture a
    critical score, while a single well-evidenced critical finding reliably
    reaches the high/critical band on its own.
    """

    scored = [f for f in findings if SEVERITY_WEIGHT.get(f.severity, 0) > 0]
    scored.sort(key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0) * f.confidence, reverse=True)

    drivers: list[RiskDriver] = []
    total = 0.0
    for index, finding in enumerate(scored):
        base = SEVERITY_WEIGHT.get(finding.severity, 0) * finding.confidence
        factor = DIMINISHING_FACTORS[index] if index < len(DIMINISHING_FACTORS) else TAIL_FACTOR
        contribution = round(base * factor)
        if contribution <= 0:
            continue
        total += contribution
        drivers.append(RiskDriver(finding.rule_id, int(contribution), finding.explanation))

    categories = {f.category for f in scored}
    if len(categories) > 1:
        bonus = min(20, 5 * (len(categories) - 1))
        total += bonus
        drivers.append(RiskDriver(
            "WEBMCP-RISK-DIVERSITY", bonus,
            f"Findings span {len(categories)} independent categories, indicating a compound rather than isolated issue.",
        ))

    for flag, amount, rule_id, reason in (
        (mutates_state, 5, "WEBMCP-RISK-MUTATES", "Operation mutates state rather than only reading data."),
        (sensitive_data_involved, 5, "WEBMCP-RISK-SENSITIVE", "Sensitive data is involved in this operation."),
        (cross_origin_implicated, 10, "WEBMCP-RISK-CROSS-ORIGIN", "Activity crosses an origin boundary."),
    ):
        if flag:
            total += amount
            drivers.append(RiskDriver(rule_id, amount, reason))

    if trust_state == "trusted":
        reduction = min(total, 20)
        if reduction:
            total -= reduction
            drivers.append(RiskDriver(
                "WEBMCP-RISK-TRUST-OVERRIDE", -int(reduction),
                "Origin is explicitly trusted by a local decision, reducing computed risk.",
            ))
    elif trust_state == "blocked":
        total = max(total, 80)
        drivers.append(RiskDriver(
            "WEBMCP-RISK-TRUST-OVERRIDE", 0,
            "Origin is explicitly blocked by a local decision; score floored at the critical band.",
        ))

    score = max(0, min(100, round(total)))
    return RiskResult(score=score, band=band_for_score(score), profile_version=RISK_PROFILE_VERSION, drivers=drivers)
