from __future__ import annotations

from .models import Finding, RiskComponents, RiskDriver, RiskResult

RISK_PROFILE_VERSION = "2"

SEVERITY_WEIGHT: dict[str, int] = {"critical": 42, "high": 34, "medium": 16, "low": 6, "info": 0}

# Diminishing returns so that many trivial findings cannot outweigh one
# strong, well-evidenced finding. Position 0 = strongest finding at full
# weight; later positions contribute progressively less. Applied *within*
# each risk component independently (see RiskComponents) so a pile of
# unrelated lifecycle noise cannot dilute a single critical content finding.
DIMINISHING_FACTORS = (1.0, 0.6, 0.35, 0.2)
TAIL_FACTOR = 0.08

BANDS: tuple[tuple[int, int, str], ...] = (
    (0, 19, "low"),
    (20, 39, "guarded"),
    (40, 59, "suspicious"),
    (60, 79, "high"),
    (80, 100, "critical"),
)

# Category -> component mapping. This is the load-bearing security boundary
# for trust handling: trust adjustments below only ever touch
# ``provenance_risk``, so a category's presence in this map (not its
# severity) is what determines whether a trusted origin can ever soften it.
# Instruction-hierarchy overrides, credential/secret extraction, data
# exfiltration, payment/wallet redirection, destructive cross-tool
# orchestration, security-bypass language and capability mismatches are all
# content/capability/impact categories, never provenance — so trust cannot
# reach them. See docs/web-shield-hardening-review.md #5.
_CONTENT_CATEGORIES = {
    "instruction_hierarchy_override",
    "authority_impersonation",
    "secrecy_demand",
    "forced_tool_selection",
    "cross_tool_invocation",
    "credential_access",
    "data_exfiltration",
    "destructive_action",
    "payment_action",
    "security_bypass",
    "forced_persistence",
    "encoded_instruction",
    "unicode_obfuscation",
}
_CAPABILITY_CATEGORIES = {"capability_mismatch"}
_LIFECYCLE_CATEGORIES = {"lifecycle_anomaly"}
_PROVENANCE_CATEGORIES = {"provenance"}
_IMPACT_CATEGORIES = {"resource_abuse", "output_contamination", "cross_origin_flow"}


def _component_for_category(category: str) -> str:
    if category in _CAPABILITY_CATEGORIES:
        return "capability"
    if category in _LIFECYCLE_CATEGORIES:
        return "lifecycle"
    if category in _PROVENANCE_CATEGORIES:
        return "provenance"
    if category in _IMPACT_CATEGORIES:
        return "impact"
    # Content is the conservative default for any category this map does not
    # yet know about (e.g. a future pattern rule): unknown findings must stay
    # visible and trust-immune rather than silently falling into a component
    # trust is allowed to soften.
    return "content"


def band_for_score(score: int) -> str:
    for low, high, name in BANDS:
        if low <= score <= high:
            return name
    return "critical" if score > 100 else "low"


def _score_bucket(findings: list[Finding]) -> tuple[float, list[RiskDriver]]:
    """Diminishing-returns scoring + within-bucket category-diversity bonus,
    scoped to one risk component's findings only."""

    ordered = sorted(findings, key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0) * f.confidence, reverse=True)
    drivers: list[RiskDriver] = []
    total = 0.0
    for index, finding in enumerate(ordered):
        base = SEVERITY_WEIGHT.get(finding.severity, 0) * finding.confidence
        factor = DIMINISHING_FACTORS[index] if index < len(DIMINISHING_FACTORS) else TAIL_FACTOR
        contribution = round(base * factor)
        if contribution <= 0:
            continue
        total += contribution
        drivers.append(RiskDriver(finding.rule_id, int(contribution), finding.explanation))

    categories = {f.category for f in ordered}
    if len(categories) > 1:
        bonus = min(20, 5 * (len(categories) - 1))
        total += bonus
        drivers.append(RiskDriver(
            "WEBMCP-RISK-DIVERSITY", bonus,
            f"Findings span {len(categories)} independent categories within this component, indicating a compound rather than isolated issue.",
        ))
    return total, drivers


def compute_risk(
    findings: list[Finding],
    *,
    mutates_state: bool = False,
    sensitive_data_involved: bool = False,
    cross_origin_implicated: bool = False,
    trust_state: str | None = None,
) -> RiskResult:
    """Deterministic, explainable, versioned risk scoring.

    The score is the sum of five independently-scored components
    (``RiskComponents``: content, capability, lifecycle, provenance,
    impact). Local trust decisions are only ever allowed to move
    ``provenance_risk`` — see the module docstring on ``RiskComponents`` and
    docs/web-shield-hardening-review.md #5. A trusted origin can therefore
    never reduce the score contribution of a confirmed prompt-injection,
    credential-extraction, exfiltration, payment-redirection, security-bypass
    or capability-mismatch finding.
    """

    scored = [f for f in findings if SEVERITY_WEIGHT.get(f.severity, 0) > 0]
    buckets: dict[str, list[Finding]] = {"content": [], "capability": [], "lifecycle": [], "provenance": [], "impact": []}
    for finding in scored:
        buckets[_component_for_category(finding.category)].append(finding)

    content_risk, content_drivers = _score_bucket(buckets["content"])
    capability_risk, capability_drivers = _score_bucket(buckets["capability"])
    lifecycle_risk, lifecycle_drivers = _score_bucket(buckets["lifecycle"])
    provenance_risk, provenance_drivers = _score_bucket(buckets["provenance"])
    impact_risk, impact_drivers = _score_bucket(buckets["impact"])

    # Capability-shaped signals belong to capability_risk, not content, so
    # that a benign-but-mutating tool is never confused with a tool whose
    # *text* contains an attack, and so that trust (which never touches
    # capability_risk) cannot be implicated in softening them either.
    if mutates_state:
        capability_risk += 5
        capability_drivers.append(RiskDriver("WEBMCP-RISK-MUTATES", 5, "Operation mutates state rather than only reading data."))
    if sensitive_data_involved:
        capability_risk += 5
        capability_drivers.append(RiskDriver("WEBMCP-RISK-SENSITIVE", 5, "Sensitive data is involved in this operation."))
    if cross_origin_implicated:
        impact_risk += 10
        impact_drivers.append(RiskDriver("WEBMCP-RISK-CROSS-ORIGIN", 10, "Activity crosses an origin boundary."))

    # --- trust: provenance_risk only, never content/capability/lifecycle/impact ---
    if trust_state == "trusted":
        reduction = min(provenance_risk, 20)
        if reduction:
            provenance_risk -= reduction
            provenance_drivers.append(RiskDriver(
                "WEBMCP-RISK-TRUST-OVERRIDE", -int(reduction),
                "Origin is explicitly trusted by a local decision, which reduces provenance risk only. "
                "Content, capability and impact findings are never reduced by trust.",
            ))
    elif trust_state == "blocked":
        pre_floor_total = content_risk + capability_risk + lifecycle_risk + provenance_risk + impact_risk
        if pre_floor_total < 80:
            deficit = 80 - pre_floor_total
            provenance_risk += deficit
            provenance_drivers.append(RiskDriver(
                "WEBMCP-RISK-TRUST-OVERRIDE", int(deficit),
                "Origin is explicitly blocked by a local decision; provenance risk is raised so the overall "
                "score reaches the critical band regardless of other components.",
            ))

    components = RiskComponents(
        content_risk=int(round(content_risk)),
        capability_risk=int(round(capability_risk)),
        lifecycle_risk=int(round(lifecycle_risk)),
        provenance_risk=int(round(provenance_risk)),
        impact_risk=int(round(impact_risk)),
    )
    total = components.content_risk + components.capability_risk + components.lifecycle_risk + components.provenance_risk + components.impact_risk
    score = max(0, min(100, round(total)))
    drivers = content_drivers + capability_drivers + lifecycle_drivers + provenance_drivers + impact_drivers
    return RiskResult(score=score, band=band_for_score(score), profile_version=RISK_PROFILE_VERSION, drivers=drivers, components=components)
