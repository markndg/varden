"""Applicability of a security contract to this Varden installation.

PROTECTED is returned only when every applicable required surface is ENFORCED,
existing policy proves the invariant, and required observability is actually
available. PARTIAL, NOT_ROUTED, and missing evidence never become PROTECTED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from varden.policy import RULE_META_KEYS

ENFORCED = "ENFORCED"
ENFORCED_GATEWAY = "ENFORCED VIA GATEWAY"
_GAP = frozenset({"PARTIAL", "OBSERVATIONAL", "UNCOVERED", "UNSUPPORTED", "NOT_ROUTED"})
_ENFORCED = frozenset({ENFORCED, ENFORCED_GATEWAY})
_PROVING_BUCKETS = frozenset({"block", "require_approval"})


@dataclass
class SurfaceFact:
    name: str
    applicable: bool
    coverage: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "applicable": self.applicable, "coverage": self.coverage}


@dataclass
class ObservabilityFact:
    name: str
    available: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "available": self.available}


@dataclass
class InstallationFacts:
    surfaces: dict[str, SurfaceFact] = field(default_factory=dict)
    observability: dict[str, ObservabilityFact] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)

    def surface(self, name: str) -> SurfaceFact:
        return self.surfaces.get(name) or SurfaceFact(name=name, applicable=False, coverage="UNKNOWN")


def policy_proves(policy: dict[str, Any] | None, proof: dict[str, Any] | None) -> bool:
    """True when an enforcing rule is equal to or broader than ``proof``.

    A narrower rule (extra predicates) does not prove the invariant. Warn and
    monitor do not prove it either: the side effect still happens.
    """
    if not proof or not isinstance(policy, dict):
        return False
    for bucket in _PROVING_BUCKETS:
        for rule in policy.get(bucket) or []:
            if not isinstance(rule, dict) or rule.get("enabled") is False:
                continue
            predicates = {
                key: value
                for key, value in rule.items()
                if key not in RULE_META_KEYS and value is not None and value != ""
            }
            if not predicates:
                continue
            if all(proof.get(key) == value for key, value in predicates.items()):
                return True
    return False


def assess_contract(contract: dict[str, Any], facts: InstallationFacts) -> dict[str, Any]:
    if contract.get("review_only") or not contract.get("id"):
        return {
            "result": "REVIEW",
            "surfaces": [],
            "observability": [],
            "policy_proves_invariant": False,
            "reasons": [contract.get("review_reason") or "No deterministic contract."],
            "fail_closed": True,
        }

    required = list(contract.get("required_surfaces") or [])
    surface_rows: list[dict[str, Any]] = []
    applicable: list[SurfaceFact] = []
    for name in required:
        fact = facts.surface(name)
        surface_rows.append(fact.to_dict())
        if fact.applicable:
            applicable.append(fact)

    obs_rows: list[dict[str, Any]] = []
    missing_obs: list[str] = []
    unknown_obs: list[str] = []
    for name in contract.get("required_observability") or []:
        fact = facts.observability.get(name) or ObservabilityFact(name=name, available=None)
        obs_rows.append(fact.to_dict())
        if fact.available is False:
            missing_obs.append(name)
        elif fact.available is None:
            unknown_obs.append(name)

    proves = policy_proves(facts.policy, contract.get("proof"))
    reasons: list[str] = []

    if not applicable:
        reasons.append(
            "None of the contract's required surfaces are applicable to this installation, "
            "so the attack path is not present here."
        )
        return _result("NOT_APPLICABLE", surface_rows, obs_rows, proves, reasons)

    gaps = [fact for fact in applicable if fact.coverage not in _ENFORCED]
    if gaps:
        for fact in gaps:
            reasons.append(_gap_reason(contract, fact))
        if missing_obs or unknown_obs:
            reasons.append(_obs_reason(missing_obs, unknown_obs))
        return _result("EXPOSED", surface_rows, obs_rows, proves, reasons)

    if not proves:
        reasons.append(
            "Applicable surfaces are enforced, but no block or require-approval rule "
            "proves the contract invariant. A narrower or warn-only rule is not proof."
        )
        if unknown_obs or missing_obs:
            reasons.append(_obs_reason(missing_obs, unknown_obs))
        return _result("EXPOSED", surface_rows, obs_rows, False, reasons)

    if missing_obs or unknown_obs:
        reasons.append(_obs_reason(missing_obs, unknown_obs))
        reasons.append("Refusing PROTECTED because required observability is not proven.")
        return _result("REVIEW", surface_rows, obs_rows, True, reasons)

    reasons.append("Applicable surfaces are ENFORCED, policy proves the invariant, and required observability is available.")
    return _result("PROTECTED", surface_rows, obs_rows, True, reasons)


def _gap_reason(contract: dict[str, Any], fact: SurfaceFact) -> str:
    invariant = contract.get("invariant") or contract.get("id")
    if fact.coverage == "NOT_ROUTED":
        return (
            f"The contract ({invariant}) requires control over {fact.name}, "
            f"but {fact.name} is applicable and not routed through enforcement."
        )
    if fact.coverage == "PARTIAL":
        return (
            f"{fact.name} coverage is PARTIAL. Partial coverage is not proof that "
            f"the invariant is enforced."
        )
    return (
        f"{fact.name} is applicable with coverage {fact.coverage}. "
        "That is not ENFORCED, so the invariant is not proven."
    )


def _obs_reason(missing: list[str], unknown: list[str]) -> str:
    parts = []
    if missing:
        parts.append("missing " + ", ".join(missing))
    if unknown:
        parts.append("unknown " + ", ".join(unknown))
    return "Required observability is " + " and ".join(parts) + "."


def _result(result: str, surfaces: list, observability: list, proves: bool, reasons: list[str]) -> dict[str, Any]:
    return {
        "result": result,
        "surfaces": surfaces,
        "observability": observability,
        "policy_proves_invariant": proves,
        "reasons": reasons,
        "fail_closed": result != "PROTECTED",
    }


def facts_from_attestation(
    attestation: dict[str, Any] | None,
    policy: dict[str, Any] | None,
    *,
    provenance_seen: bool | None,
    authority_seen: bool | None,
    classification_seen: bool | None,
) -> InstallationFacts:
    """Build installation facts from a coverage attestation.

    ``*_seen`` is True/False when telemetry settled the question, and None
    when there is no evidence either way.
    """
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for surface in (attestation or {}).get("surfaces") or []:
        if not isinstance(surface, dict):
            continue
        category = str(surface.get("category") or "")
        by_cat.setdefault(category, []).append(surface)
    facts = InstallationFacts(policy=dict(policy or {}))
    for category, rows in by_cat.items():
        applicable_rows = [row for row in rows if row.get("applicable") or row.get("status") in _ENFORCED or row.get("active")]
        applicable = bool(applicable_rows)
        coverage = "UNKNOWN"
        if applicable_rows:
            coverage = _worst([str(row.get("status") or "UNKNOWN") for row in applicable_rows])
        elif rows:
            coverage = str(rows[0].get("status") or "UNKNOWN")
        facts.surfaces[category] = SurfaceFact(name=category, applicable=applicable, coverage=coverage)
    facts.observability = {
        "provenance": ObservabilityFact("provenance", provenance_seen),
        "authority_flow": ObservabilityFact("authority_flow", authority_seen),
        "data_classification": ObservabilityFact("data_classification", classification_seen),
        "tool_invocation": ObservabilityFact("tool_invocation", _tool_obs(facts)),
        "destination": ObservabilityFact("destination", _destination_obs(facts)),
    }
    return facts


def _tool_obs(facts: InstallationFacts) -> bool | None:
    tools = facts.surfaces.get("tools")
    if tools is None:
        return None
    if not tools.applicable:
        return False
    return tools.coverage in _ENFORCED


def _destination_obs(facts: InstallationFacts) -> bool | None:
    http = facts.surfaces.get("http")
    mcp = facts.surfaces.get("mcp")
    if http is None and mcp is None:
        return None
    applicable = [row for row in (http, mcp) if row and row.applicable]
    if not applicable:
        return False
    return all(row.coverage in _ENFORCED for row in applicable)


def _worst(statuses: list[str]) -> str:
    order = {
        ENFORCED_GATEWAY: 0,
        ENFORCED: 0,
        "PARTIAL": 1,
        "OBSERVATIONAL": 2,
        "NOT_ROUTED": 3,
        "UNCOVERED": 4,
        "UNSUPPORTED": 5,
        "UNKNOWN": 6,
    }
    return sorted(statuses, key=lambda item: order.get(item, 99), reverse=True)[0]


def telemetry_flags(events: list[dict[str, Any]]) -> tuple[bool | None, bool | None, bool | None]:
    """Return provenance, authority, classification seen-flags from stored events."""
    if not events:
        return None, None, None
    provenance = False
    authority = False
    classification = False
    for event in events:
        action = event.get("action") if isinstance(event, dict) else None
        if not isinstance(action, dict):
            continue
        meta = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
        classifiers = action.get("classifiers") if isinstance(action.get("classifiers"), dict) else {}
        if meta.get("provenance") or meta.get("taint") or classifiers.get("provenance_untrusted") or classifiers.get("provenance_unknown"):
            provenance = True
        if (
            meta.get("authority")
            or meta.get("authority_flow")
            or classifiers.get("authority_violation")
            or classifiers.get("authority_escalation")
            or classifiers.get("confused_deputy")
        ):
            authority = True
        if classifiers:
            classification = True
    return provenance, authority, classification
