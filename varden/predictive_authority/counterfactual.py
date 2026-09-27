"""Counterfactual explanations — explanatory only, no side effects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .authority_delta import AuthorityDelta
from .hazardous import HazardousFinding
from .state import AuthorityState


@dataclass
class CounterfactualExplanation:
    action_summary: str
    current_capabilities: list[str] = field(default_factory=list)
    newly_reachable: list[str] = field(default_factory=list)
    newly_potential: list[str] = field(default_factory=list)
    hazardous_paths: list[str] = field(default_factory=list)
    shortest_trajectory_length: int | None = None
    existing_decision: str = "allow"
    predictive_recommendation: str = "allow"
    final_decision: str = "allow"
    mode: str = "observe"
    reason: str = ""
    provenance_evidence: list[str] = field(default_factory=list)
    irreversible: bool = False
    privilege_domains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_summary": self.action_summary,
            "current_capabilities": list(self.current_capabilities),
            "newly_reachable": list(self.newly_reachable),
            "newly_potential": list(self.newly_potential),
            "hazardous_paths": list(self.hazardous_paths),
            "shortest_trajectory_length": self.shortest_trajectory_length,
            "existing_decision": self.existing_decision,
            "predictive_recommendation": self.predictive_recommendation,
            "final_decision": self.final_decision,
            "mode": self.mode,
            "reason": self.reason,
            "provenance_evidence": list(self.provenance_evidence),
            "irreversible": self.irreversible,
            "privilege_domains": list(self.privilege_domains),
        }

    def render(self) -> str:
        lines = [
            "VARDEN PREDICTIVE AUTHORITY — COUNTERFACTUAL",
            "",
            f"Action: {self.action_summary}",
            "",
            "Current authority:",
        ]
        if self.current_capabilities:
            for c in self.current_capabilities[:12]:
                lines.append(f"  - {c}")
        else:
            lines.append("  - (none recorded)")
        lines.append("")
        lines.append("Newly reachable authority:")
        if self.newly_reachable or self.newly_potential:
            for c in self.newly_reachable:
                lines.append(f"  - {c} (confirmed)")
            for c in self.newly_potential:
                lines.append(f"  - {c} (potential)")
        else:
            lines.append("  - (none)")
        if self.privilege_domains:
            lines.append("")
            lines.append("New privileged domains: " + ", ".join(self.privilege_domains))
        if self.hazardous_paths:
            lines.append("")
            lines.append("Hazardous path:")
            for p in self.hazardous_paths[:3]:
                lines.append(f"  {p}")
            if self.shortest_trajectory_length is not None:
                lines.append(f"Shortest hazardous trajectory: {self.shortest_trajectory_length} transitions")
        if self.irreversible:
            lines.append("")
            lines.append("Irreversibility: proposed action or newly reachable sink is irreversible")
        lines.extend(
            [
                "",
                f"Existing decision: {self.existing_decision.upper()}",
                f"Predictive recommendation: {self.predictive_recommendation.upper()}",
                f"Final decision: {self.final_decision.upper()}"
                + (f" ({self.mode} mode)" if self.mode == "observe" else ""),
            ]
        )
        if self.reason:
            lines.extend(["", f"Reason: {self.reason}"])
        if self.provenance_evidence:
            lines.append("")
            lines.append("Provenance evidence:")
            for e in self.provenance_evidence[:8]:
                lines.append(f"  - {e}")
        return "\n".join(lines) + "\n"


def build_explanation(
    *,
    action_summary: str,
    before: AuthorityState,
    delta: AuthorityDelta,
    findings: list[HazardousFinding],
    existing_decision: str,
    predictive_recommendation: str,
    final_decision: str,
    mode: str,
) -> CounterfactualExplanation:
    current = sorted({c.name for c in before.confirmed_capabilities()})
    newly = sorted({c.name for c in delta.confirmed_added()})
    potential = sorted({c.name for c in delta.potential_added()})
    paths = [f.path.to_dict()["display"] for f in findings]
    shortest = None
    if findings:
        shortest = min(f.path.length for f in findings)

    reason_parts: list[str] = []
    if findings:
        reason_parts.append(f"Hazardous path pattern '{findings[0].pattern}' detected.")
    if delta.added_privilege_domains:
        reason_parts.append(
            "New privilege domain(s): " + ", ".join(delta.added_privilege_domains) + "."
        )
    if delta.potential_added() and not delta.confirmed_added():
        reason_parts.append("Potential (unconfirmed) capabilities expanded.")
    if delta.added_irreversible_actions:
        reason_parts.append("Irreversible action reachable.")
    if not reason_parts and delta.authority_expands:
        reason_parts.append("Authority graph expanded.")
    if not reason_parts:
        reason_parts.append("No significant authority expansion.")

    prov = list(before.provenance_refs[-8:])

    return CounterfactualExplanation(
        action_summary=action_summary,
        current_capabilities=current,
        newly_reachable=newly,
        newly_potential=potential,
        hazardous_paths=paths,
        shortest_trajectory_length=shortest,
        existing_decision=existing_decision,
        predictive_recommendation=predictive_recommendation,
        final_decision=final_decision,
        mode=mode,
        reason=" ".join(reason_parts),
        provenance_evidence=prov,
        irreversible=bool(delta.added_irreversible_actions),
        privilege_domains=list(delta.added_privilege_domains),
    )
