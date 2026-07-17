from __future__ import annotations

from .layers.capability import infer_capability_profile, scan_capability_mismatch
from .layers.lifecycle import scan_lifecycle
from .layers.output_scan import scan_output_text
from .layers.patterns import scan_instruction_patterns
from .layers.provenance import scan_provenance
from .layers.structural import scan_structural
from .layers.unicode_analysis import scan_unicode_for_tool
from .models import Finding, RiskResult, ScanContext, ScanResult, WebMCPToolDefinition
from .risk import compute_risk


def scan_registration(tool: WebMCPToolDefinition, context: ScanContext | None = None) -> ScanResult:
    """Run all registration-time classifier layers and produce an explainable score.

    Works with no context at all (static CLI scan of a JSON file) — lifecycle
    and provenance layers simply degrade to "no evidence" rather than
    fabricating findings, which is what lets ``varden web-shield scan`` work
    without a browser or a running session.
    """

    context = context or ScanContext()
    findings: list[Finding] = []
    findings.extend(scan_structural(tool))
    findings.extend(scan_unicode_for_tool(tool))
    findings.extend(scan_instruction_patterns(tool))

    capability = infer_capability_profile(tool)
    findings.extend(scan_capability_mismatch(tool, capability))
    findings.extend(scan_lifecycle(tool, context))
    findings.extend(scan_provenance(tool, context))

    exact_hash, canonical_hash = tool.compute_hashes()
    sensitive_data_involved = bool(capability.sensitive_schema_fields) or capability.mentions_credential
    cross_origin_implicated = context.is_third_party_frame

    risk = compute_risk(
        findings,
        mutates_state=capability.mutates_state,
        sensitive_data_involved=sensitive_data_involved,
        cross_origin_implicated=cross_origin_implicated,
        trust_state=context.trust_state,
    )
    return ScanResult(
        tool=tool,
        findings=findings,
        risk=risk,
        capability=capability,
        exact_hash=exact_hash,
        canonical_hash=canonical_hash,
    )


def scan_output(
    text: str,
    *,
    owner_origin: str = "",
    contains_user_generated_content: bool = False,
    trust_state: str | None = None,
) -> tuple[list[Finding], RiskResult]:
    """Run output-time (Layer 7) scanning and produce a risk score for the result."""

    findings = scan_output_text(text, owner_origin=owner_origin, contains_user_generated_content=contains_user_generated_content)
    cross_origin_implicated = any(f.category == "cross_origin_flow" for f in findings)
    sensitive_data_involved = any(f.rule_id == "WEBMCP-OUTPUT-002" for f in findings)
    risk = compute_risk(
        findings,
        mutates_state=False,
        sensitive_data_involved=sensitive_data_involved,
        cross_origin_implicated=cross_origin_implicated,
        trust_state=trust_state,
    )
    return findings, risk
