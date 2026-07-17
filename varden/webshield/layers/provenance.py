from __future__ import annotations

from ..models import Finding, ScanContext, WebMCPToolDefinition


def scan_provenance(tool: WebMCPToolDefinition, context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if not context.https:
        findings.append(Finding(
            rule_id="WEBMCP-PROVENANCE-001",
            category="provenance",
            severity="medium",
            field_path="top_origin",
            evidence=tool.top_origin,
            explanation="Tool was registered from a non-HTTPS origin, which cannot be authenticated or protected from tampering in transit.",
            confidence=0.9,
            remediation="Serve the site over HTTPS before trusting its WebMCP tool surface.",
        ))

    if context.is_third_party_frame:
        findings.append(Finding(
            rule_id="WEBMCP-PROVENANCE-002",
            category="provenance",
            severity="medium",
            field_path="owner_origin",
            evidence=f"{tool.owner_origin} inside {tool.top_origin}",
            explanation="Tool was introduced by a third-party frame embedded in the top-level page, not the top-level origin itself.",
            confidence=0.75,
            remediation="Confirm the embedded origin is expected and trusted before allowing it to register tools.",
        ))

    if context.prior_violation_count > 0:
        findings.append(Finding(
            rule_id="WEBMCP-PROVENANCE-003",
            category="provenance",
            severity="high",
            field_path="owner_origin",
            evidence=f"{context.prior_violation_count} prior violation(s)",
            explanation="This origin has previously triggered Web Shield findings, which increases the weight given to new findings.",
            confidence=0.7,
            remediation="Review this origin's history before granting further trust.",
        ))

    if context.trust_state == "blocked":
        findings.append(Finding(
            rule_id="WEBMCP-PROVENANCE-004",
            category="provenance",
            severity="critical",
            field_path="owner_origin",
            evidence=tool.owner_origin,
            explanation="Origin is explicitly blocked by a local trust decision.",
            confidence=1.0,
            remediation="Remove the block if this was decided in error; otherwise no action is required.",
        ))
    elif context.trust_state == "trusted":
        findings.append(Finding(
            rule_id="WEBMCP-PROVENANCE-005",
            category="provenance",
            severity="info",
            field_path="owner_origin",
            evidence=tool.owner_origin,
            explanation="Origin is explicitly trusted by a local trust decision, which reduces (but does not eliminate) computed risk.",
            confidence=1.0,
            remediation="No action required.",
        ))

    return findings
