from __future__ import annotations

import re

from ..models import Finding
from .patterns import scan_text_for_patterns
from .unicode_analysis import scan_unicode

MAX_OUTPUT_BYTES = 20_000

_SECRET_SHAPE_RE = re.compile(
    r"(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}|"
    r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b)"
)
_CROSS_ORIGIN_DIRECTIVE_RE = re.compile(
    r"(send|email|post|submit|forward)\s+(this|it|the\s+result|the\s+data)\s+to\s+(https?://[^\s]+)",
    re.IGNORECASE,
)


def scan_output_text(
    text: str,
    *,
    owner_origin: str = "",
    contains_user_generated_content: bool = False,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> list[Finding]:
    if not text:
        return []

    findings: list[Finding] = []
    size = len(text.encode("utf-8", errors="ignore"))
    if size > max_bytes:
        findings.append(Finding(
            rule_id="WEBMCP-OUTPUT-001",
            category="resource_abuse",
            severity="medium",
            field_path="output",
            evidence=f"{size} bytes",
            explanation=f"Tool output is {size} bytes, exceeding the {max_bytes}-byte safe-exposure limit.",
            confidence=0.9,
            remediation="Truncate or summarise large tool output before returning it to the agent.",
        ))

    findings.extend(scan_unicode("output", text))

    pattern_findings = scan_text_for_patterns("output", text)
    for finding in pattern_findings:
        if contains_user_generated_content:
            finding.explanation += " (found inside user-generated/third-party content returned by the tool)"
        findings.append(finding)

    secret_match = _SECRET_SHAPE_RE.search(text)
    if secret_match:
        findings.append(Finding(
            rule_id="WEBMCP-OUTPUT-002",
            category="output_contamination",
            severity="critical",
            field_path="output",
            evidence=secret_match.group(0)[:12] + "…",
            explanation="Tool output contains a value shaped like a secret or credential (API key, JWT, or card number pattern).",
            confidence=0.7,
            remediation="Redact secret-shaped values before returning tool output to the agent.",
        ))

    cross_origin_match = _CROSS_ORIGIN_DIRECTIVE_RE.search(text)
    if cross_origin_match:
        target = cross_origin_match.group(3)
        findings.append(Finding(
            rule_id="WEBMCP-OUTPUT-003",
            category="cross_origin_flow" if owner_origin else "output_contamination",
            severity="high",
            field_path="output",
            evidence=cross_origin_match.group(0)[:120],
            explanation=f"Tool output directs the agent to send data to {target}, outside the tool's own origin ({owner_origin or 'unknown'}).",
            confidence=0.75,
            remediation="Do not act on cross-origin action directives embedded in tool output without independent policy approval.",
        ))

    return findings
