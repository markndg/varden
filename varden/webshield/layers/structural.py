from __future__ import annotations

import re
import unicodedata

from ..models import Finding, WebMCPToolDefinition
from ..textfields import schema_depth, schema_property_count, iter_schema_property_names

MAX_METADATA_BYTES = 32_000
MAX_SCHEMA_DEPTH = 8
MAX_SCHEMA_PROPERTIES = 200
MAX_FIELD_TEXT_LENGTH = 8_000

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,127}$")
_URL_SCHEME_RE = re.compile(r"\b(javascript|vbscript|data):", re.IGNORECASE)
_EXECUTABLE_HINT_RE = re.compile(r"<script\b|on\w+\s*=", re.IGNORECASE)


def _finding(rule_id: str, category: str, severity: str, field_path: str, evidence: str, explanation: str, remediation: str, confidence: float = 1.0) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        field_path=field_path,
        evidence=evidence[:240],
        explanation=explanation,
        confidence=confidence,
        remediation=remediation,
    )


def scan_structural(tool: WebMCPToolDefinition) -> list[Finding]:
    findings: list[Finding] = []

    if not tool.name or not tool.name.strip():
        findings.append(_finding(
            "WEBMCP-STRUCT-001", "structural", "medium", "name", "",
            "Tool has a missing or blank name.",
            "Give the tool a stable, descriptive, machine-safe name.",
        ))
    elif not _NAME_RE.match(tool.name):
        findings.append(_finding(
            "WEBMCP-STRUCT-002", "structural", "low", "name", tool.name,
            "Tool name contains unusual characters or is unusually long/short for a machine identifier.",
            "Use a short alphanumeric identifier (letters, digits, `_`, `-`, `.`).",
            confidence=0.7,
        ))

    if not tool.description or not tool.description.strip():
        findings.append(_finding(
            "WEBMCP-STRUCT-003", "structural", "medium", "description", "",
            "Tool has a missing or blank description, which prevents meaningful capability review.",
            "Add a description that accurately states the tool's purpose and side effects.",
        ))

    try:
        total_bytes = len(str(tool.to_dict()).encode("utf-8", errors="ignore"))
    except Exception:
        total_bytes = 0
    if total_bytes > MAX_METADATA_BYTES:
        findings.append(_finding(
            "WEBMCP-STRUCT-004", "resource_abuse", "high", "*", f"{total_bytes} bytes",
            f"Tool metadata is {total_bytes} bytes, exceeding the {MAX_METADATA_BYTES}-byte safety limit.",
            "Reduce metadata size; large registrations increase classification cost and can hide content.",
        ))

    for field_path, text in (("title", tool.title or ""), ("description", tool.description or "")):
        if len(text) > MAX_FIELD_TEXT_LENGTH:
            findings.append(_finding(
                "WEBMCP-STRUCT-005", "resource_abuse", "medium", field_path, f"{len(text)} chars",
                f"Field '{field_path}' is unusually long ({len(text)} characters).",
                "Keep user-facing tool text concise; excessive length is a common obfuscation vector.",
            ))

    depth = schema_depth(tool.input_schema or {})
    if depth > MAX_SCHEMA_DEPTH:
        findings.append(_finding(
            "WEBMCP-STRUCT-006", "resource_abuse", "high", "input_schema", f"depth={depth}",
            f"Input schema nesting depth is {depth}, exceeding the safety limit of {MAX_SCHEMA_DEPTH}.",
            "Flatten the schema; deeply nested schemas are expensive to validate and can hide fields.",
        ))

    prop_count = schema_property_count(tool.input_schema or {})
    if prop_count > MAX_SCHEMA_PROPERTIES:
        findings.append(_finding(
            "WEBMCP-STRUCT-007", "resource_abuse", "medium", "input_schema", f"properties={prop_count}",
            f"Input schema declares {prop_count} properties, exceeding the safety limit of {MAX_SCHEMA_PROPERTIES}.",
            "Reduce the number of schema properties to what the tool genuinely needs.",
        ))

    names = iter_schema_property_names(tool.input_schema or {})
    seen: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered in seen:
            findings.append(_finding(
                "WEBMCP-STRUCT-008", "structural", "low", f"input_schema.properties.{name}", name,
                f"Schema property name '{name}' collides case-insensitively with another property.",
                "Use distinct, unambiguous property names.",
                confidence=0.6,
            ))
        seen.add(lowered)

    for field_path, text in (("description", tool.description or ""), ("title", tool.title or "")):
        if _URL_SCHEME_RE.search(text) or _EXECUTABLE_HINT_RE.search(text):
            findings.append(_finding(
                "WEBMCP-STRUCT-009", "structural", "high", field_path, text[:120],
                f"Field '{field_path}' contains a script/executable-content pattern (javascript:/data:/<script>).",
                "Remove executable content from descriptive metadata; it has no legitimate purpose there.",
            ))

    for field_path, text in (("name", tool.name or ""), ("title", tool.title or ""), ("description", tool.description or "")):
        for ch in text:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                findings.append(_finding(
                    "WEBMCP-STRUCT-010", "structural", "medium", field_path, repr(ch),
                    f"Field '{field_path}' contains a malformed/unpaired Unicode surrogate.",
                    "Ensure text is valid, well-formed Unicode before registration.",
                ))
                break
            try:
                unicodedata.category(ch)
            except Exception:
                pass

    return findings
