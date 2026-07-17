from __future__ import annotations

import re

from varden.redaction import SENSITIVE_FIELD_RE as _SENSITIVE_FIELD_RE

from ..models import CapabilityProfile, Finding, WebMCPToolDefinition
from ..textfields import iter_schema_property_names

_PAYMENT_HINT_RE = re.compile(r"\b(pay|payment|purchase|buy|invoice|checkout|wallet|crypto|refund|transfer|withdraw)\b", re.IGNORECASE)
_CREDENTIAL_HINT_RE = re.compile(r"\b(password|credential|secret|api[_\-]?key|private[_\-]?key|auth(entication)?[_\-]?token|cookie|session[_\-]?token)\b", re.IGNORECASE)
_DESTRUCTIVE_HINT_RE = re.compile(r"\b(delete|remove|destroy|drop|purge|wipe|erase|terminate|format)\b", re.IGNORECASE)
_MUTATING_HINT_RE = re.compile(r"\b(create|update|modify|write|submit|send|purchase|buy|transfer|withdraw|register|cancel|sign|post|delete|remove)\b", re.IGNORECASE)
_READONLY_HINT_RE = re.compile(r"\b(read|get|fetch|list|search|lookup|view|show|retrieve|query|display)\b", re.IGNORECASE)
_CLIPBOARD_HINT_RE = re.compile(r"\bclipboard\b", re.IGNORECASE)
_FILESYSTEM_HINT_RE = re.compile(r"\b(filesystem|file\s+system|directory|read\s+file|write\s+file)\b", re.IGNORECASE)
_NETWORK_HINT_RE = re.compile(r"\b(https?://|webhook|fetch\(|xhr|network\s+request)\b", re.IGNORECASE)
_NEGATION_RE = re.compile(r"\b(does\s+not|do\s+not|doesn't|don't|never|cannot|can't|without|no\s+longer|not\s+able\s+to)\b", re.IGNORECASE)
_NEGATION_WINDOW = 28


def _has_unnegated_match(pattern: re.Pattern, text: str) -> bool:
    """True if ``pattern`` matches somewhere not immediately preceded by a negation.

    A short lookback window (e.g. "does not modify any data") is enough to
    avoid the common false-positive of matching a mutating/destructive verb
    that the text is actually disclaiming, without needing full NLP.
    """

    for match in pattern.finditer(text):
        window_start = max(0, match.start() - _NEGATION_WINDOW)
        preceding = text[window_start:match.start()]
        if not _NEGATION_RE.search(preceding):
            return True
    return False


def infer_capability_profile(tool: WebMCPToolDefinition) -> CapabilityProfile:
    text = " ".join(filter(None, [tool.name, tool.title, tool.description]))
    sensitive_fields = sorted({
        name for name in iter_schema_property_names(tool.input_schema or {})
        if _SENSITIVE_FIELD_RE.search(name)
    })
    annotations = tool.annotations or {}
    declared_readonly = None
    for key in ("readOnlyHint", "read_only_hint", "readonly"):
        if key in annotations:
            declared_readonly = bool(annotations[key])
            break
    destructive_hint = bool(annotations.get("destructiveHint") or annotations.get("destructive_hint"))
    mutates_by_text = _has_unnegated_match(_MUTATING_HINT_RE, text) or _has_unnegated_match(_DESTRUCTIVE_HINT_RE, text)
    return CapabilityProfile(
        mutates_state=bool(destructive_hint or mutates_by_text),
        declared_readonly=declared_readonly,
        mentions_payment=bool(_PAYMENT_HINT_RE.search(text)),
        mentions_credential=bool(_CREDENTIAL_HINT_RE.search(text)),
        mentions_destructive=bool(destructive_hint or _has_unnegated_match(_DESTRUCTIVE_HINT_RE, text)),
        mentions_clipboard=bool(_CLIPBOARD_HINT_RE.search(text)),
        mentions_filesystem=bool(_FILESYSTEM_HINT_RE.search(text)),
        mentions_network=bool(_NETWORK_HINT_RE.search(text)),
        sensitive_schema_fields=sensitive_fields,
    )


def scan_capability_mismatch(tool: WebMCPToolDefinition, capability: CapabilityProfile) -> list[Finding]:
    findings: list[Finding] = []

    if capability.declared_readonly is True and (capability.mentions_destructive or capability.mutates_state):
        findings.append(Finding(
            rule_id="WEBMCP-CAPABILITY-001",
            category="capability_mismatch",
            severity="high",
            field_path="annotations.readOnlyHint",
            evidence=f"readOnlyHint=true; description={ (tool.description or '')[:100] }",
            explanation="Tool declares readOnlyHint=true but its description or schema indicates a mutating or destructive operation.",
            confidence=0.85,
            remediation="Correct the readOnlyHint annotation or remove the mutating capability; the two must agree.",
        ))

    purpose_text = " ".join(filter(None, [tool.name, tool.title, tool.description])).lower()
    if capability.sensitive_schema_fields and not (capability.mentions_payment or capability.mentions_credential):
        findings.append(Finding(
            rule_id="WEBMCP-CAPABILITY-002",
            category="capability_mismatch",
            severity="high",
            field_path="input_schema",
            evidence=", ".join(capability.sensitive_schema_fields[:5]),
            explanation=(
                f"Tool requests sensitive field(s) ({', '.join(capability.sensitive_schema_fields[:5])}) "
                "that are unrelated to its declared purpose."
            ),
            confidence=0.95,
            remediation="Remove sensitive fields that are not required for the tool's stated purpose, or update the description to justify them.",
        ))

    readonly_claimed = bool(_READONLY_HINT_RE.search(purpose_text)) and not _MUTATING_HINT_RE.search(purpose_text)
    recipient_like = any(name.lower() in {"recipient", "to", "destination_account", "beneficiary"} for name in iter_schema_property_names(tool.input_schema or {}))
    if readonly_claimed and (recipient_like or capability.mentions_credential):
        findings.append(Finding(
            rule_id="WEBMCP-CAPABILITY-003",
            category="capability_mismatch",
            severity="medium",
            field_path="input_schema",
            evidence=purpose_text[:100],
            explanation="Tool's title/description reads as a read-only lookup, but its schema includes recipient or credential-shaped fields typical of a state-changing action.",
            confidence=0.6,
            remediation="Clarify the tool's true capability in its description and annotations.",
        ))

    return findings
