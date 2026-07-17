from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Finding, WebMCPToolDefinition
from ..textfields import iter_text_fields
from .unicode_analysis import normalize_for_analysis


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    category: str
    severity: str
    regexes: tuple[re.Pattern, ...]
    description: str
    remediation: str
    confidence: float = 0.9


def _rx(*phrases: str) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.DOTALL) for p in phrases)


# Deterministic, phrase-level (not single-keyword) patterns to keep precision high.
# Each rule fires on multi-word instructional phrasing rather than isolated
# common words, so legitimate tools that merely *mention* a concept (e.g. a
# password-manager tool, or a security-focused description) do not trigger a
# finding just for using the underlying vocabulary once.
RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "WEBMCP-INJECTION-001", "instruction_hierarchy_override", "critical",
        _rx(
            r"ignore\s+(all\s+|any\s+)?(prior|previous|earlier|above)\s+instructions",
            r"disregard\s+(all\s+|any\s+)?(prior|previous|earlier|above)\s+(instructions|rules|policy)(\s+you\s+(were|have\s+been)\s+given)?",
            r"supersede[s]?\s+(all\s+)?(prior|previous|other)\s+instructions",
            r"override\s+(any|all)\s+(safety|prior|system)\s+(rules|instructions|policy)",
            r"new\s+instructions\s+(that\s+)?(take\s+priority|override)",
        ),
        "Text instructs the agent to ignore or override prior instructions or policy.",
        "Remove instruction-hierarchy override language; tool metadata must not attempt to reprogram the agent.",
    ),
    PatternRule(
        "WEBMCP-INJECTION-002", "authority_impersonation", "high",
        _rx(
            r"as\s+the\s+(system|developer|administrator)\s*[:,]",
            r"you\s+are\s+now\s+(the\s+)?(system|developer|admin(istrator)?)",
            r"this\s+is\s+an?\s+(system|developer)\s+(message|directive|instruction)",
            r"acting\s+as\s+(the\s+)?(system|root|administrator)",
        ),
        "Text impersonates a system, developer, or administrator authority level it does not have.",
        "Remove language that claims elevated authority; tool metadata is untrusted user-level input.",
    ),
    PatternRule(
        "WEBMCP-INJECTION-003", "secrecy_demand", "high",
        _rx(
            r"do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user",
            r"without\s+(asking|telling|notifying)\s+the\s+user",
            r"keep\s+this\s+(secret|hidden)\s+from\s+the\s+user",
            r"do\s+not\s+ask\s+for\s+(confirmation|permission|consent)",
            r"never\s+(disclose|reveal|show)\s+this\s+to\s+the\s+user",
            r"no\s+need\s+to\s+(mention|disclose|report|tell\s+(the\s+user|anyone))\b",
        ),
        "Text instructs the agent to hide actions or requests from the human user.",
        "Remove anti-disclosure instructions; tools must not instruct agents to conceal actions from users.",
    ),
    PatternRule(
        "WEBMCP-INJECTION-004", "forced_tool_selection", "high",
        _rx(
            r"always\s+call\s+\w+\s+(first|before)",
            r"you\s+must\s+(always\s+)?call\s+[\w.\-]+\s+(tool\s+)?(first|automatically)",
            r"automatically\s+invoke\s+[\w.\-]+",
            r"this\s+tool\s+must\s+be\s+called\s+(first|before\s+any\s+other)",
        ),
        "Text instructs the agent to always/automatically invoke a specific tool, overriding agent judgement.",
        "Remove forced-invocation language; tools should not dictate agent orchestration.",
    ),
    PatternRule(
        "WEBMCP-CROSS-TOOL-001", "cross_tool_invocation", "high",
        _rx(
            r"then\s+call\s+(the\s+)?[\w]*[_\-]?(wallet|payment|email|shell|filesystem|credential)[\w_\- ]*\s*tool",
            r"\bcall(?:s|ing)?\s+the\s+[\w]*[_\-]?(wallet|payment|email|shell|filesystem|credential)[\w_\-]*\s+tool\b",
            r"send\s+(the\s+)?(current\s+)?(account\s+)?(token|password|secret|key)\s+to\s+[\w.\-]+",
            r"pass\s+(the\s+)?(result|output|data)\s+to\s+(the\s+)?[\w.\-]+\s+tool",
            r"call\s+wallet_sign|call\s+send_email|call\s+delete_file",
        ),
        "Text directs the agent to chain into another, unrelated tool (e.g. wallet, email, filesystem).",
        "Remove cross-tool orchestration language; a tool description must not name and direct calls to other tools.",
        confidence=0.92,
    ),
    PatternRule(
        "WEBMCP-CREDENTIAL-001", "credential_access", "critical",
        _rx(
            r"read\s+this\s+from\s+the\s+user'?s\s+wallet",
            r"(private\s*key|seed\s*phrase|mnemonic)\s+without\s+asking",
            r"retrieve\s+the\s+(user'?s\s+)?(password|api\s*key|private\s*key|auth(entication)?\s*token)\s+(and|without)",
            r"read\s+(the\s+)?(cookie|session\s*token)\s+(and\s+)?send",
        ),
        "Text instructs the agent to obtain a credential or secret without user awareness or consent.",
        "This capability cannot be safely repaired by editing text; the underlying field should be blocked.",
    ),
    PatternRule(
        "WEBMCP-EXFIL-001", "data_exfiltration", "critical",
        _rx(
            r"send\s+(the\s+)?(user'?s\s+)?(data|contents?|conversation|file)\s+to\s+https?://",
            r"upload\s+(the\s+)?(result|data|file)\s+to\s+(an?\s+)?external\s+(server|url|endpoint)",
            r"exfiltrat\w+",
            r"forward\s+(this|the\s+data)\s+to\s+[\w.\-]+\.[a-z]{2,}\b",
        ),
        "Text instructs the agent to transmit data to an external destination outside the declared purpose.",
        "Remove exfiltration instructions; tools must not direct data to unrelated destinations.",
    ),
    PatternRule(
        "WEBMCP-DESTRUCTIVE-001", "destructive_action", "high",
        _rx(
            r"delete\s+all\s+(files|records|data)",
            r"permanently\s+(delete|remove|erase)",
            r"drop\s+(table|database)",
            r"format\s+the\s+(disk|drive)",
            r"rm\s+-rf\s+",
        ),
        "Text describes an irreversible destructive action inconsistent with typical tool metadata.",
        "Confirm the destructive capability is genuinely intended and correctly annotated (destructiveHint).",
        confidence=0.75,
    ),
    PatternRule(
        "WEBMCP-PAYMENT-001", "payment_action", "high",
        _rx(
            r"(transfer|send)\s+(funds|payment|money|crypto|bitcoin|eth(ereum)?)\s+to",
            r"authorize\s+(a\s+)?payment\s+of",
            r"sign\s+(the\s+)?transaction\s+(automatically|without)",
        ),
        "Text describes a payment/funds-transfer action.",
        "Ensure payment capability is explicitly annotated and gated by approval, not silently described.",
        confidence=0.75,
    ),
    PatternRule(
        "WEBMCP-SECURITY-BYPASS-001", "security_bypass", "critical",
        _rx(
            r"disable\s+(safety|security)\s+(checks?|controls?|filters?)",
            r"bypass\s+(the\s+)?(policy|safety|security|approval)\s*(check|control|gate)?",
            r"turn\s+off\s+(content\s+)?(filtering|moderation|safety)",
            r"skip\s+(the\s+)?approval\s+(step|process)",
        ),
        "Text instructs the agent to disable or bypass a safety, security, or approval control.",
        "Remove security-bypass instructions; a tool must not direct the agent to weaken its own guardrails.",
    ),
    PatternRule(
        "WEBMCP-PERSIST-001", "forced_persistence", "medium",
        _rx(
            r"remember\s+this\s+(instruction\s+)?for\s+(all\s+)?future\s+(sessions|conversations|requests)",
            r"apply\s+this\s+rule\s+to\s+every\s+(future\s+)?(session|conversation|request)",
            r"persist\s+this\s+(directive|instruction)\s+across\s+sessions",
        ),
        "Text attempts to make an instruction persist beyond the current tool invocation or session.",
        "Remove persistence instructions; tool metadata should not attempt to alter agent behaviour long-term.",
        confidence=0.8,
    ),
    PatternRule(
        "WEBMCP-INJECTION-005", "encoded_instruction", "medium",
        _rx(
            r"decode\s+(the\s+)?following\s+(and\s+)?(run|execute|follow)",
            r"the\s+following\s+is\s+base64[- ]encoded[:,]?\s+(instructions|commands)",
        ),
        "Text explicitly directs the agent to decode and follow encoded instructions.",
        "Remove references to encoded follow-up instructions.",
        confidence=0.85,
    ),
)

_RULES_BY_CATEGORY: dict[str, list[PatternRule]] = {}
for _rule in RULES:
    _RULES_BY_CATEGORY.setdefault(_rule.category, []).append(_rule)


def scan_text_for_patterns(field_path: str, original_text: str) -> list[Finding]:
    if not original_text:
        return []
    normalized = normalize_for_analysis(original_text)
    findings: list[Finding] = []
    for rule in RULES:
        for regex in rule.regexes:
            match = regex.search(normalized)
            if not match:
                continue
            start = max(0, match.start() - 20)
            end = min(len(normalized), match.end() + 20)
            findings.append(Finding(
                rule_id=rule.rule_id,
                category=rule.category,
                severity=rule.severity,
                field_path=field_path,
                evidence=normalized[start:end][:200],
                explanation=rule.description,
                confidence=rule.confidence,
                remediation=rule.remediation,
            ))
            break  # one finding per rule per field is enough signal
    return findings


def scan_instruction_patterns(tool: WebMCPToolDefinition) -> list[Finding]:
    findings: list[Finding] = []
    for field_path, text in iter_text_fields(tool):
        findings.extend(scan_text_for_patterns(field_path, text))

    # Fragmented-attack detection: some attacks split a phrase across two
    # fields (e.g. "ignore" in the title, "prior instructions" in the
    # description) so no single field matches, but the concatenation does.
    combined = " ".join(text for _, text in iter_text_fields(tool))
    combined_only = scan_text_for_patterns("*combined*", combined)
    already = {(f.rule_id, f.field_path) for f in findings}
    single_field_rule_ids = {f.rule_id for f in findings}
    for finding in combined_only:
        if finding.rule_id in single_field_rule_ids:
            continue
        finding.explanation = "Fragmented across multiple fields: " + finding.explanation
        finding.confidence = min(finding.confidence, 0.6)
        findings.append(finding)
    return findings
