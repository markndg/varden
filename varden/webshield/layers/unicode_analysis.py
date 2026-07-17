from __future__ import annotations

import base64
import re
import unicodedata

from ..models import Finding, WebMCPToolDefinition
from ..textfields import iter_text_fields

ZERO_WIDTH_CHARS = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD}
BIDI_OVERRIDE_CHARS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
UNUSUAL_WHITESPACE = {0x00A0, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x3000}

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_MARKUP_RE = re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)", re.IGNORECASE)
_DATA_URL_RE = re.compile(r"data:[a-zA-Z0-9/+.\-]+;base64,[A-Za-z0-9+/=]{16,}")
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")

_INJECTION_HINTS = (
    "ignore", "disregard", "system", "instruction", "prompt", "override",
    "secret", "password", "token", "wallet", "private key", "do not tell",
)


def _excerpt(text: str, index: int, radius: int = 24) -> str:
    start = max(0, index - radius)
    end = min(len(text), index + radius)
    return text[start:end]


def strip_hidden_characters(text: str) -> str:
    """Remove zero-width/bidi/control characters only (no case-folding or NFKC).

    Safe to apply unconditionally when sanitising text for display, unlike
    :func:`normalize_for_analysis` which is analysis-only and must never be
    substituted for the real sanitised output.
    """

    if not text:
        return text
    return "".join(
        ch for ch in text
        if ord(ch) not in ZERO_WIDTH_CHARS and ord(ch) not in BIDI_OVERRIDE_CHARS
        and not (unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\n\t\r")
    )


def normalize_for_analysis(text: str) -> str:
    """NFKC-normalise and drop invisible characters for pattern matching.

    Always used alongside (never instead of) the original text: findings keep
    the original excerpt as evidence.
    """

    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in normalized if ord(ch) not in ZERO_WIDTH_CHARS and ord(ch) not in BIDI_OVERRIDE_CHARS)


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    first = name.split(" ")[0]
    return first


def _finding(rule_id: str, severity: str, field_path: str, evidence: str, explanation: str, remediation: str, confidence: float = 1.0) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="unicode_obfuscation",
        severity=severity,
        field_path=field_path,
        evidence=evidence[:200],
        explanation=explanation,
        confidence=confidence,
        remediation=remediation,
    )


def scan_unicode(field_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    zero_width_hits = [i for i, ch in enumerate(text) if ord(ch) in ZERO_WIDTH_CHARS]
    if zero_width_hits:
        findings.append(_finding(
            "WEBMCP-UNICODE-001", "high", field_path, _excerpt(text, zero_width_hits[0]),
            f"Field contains {len(zero_width_hits)} zero-width/invisible character(s), often used to hide or split text.",
            "Remove zero-width characters; they have no legitimate display purpose in tool metadata.",
        ))

    bidi_hits = [i for i, ch in enumerate(text) if ord(ch) in BIDI_OVERRIDE_CHARS]
    if bidi_hits:
        findings.append(_finding(
            "WEBMCP-UNICODE-002", "critical", field_path, _excerpt(text, bidi_hits[0]),
            "Field contains bidirectional override/isolate characters, which can visually reorder text to hide its true meaning.",
            "Remove bidirectional control characters from tool metadata.",
        ))

    control_hits = [
        i for i, ch in enumerate(text)
        if unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\n\t\r" and ord(ch) not in ZERO_WIDTH_CHARS and ord(ch) not in BIDI_OVERRIDE_CHARS
    ]
    if control_hits:
        findings.append(_finding(
            "WEBMCP-UNICODE-003", "medium", field_path, _excerpt(text, control_hits[0]),
            f"Field contains {len(control_hits)} non-printable control character(s).",
            "Strip control characters from user-facing metadata.",
        ))

    unusual_ws = [i for i, ch in enumerate(text) if ord(ch) in UNUSUAL_WHITESPACE]
    if len(unusual_ws) >= 3:
        findings.append(_finding(
            "WEBMCP-UNICODE-004", "low", field_path, _excerpt(text, unusual_ws[0]),
            "Field contains repeated unusual whitespace characters (non-breaking/line-separator/ideographic space).",
            "Use standard ASCII whitespace in tool metadata.",
            confidence=0.6,
        ))

    scripts = {_script_of(ch) for ch in text if ch.isalpha()}
    letter_scripts = {s for s in scripts if s not in {"UNKNOWN"}}
    if len(letter_scripts) >= 3:
        findings.append(_finding(
            "WEBMCP-UNICODE-005", "medium", field_path, text[:80],
            f"Field mixes {len(letter_scripts)} distinct Unicode scripts, a common homoglyph/confusable-identifier technique.",
            "Use a single consistent script for identifiers and display text.",
            confidence=0.55,
        ))

    comment_match = _HTML_COMMENT_RE.search(text)
    if comment_match:
        findings.append(_finding(
            "WEBMCP-UNICODE-006", "medium", field_path, comment_match.group(0)[:120],
            "Field contains an HTML comment, which can hide instructions from a rendered UI while remaining machine-readable.",
            "Remove HTML comments from tool metadata.",
        ))

    hidden_markup = _HIDDEN_MARKUP_RE.search(text)
    if hidden_markup:
        findings.append(_finding(
            "WEBMCP-UNICODE-007", "medium", field_path, hidden_markup.group(0),
            "Field contains CSS commonly used to visually hide content from a human reviewer.",
            "Remove hidden-content styling from tool metadata.",
        ))

    data_url = _DATA_URL_RE.search(text)
    if data_url:
        findings.append(_finding(
            "WEBMCP-UNICODE-008", "high", field_path, data_url.group(0)[:80],
            "Field contains a base64 data: URL, which can smuggle arbitrary encoded content.",
            "Do not embed data: URLs in descriptive tool metadata.",
        ))

    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        decoded_text = _try_decode_base64(candidate)
        if decoded_text and any(hint in decoded_text.lower() for hint in _INJECTION_HINTS):
            findings.append(_finding(
                "WEBMCP-UNICODE-009", "high", field_path, candidate[:60],
                "Field contains a Base64-encoded fragment that decodes to instruction-like language.",
                "Do not encode instructions inside tool metadata; keep metadata in plain, reviewable text.",
                confidence=0.8,
            ))
        elif decoded_text:
            findings.append(_finding(
                "WEBMCP-UNICODE-010", "low", field_path, candidate[:60],
                "Field contains a long Base64-looking fragment of unclear purpose.",
                "Avoid opaque encoded content in tool metadata unless required and documented.",
                confidence=0.4,
            ))

    return findings


def _try_decode_base64(candidate: str) -> str | None:
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
        text = raw.decode("utf-8")
    except Exception:
        return None
    printable = sum(1 for ch in text if ch.isprintable())
    if not text or printable / max(1, len(text)) < 0.85:
        return None
    return text


def scan_unicode_for_tool(tool: WebMCPToolDefinition) -> list[Finding]:
    findings: list[Finding] = []
    for field_path, text in iter_text_fields(tool):
        findings.extend(scan_unicode(field_path, text))
    return findings
