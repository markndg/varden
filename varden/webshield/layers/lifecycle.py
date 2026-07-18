from __future__ import annotations

import unicodedata

from ..models import Finding, ScanContext, WebMCPToolDefinition

LATE_SESSION_THRESHOLD_SECONDS = 60.0
REGISTRATION_BURST_THRESHOLD = 5
NEAR_DUPLICATE_MAX_DISTANCE = 2

# A deliberately small, high-precision table of characters from other scripts
# that are commonly used as visual look-alikes for Latin letters in
# homoglyph/"confusable identifier" attacks (docs/web-shield-hardening-review.md
# #6, objective #10 "use confusable tool names"). This is intentionally not a
# full Unicode confusables database (that would need a bundled data file and
# more maintenance than this project takes on) — it is a bounded, deterministic
# projection that catches the common, high-confidence cases: whole-script
# substitution of Cyrillic/Greek look-alikes for Latin letters.
_CONFUSABLE_MAP = {
    # Cyrillic -> Latin
    "а": "a", "А": "a", "е": "e", "Е": "e", "о": "o", "О": "o", "р": "p", "Р": "p",
    "с": "c", "С": "c", "х": "x", "Х": "x", "у": "y", "У": "y", "к": "k", "К": "k",
    "м": "m", "М": "m", "н": "h", "Н": "h", "т": "t", "Т": "t", "в": "b", "В": "b",
    "і": "i", "І": "i", "ѕ": "s", "Ѕ": "s", "ј": "j", "Ј": "j", "ԛ": "q", "д": "d",
    # Greek -> Latin
    "α": "a", "Α": "a", "ο": "o", "Ο": "o", "ρ": "p", "Ρ": "p", "ν": "v", "Ν": "n",
    "υ": "u", "Υ": "y", "τ": "t", "Τ": "t", "χ": "x", "Χ": "x", "ι": "i", "Ι": "i",
    "κ": "k", "Κ": "k", "β": "b", "Β": "b", "η": "n", "Η": "h",
}


def _confusable_skeleton(text: str) -> str:
    """Project ``text`` onto a Latin-letter "skeleton" for confusable-identifier
    comparison. Two names that render near-identically to a human but use
    different Unicode scripts collapse to the same skeleton; two names that
    are genuinely different (even if superficially similar in length) do not.
    """

    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in normalized).strip().lower()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + cost,
            )
        previous = current
    return previous[-1]


def scan_lifecycle(tool: WebMCPToolDefinition, context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    if context.first_seen:
        findings.append(Finding(
            rule_id="WEBMCP-LIFECYCLE-001",
            category="lifecycle_anomaly",
            severity="info",
            field_path="*",
            evidence=tool.identity_key(),
            explanation="First-seen tool identity for this origin.",
            confidence=1.0,
            remediation="No action required; establishes baseline trust history.",
        ))
    elif context.previous_canonical_hash and context.previous_canonical_hash != tool.compute_hashes().security_normalised_hash:
        findings.append(Finding(
            rule_id="WEBMCP-LIFECYCLE-002",
            category="lifecycle_anomaly",
            severity="high",
            field_path="*",
            evidence=f"previous={context.previous_canonical_hash[:12]} current={tool.compute_hashes().security_normalised_hash[:12]}",
            explanation="Tool metadata changed under the same tool identity since it was first trusted.",
            confidence=0.9,
            remediation="Review the metadata diff before continuing to trust this tool identity.",
        ))

    if (
        context.session_started_at is not None
        and context.session_already_active
        and tool.registered_at - context.session_started_at > LATE_SESSION_THRESHOLD_SECONDS
    ):
        findings.append(Finding(
            rule_id="WEBMCP-LIFECYCLE-003",
            category="lifecycle_anomaly",
            severity="high",
            field_path="*",
            evidence=f"registered {tool.registered_at - context.session_started_at:.0f}s after session start",
            explanation="Tool was registered well after the agent session had already begun, rather than at session start.",
            confidence=0.85,
            remediation="Review late-session tool additions; legitimate integrations usually register tools up front.",
        ))

    if context.registration_count_recent > REGISTRATION_BURST_THRESHOLD:
        findings.append(Finding(
            rule_id="WEBMCP-LIFECYCLE-004",
            category="lifecycle_anomaly",
            severity="high",
            field_path="*",
            evidence=f"{context.registration_count_recent} registrations recently",
            explanation="Rapid registration/unregistration churn detected for this origin, consistent with tool-surface manipulation or flooding.",
            confidence=0.9,
            remediation="Investigate the source script; legitimate tools do not repeatedly register and unregister.",
        ))

    normalized_name = tool.name.strip().lower()
    for existing in context.existing_tool_names:
        existing_norm = existing.strip().lower()
        if existing_norm == normalized_name:
            continue
        distance = _levenshtein(normalized_name, existing_norm)
        if 0 < distance <= NEAR_DUPLICATE_MAX_DISTANCE and abs(len(normalized_name) - len(existing_norm)) <= NEAR_DUPLICATE_MAX_DISTANCE:
            findings.append(Finding(
                rule_id="WEBMCP-LIFECYCLE-005",
                category="lifecycle_anomaly",
                severity="high",
                field_path="name",
                evidence=f"{tool.name!r} vs existing {existing!r}",
                explanation="Tool name is a near-duplicate of an existing tool name, which can confuse agent tool selection.",
                confidence=0.8,
                remediation="Use a clearly distinct tool name.",
            ))
            break

    # A homoglyph attack can substitute *every* character with a different-
    # script look-alike, which defeats plain edit-distance comparison above
    # (every character differs, so the Levenshtein distance is large) while
    # still rendering identically to a human. Compare confusable skeletons
    # separately so this class of attack is still caught.
    skeleton = _confusable_skeleton(tool.name)
    if skeleton:
        for existing in context.existing_tool_names:
            if existing.strip().lower() == normalized_name:
                continue
            if _confusable_skeleton(existing) == skeleton:
                findings.append(Finding(
                    rule_id="WEBMCP-LIFECYCLE-006",
                    category="lifecycle_anomaly",
                    severity="critical",
                    field_path="name",
                    evidence=f"{tool.name!r} visually resembles existing {existing!r}",
                    explanation=(
                        "Tool name uses different Unicode characters (e.g. Cyrillic/Greek "
                        "look-alikes) that render nearly identically to an existing tool name — "
                        "a confusable-identifier collision commonly used to trick an agent or "
                        "human reviewer into selecting the wrong tool."
                    ),
                    confidence=0.85,
                    remediation="Reject or clearly and visibly distinguish confusable tool names; do not allow both to register unchallenged.",
                ))
                break

    return findings
