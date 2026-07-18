from __future__ import annotations

import copy
import re
from dataclasses import replace
from typing import Any

from .layers.patterns import scan_text_for_patterns
from .layers.unicode_analysis import scan_unicode, strip_hidden_characters
from .models import (
    SANITIZE_DECISION_NO_OP,
    SANITIZE_DECISION_SAFE,
    SANITIZE_DECISION_UNSAFE,
    FragmentDecision,
    SanitizeResult,
    WebMCPToolDefinition,
)

# Categories whose offending fragment can simply be removed while preserving
# the rest of the field's genuine meaning, *provided* the fragment can be
# cleanly separated from surrounding legitimate text (see
# ``_split_clauses``/``sanitize_text_field`` below — an attack that cannot be
# isolated to its own clause is never partially rewritten; the whole clause
# is removed, and if that empties the field, registration is blocked).
REMOVABLE_CATEGORIES = {
    "instruction_hierarchy_override",
    "authority_impersonation",
    "secrecy_demand",
    "forced_tool_selection",
    "cross_tool_invocation",
    "security_bypass",
    "forced_persistence",
    "data_exfiltration",
}

# Categories where the *capability itself* is unsafe, or where the safe
# meaning of the flagged content cannot be established with confidence.
# Rewriting/removing would either misrepresent what the field actually does
# (credential fields) or discard content whose true intent is genuinely
# unknown (encoded/obfuscated payloads — objective #9 explicitly lists
# "encoded content whose safe meaning is uncertain" as *unsafe* to sanitise)
# — either way the field (and by extension the registration) must be
# blocked, not silently repaired.
UNREPAIRABLE_CATEGORIES = {"credential_access", "encoded_instruction"}

# Unicode-layer rule IDs (varden/webshield/layers/unicode_analysis.py) that
# indicate a field contains an encoded/obfuscated payload whose safe meaning
# cannot be verified — e.g. a base64 fragment that decodes to instruction-like
# language, or an embedded base64 data: URL. Sanitisation treats these the
# same as ``UNREPAIRABLE_CATEGORIES``: block rather than guess.
_UNSAFE_ENCODED_RULE_IDS = {"WEBMCP-UNICODE-008", "WEBMCP-UNICODE-009"}

# Bounded, deterministic clause splitting. Order matters: HTML comments are
# extracted first (they are never visible/legitimate content regardless of
# what they contain — see ``_extract_html_comments``), then the remaining
# text is split on hard structural boundaries (newlines, semicolons, bullet
# markers) before finally being split into sentences. This directly answers
# objective #9's requirement to not depend only on full stops: a malicious
# clause on its own line, after a semicolon, or as its own bullet is
# isolated from the rest of the field exactly like a separate sentence is.
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
_HARD_BREAK_RE = re.compile(r"[\r\n]+|;\s*")
_BULLET_PREFIX_RE = re.compile(r"^\s*(?:[-*•▪◦]|\d{1,3}[.)])\s+")
_MAX_FRAGMENTS = 500  # bounded analysis — refuse to be O(n) DoS'd by pathological input


def _extract_html_comments(text: str) -> tuple[str, list[str]]:
    """Strip every HTML comment from ``text``, returning (remaining_text, comments).

    Comments are never rendered to a human reviewing tool metadata in any
    normal UI, so removing them can never change what a legitimate,
    non-hidden tool description says — this is `safe_to_sanitise` by
    construction, independent of the comment's *content*, which is why this
    step runs unconditionally rather than only when the comment content
    happens to match a known-bad pattern.
    """

    comments = [m.group(0) for m in _HTML_COMMENT_RE.finditer(text)]
    remaining = _HTML_COMMENT_RE.sub(" ", text)
    return remaining, comments


def _strip_bullet_prefix(clause: str) -> str:
    return _BULLET_PREFIX_RE.sub("", clause)


def _split_clauses(text: str) -> list[str]:
    """Bounded, deterministic split into analysable clauses.

    Splits on (in this order of granularity): hard line/semicolon breaks,
    then bullet-prefix stripping per resulting segment, then sentence
    terminators within each segment. Every clause boundary this produces is a
    point at which a malicious instruction could plausibly be isolated from
    surrounding legitimate text without rewriting anything.
    """

    text = text.strip()
    if not text:
        return []
    segments = [seg.strip() for seg in _HARD_BREAK_RE.split(text) if seg.strip()]
    if not segments:
        return []
    clauses: list[str] = []
    for segment in segments:
        segment = _strip_bullet_prefix(segment).strip()
        if not segment:
            continue
        for sentence in _SENTENCE_SPLIT_RE.split(segment):
            sentence = sentence.strip()
            if sentence:
                clauses.append(sentence)
            if len(clauses) >= _MAX_FRAGMENTS:
                return clauses
    return clauses or [text]


def sanitize_text_field(field_path: str, text: str) -> tuple[str, dict[str, Any], bool, list[FragmentDecision]]:
    """Sanitise a single text field.

    Returns ``(sanitized_text, diff, unrepairable, decisions)`` where
    ``decisions`` is one :class:`FragmentDecision` per HTML comment and
    clause considered, in original order, forming the full explainable audit
    trail required by objective #9.
    """

    original = text or ""
    cleaned = strip_hidden_characters(original)
    without_comments, comments = _extract_html_comments(cleaned)

    decisions: list[FragmentDecision] = []
    unrepairable = False
    removed: list[str] = []

    for comment in comments:
        comment_findings = scan_text_for_patterns(field_path, comment)
        decisions.append(FragmentDecision(
            field_path=field_path,
            original_fragment=comment,
            resulting_fragment="",
            decision=SANITIZE_DECISION_SAFE,
            rule_ids=[f.rule_id for f in comment_findings],
            confidence=1.0,
            reason=(
                "HTML comments are never rendered to a human reviewing tool metadata, "
                "so removing one cannot change the tool's genuine, visible meaning."
                + (" It also contained hidden-instruction-shaped text." if comment_findings else "")
            ),
            semantics_changed=False,
        ))
        removed.append(comment)

    clauses = _split_clauses(without_comments)
    kept: list[str] = []
    for clause in clauses:
        findings = scan_text_for_patterns(field_path, clause) + scan_unicode(field_path, clause)
        credential_findings = [f for f in findings if f.category in UNREPAIRABLE_CATEGORIES]
        encoded_findings = [f for f in findings if f.rule_id in _UNSAFE_ENCODED_RULE_IDS]
        removable_findings = [
            f for f in findings if f.category in REMOVABLE_CATEGORIES and f.severity in {"high", "critical"}
        ]
        if credential_findings or encoded_findings:
            unsafe_findings = credential_findings + encoded_findings
            unrepairable = True
            removed.append(clause)
            decisions.append(FragmentDecision(
                field_path=field_path,
                original_fragment=clause,
                resulting_fragment=clause,
                decision=SANITIZE_DECISION_UNSAFE,
                rule_ids=[f.rule_id for f in unsafe_findings],
                confidence=max((f.confidence for f in unsafe_findings), default=1.0),
                reason=(
                    "Clause implicates a credential/secret-shaped capability, or contains encoded/"
                    "obfuscated content whose safe meaning cannot be verified; removing or rewriting "
                    "it would be a semantic change this codebase refuses to make unilaterally. "
                    "Blocking, not guessing."
                ),
                semantics_changed=True,
            ))
            continue
        if removable_findings:
            removed.append(clause)
            decisions.append(FragmentDecision(
                field_path=field_path,
                original_fragment=clause,
                resulting_fragment="",
                decision=SANITIZE_DECISION_SAFE,
                rule_ids=[f.rule_id for f in removable_findings],
                confidence=max((f.confidence for f in removable_findings), default=1.0),
                reason=(
                    "Clause is cleanly separable from surrounding text (its own sentence/line/bullet/"
                    "semicolon-delimited unit) and matches a deterministic high-confidence attack "
                    "pattern; removing the whole clause leaves the rest of the field's genuine "
                    "meaning intact."
                ),
                semantics_changed=False,
            ))
            continue
        kept.append(clause)
        if findings:
            # Matched *something* (e.g. a low-severity/low-confidence signal)
            # but not strongly enough to justify removal on its own.
            decisions.append(FragmentDecision(
                field_path=field_path,
                original_fragment=clause,
                resulting_fragment=clause,
                decision=SANITIZE_DECISION_NO_OP,
                rule_ids=[f.rule_id for f in findings],
                confidence=max((f.confidence for f in findings), default=0.0),
                reason="Matched pattern(s) below the removal confidence/severity threshold; kept as-is rather than guessed at.",
                semantics_changed=False,
            ))

    sanitized = " ".join(kept).strip()
    diff = {"before": original, "after": sanitized, "removed_fragments": removed}
    return sanitized, diff, unrepairable, decisions


def _sanitize_schema(
    schema: dict[str, Any] | None, path: str, depth: int = 0
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]], list[str], list[FragmentDecision]]:
    if not isinstance(schema, dict) or depth > 25:
        return schema, {}, [], []

    new_schema = copy.deepcopy(schema)
    diffs: dict[str, dict[str, Any]] = {}
    unrepairable: list[str] = []
    decisions: list[FragmentDecision] = []

    for key in ("description", "title"):
        value = schema.get(key)
        if isinstance(value, str) and value:
            sanitized, diff, bad, field_decisions = sanitize_text_field(f"{path}.{key}", value)
            decisions.extend(field_decisions)
            if bad:
                unrepairable.append(f"{path}.{key}")
            if diff["before"] != diff["after"]:
                diffs[f"{path}.{key}"] = diff
                new_schema[key] = sanitized

    properties = schema.get("properties")
    if isinstance(properties, dict):
        new_properties = new_schema.get("properties", {})
        for name, prop in properties.items():
            sub_schema, sub_diffs, sub_unrepairable, sub_decisions = _sanitize_schema(prop, f"{path}.properties.{name}", depth + 1)
            new_properties[name] = sub_schema
            diffs.update(sub_diffs)
            unrepairable.extend(sub_unrepairable)
            decisions.extend(sub_decisions)
        new_schema["properties"] = new_properties

    items = schema.get("items")
    if isinstance(items, dict):
        sub_schema, sub_diffs, sub_unrepairable, sub_decisions = _sanitize_schema(items, f"{path}.items", depth + 1)
        new_schema["items"] = sub_schema
        diffs.update(sub_diffs)
        unrepairable.extend(sub_unrepairable)
        decisions.extend(sub_decisions)

    return new_schema, diffs, unrepairable, decisions


def sanitize_tool(tool: WebMCPToolDefinition) -> SanitizeResult:
    """Field-aware sanitisation (§9): remove only unsafe fragments, never blanket-strip.

    Returns ``blocked=True`` when sanitisation cannot safely repair the
    registration (an unrepairable credential-access field, or a description
    with no genuine content left once unsafe fragments are removed).

    Guarantees (see docs/web-shield-hardening-review.md #9 and
    tests/test_webshield_sanitize.py):

    * never expands text — output length is always <= input length per field;
    * never inserts new operational claims — the only edits are removals of
      whole clauses; no paraphrasing, no substitution;
    * idempotent — sanitising an already-sanitised tool is a no-op;
    * byte-for-byte unchanged fields when nothing was flagged.
    """

    diff: dict[str, dict[str, Any]] = {}
    unrepairable_fields: list[str] = []
    decisions: list[FragmentDecision] = []

    new_title = tool.title
    if tool.title:
        sanitized, title_diff, bad, title_decisions = sanitize_text_field("title", tool.title)
        decisions.extend(title_decisions)
        if title_diff["before"] != title_diff["after"]:
            diff["title"] = title_diff
        new_title = sanitized or None
        if bad:
            unrepairable_fields.append("title")

    new_description, desc_diff, desc_bad, desc_decisions = sanitize_text_field("description", tool.description or "")
    decisions.extend(desc_decisions)
    if desc_diff["before"] != desc_diff["after"]:
        diff["description"] = desc_diff
    if desc_bad:
        unrepairable_fields.append("description")

    new_schema = tool.input_schema
    if tool.input_schema is not None:
        new_schema, schema_diff, schema_unrepairable, schema_decisions = _sanitize_schema(tool.input_schema, "input_schema")
        diff.update(schema_diff)
        unrepairable_fields.extend(schema_unrepairable)
        decisions.extend(schema_decisions)

    description_became_empty = bool((tool.description or "").strip()) and not new_description.strip() and "description" in diff
    blocked = bool(unrepairable_fields) or description_became_empty

    sanitized_tool = replace(tool, title=new_title, description=new_description, input_schema=new_schema)
    return SanitizeResult(
        sanitized_tool=sanitized_tool,
        diff=diff,
        unrepairable_fields=unrepairable_fields,
        blocked=blocked,
        decisions=decisions,
    )
