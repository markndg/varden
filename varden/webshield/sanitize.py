from __future__ import annotations

import copy
import re
from dataclasses import replace
from typing import Any

from .layers.patterns import scan_text_for_patterns
from .layers.unicode_analysis import strip_hidden_characters
from .models import SanitizeResult, WebMCPToolDefinition

# Categories whose offending sentence/fragment can simply be removed while
# preserving the rest of the field's genuine meaning.
REMOVABLE_CATEGORIES = {
    "instruction_hierarchy_override",
    "authority_impersonation",
    "secrecy_demand",
    "forced_tool_selection",
    "cross_tool_invocation",
    "security_bypass",
    "forced_persistence",
    "encoded_instruction",
    "data_exfiltration",
}

# Categories where the *capability itself* is unsafe, not merely its wording.
# Rewriting the text would misrepresent what the field actually does, so the
# field (and by extension the registration) must be blocked, not sanitised.
UNREPAIRABLE_CATEGORIES = {"credential_access"}

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _split_sentences(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    parts = [p.strip() for p in _SENTENCE_SPLIT_RE.split(text) if p.strip()]
    return parts or [text]


def sanitize_text_field(field_path: str, text: str) -> tuple[str, dict[str, Any], bool]:
    """Sanitise a single text field, returning (sanitized_text, diff, unrepairable)."""

    original = text or ""
    cleaned = strip_hidden_characters(original)
    sentences = _split_sentences(cleaned)
    kept: list[str] = []
    removed: list[str] = []
    unrepairable = False

    for sentence in sentences:
        findings = scan_text_for_patterns(field_path, sentence)
        if any(f.category in UNREPAIRABLE_CATEGORIES for f in findings):
            unrepairable = True
            removed.append(sentence)
            continue
        if any(f.category in REMOVABLE_CATEGORIES and f.severity in {"high", "critical"} for f in findings):
            removed.append(sentence)
            continue
        kept.append(sentence)

    sanitized = " ".join(kept).strip()
    diff = {"before": original, "after": sanitized, "removed_fragments": removed}
    return sanitized, diff, unrepairable


def _sanitize_schema(schema: dict[str, Any] | None, path: str, depth: int = 0) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]], list[str]]:
    if not isinstance(schema, dict) or depth > 25:
        return schema, {}, []

    new_schema = copy.deepcopy(schema)
    diffs: dict[str, dict[str, Any]] = {}
    unrepairable: list[str] = []

    for key in ("description", "title"):
        value = schema.get(key)
        if isinstance(value, str) and value:
            sanitized, diff, bad = sanitize_text_field(f"{path}.{key}", value)
            if bad:
                unrepairable.append(f"{path}.{key}")
            if diff["before"] != diff["after"]:
                diffs[f"{path}.{key}"] = diff
                new_schema[key] = sanitized

    properties = schema.get("properties")
    if isinstance(properties, dict):
        new_properties = new_schema.get("properties", {})
        for name, prop in properties.items():
            sub_schema, sub_diffs, sub_unrepairable = _sanitize_schema(prop, f"{path}.properties.{name}", depth + 1)
            new_properties[name] = sub_schema
            diffs.update(sub_diffs)
            unrepairable.extend(sub_unrepairable)
        new_schema["properties"] = new_properties

    items = schema.get("items")
    if isinstance(items, dict):
        sub_schema, sub_diffs, sub_unrepairable = _sanitize_schema(items, f"{path}.items", depth + 1)
        new_schema["items"] = sub_schema
        diffs.update(sub_diffs)
        unrepairable.extend(sub_unrepairable)

    return new_schema, diffs, unrepairable


def sanitize_tool(tool: WebMCPToolDefinition) -> SanitizeResult:
    """Field-aware sanitisation (§9): remove only unsafe fragments, never blanket-strip.

    Returns ``blocked=True`` when sanitisation cannot safely repair the
    registration (an unrepairable credential-access field, or a description
    with no genuine content left once unsafe fragments are removed).
    """

    diff: dict[str, dict[str, Any]] = {}
    unrepairable_fields: list[str] = []

    new_title = tool.title
    if tool.title:
        sanitized, title_diff, bad = sanitize_text_field("title", tool.title)
        if title_diff["before"] != title_diff["after"]:
            diff["title"] = title_diff
        new_title = sanitized or None
        if bad:
            unrepairable_fields.append("title")

    new_description, desc_diff, desc_bad = sanitize_text_field("description", tool.description or "")
    if desc_diff["before"] != desc_diff["after"]:
        diff["description"] = desc_diff
    if desc_bad:
        unrepairable_fields.append("description")

    new_schema = tool.input_schema
    if tool.input_schema is not None:
        new_schema, schema_diff, schema_unrepairable = _sanitize_schema(tool.input_schema, "input_schema")
        diff.update(schema_diff)
        unrepairable_fields.extend(schema_unrepairable)

    description_became_empty = bool((tool.description or "").strip()) and not new_description.strip() and "description" in diff
    blocked = bool(unrepairable_fields) or description_became_empty

    sanitized_tool = replace(tool, title=new_title, description=new_description, input_schema=new_schema)
    return SanitizeResult(
        sanitized_tool=sanitized_tool,
        diff=diff,
        unrepairable_fields=unrepairable_fields,
        blocked=blocked,
    )
