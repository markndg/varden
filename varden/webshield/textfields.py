from __future__ import annotations

from typing import Any

from .models import WebMCPToolDefinition


def iter_text_fields(tool: WebMCPToolDefinition) -> list[tuple[str, str]]:
    """Yield (field_path, text) pairs for every text-bearing field on a tool.

    Field paths use a stable dotted/bracket notation so findings can point
    at an exact location (e.g. ``input_schema.properties.private_key.description``).
    """

    out: list[tuple[str, str]] = []
    if tool.name:
        out.append(("name", tool.name))
    if tool.title:
        out.append(("title", tool.title))
    if tool.description:
        out.append(("description", tool.description))
    out.extend(_walk_schema(tool.input_schema or {}, "input_schema"))
    out.extend(_walk_json_text(tool.annotations or {}, "annotations"))
    out.extend(_walk_json_text(tool.extension_metadata or {}, "extension_metadata"))
    return out


def _walk_schema(schema: Any, path: str, depth: int = 0) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if depth > 25 or not isinstance(schema, dict):
        return out
    for key in ("title", "description"):
        value = schema.get(key)
        if isinstance(value, str) and value:
            out.append((f"{path}.{key}", value))
    examples = schema.get("examples")
    if isinstance(examples, list):
        for idx, example in enumerate(examples):
            if isinstance(example, str):
                out.append((f"{path}.examples[{idx}]", example))
    default = schema.get("default")
    if isinstance(default, str):
        out.append((f"{path}.default", default))
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, prop in properties.items():
            out.extend(_walk_schema(prop, f"{path}.properties.{name}", depth + 1))
    items = schema.get("items")
    if isinstance(items, dict):
        out.extend(_walk_schema(items, f"{path}.items", depth + 1))
    for combinator in ("anyOf", "oneOf", "allOf"):
        entries = schema.get(combinator)
        if isinstance(entries, list):
            for idx, entry in enumerate(entries):
                out.extend(_walk_schema(entry, f"{path}.{combinator}[{idx}]", depth + 1))
    return out


def _walk_json_text(value: Any, path: str, depth: int = 0) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if depth > 15:
        return out
    if isinstance(value, str):
        if value:
            out.append((path, value))
    elif isinstance(value, dict):
        for key, sub in value.items():
            out.extend(_walk_json_text(sub, f"{path}.{key}", depth + 1))
    elif isinstance(value, list):
        for idx, sub in enumerate(value):
            out.extend(_walk_json_text(sub, f"{path}[{idx}]", depth + 1))
    return out


def schema_depth(schema: Any, depth: int = 0) -> int:
    if not isinstance(schema, dict) or depth > 100:
        return depth
    best = depth
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for prop in properties.values():
            best = max(best, schema_depth(prop, depth + 1))
    items = schema.get("items")
    if isinstance(items, dict):
        best = max(best, schema_depth(items, depth + 1))
    for combinator in ("anyOf", "oneOf", "allOf"):
        entries = schema.get(combinator)
        if isinstance(entries, list):
            for entry in entries:
                best = max(best, schema_depth(entry, depth + 1))
    return best


def schema_property_count(schema: Any, _seen: int = 0) -> int:
    if not isinstance(schema, dict):
        return _seen
    properties = schema.get("properties")
    if isinstance(properties, dict):
        _seen += len(properties)
        for prop in properties.values():
            _seen = schema_property_count(prop, _seen)
    items = schema.get("items")
    if isinstance(items, dict):
        _seen = schema_property_count(items, _seen)
    return _seen


def iter_schema_property_names(schema: Any, depth: int = 0) -> list[str]:
    out: list[str] = []
    if not isinstance(schema, dict) or depth > 25:
        return out
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, prop in properties.items():
            out.append(name)
            out.extend(iter_schema_property_names(prop, depth + 1))
    items = schema.get("items")
    if isinstance(items, dict):
        out.extend(iter_schema_property_names(items, depth + 1))
    return out
