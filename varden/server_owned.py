"""Fields only the control plane may set.

Client payloads are plain dictionaries. These keys are removed at ingest.
Server code writes them back through explicit assignments after that strip.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SERVER_OWNED_METADATA = frozenset(
    {
        "enforcement",
        "audit_binding",
        "audit_integrity",
        "authority",
        "flow",
        "scan",
        "posture",
        "predictive_authority",
        "predictive_authority_config",
        "decision_latency_ms",
        "provenance_analysis",
        "approvals",
        "budget_evidence",
    }
)

SERVER_OWNED_RUNTIME = frozenset(
    {
        "coverage",
        "coverage_mode",
        "coverage_applicable",
        "posture_result",
        "interceptor_active",
        "mode_claim",
    }
)


def strip_untrusted_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    clean = {key: value for key, value in metadata.items() if key not in SERVER_OWNED_METADATA}
    runtime = clean.get("runtime")
    if isinstance(runtime, dict):
        kept = {key: value for key, value in runtime.items() if key not in SERVER_OWNED_RUNTIME}
        if kept:
            clean["runtime"] = kept
        else:
            clean.pop("runtime", None)
    return clean


def _placeholder(value: Any, depth: int = 0) -> Any:
    """Stable view for fingerprints. Sensitive values collapse to one marker."""
    if depth > 32:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        from varden.redaction import sensitive_key

        return {
            key: "[REDACTED]" if sensitive_key(str(key)) else _placeholder(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_placeholder(item, depth + 1) for item in value]
    if isinstance(value, str):
        from varden.redaction import value_label

        if value.startswith("[REDACTED:") or value_label(value):
            return "[REDACTED]"
        return value
    return value


def action_fingerprint(action: dict[str, Any]) -> str:
    body = {
        "type": action.get("type"),
        "tool": action.get("tool"),
        "method": action.get("method"),
        "url": action.get("url"),
        "trace_id": action.get("trace_id"),
        "args": _placeholder(action.get("args") or {}),
    }
    encoded = json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
