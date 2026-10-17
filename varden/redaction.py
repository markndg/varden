"""Structural redaction for persistence and control-plane transmission.

Classifiers must run on the unredacted in-memory action. Only the copy
that is stored, hashed, or published is redacted.

Correlation identifiers are HMAC truncations scoped by tenant and field
label. They are not truncated hashes of the secret, so a low-entropy
password cannot be recovered by guessing against a public digest.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Any

from varden.key_derivation import PURPOSE_REDACTION, purpose_hmac

MAX_DEPTH = 32
MAX_NODES = 8_000
MAX_STRING = 8_192

# Used by Web Shield capability inference. Kept stable so field detection
# does not change as a side effect of persistence redaction.
SENSITIVE_FIELD_RE = re.compile(
    r"(password|secret|api[_-]?key|private[_-]?key|credit\s*card|token)",
    re.IGNORECASE,
)

# Keys that are hashes or identifiers, not credentials. High-entropy
# detection must not destroy audit evidence stored under these names.
_HASH_KEYS = frozenset(
    {
        "event_hash",
        "prev_hash",
        "content_hash",
        "policy_fingerprint",
        "fingerprint",
        "key_hash",
        "source_id",
        "trace_id",
        "workflow_id",
        "session_id",
        "event_id",
        "approval_id",
    }
)

_KEY_EXACT = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api_key",
        "api-key",
        "password",
        "passwd",
        "pwd",
        "token",
        "access_token",
        "access-token",
        "refresh_token",
        "refresh-token",
        "secret",
        "client_secret",
        "client-secret",
        "private_key",
        "private-key",
    }
)

_KEY_PATTERN = re.compile(
    r"(?:^|[_\-])(?:token|key)$"
    r"|password|passwd|api[_\-]?key|client[_\-]?secret|private[_\-]?key"
    r"|refresh[_\-]?token|access[_\-]?token"
    r"|session[_\-](?:credential|token|key)s?"
    r"|authorization|set-cookie|^cookie$",
    re.IGNORECASE,
)

_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bearer", re.compile(r"^bearer\s+\S+", re.IGNORECASE)),
    ("openai_key", re.compile(r"^sk-[A-Za-z0-9_\-]{8,}$")),
    ("aws_access_key", re.compile(r"^AKIA[0-9A-Z]{16}$")),
    ("github_token", re.compile(r"^(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}$")),
    ("slack_token", re.compile(r"^xox[baprs]-[A-Za-z0-9\-]{8,}$")),
    ("jwt", re.compile(r"^[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}$")),
    ("pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

_MARKER_RE = re.compile(r"^\[REDACTED:[a-z0-9_\-]{1,32}:[0-9a-f]{4}\]$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")


def _master_secret() -> str:
    return os.environ.get("VARDEN_SIGNING_SECRET") or "varden-dev-redaction-not-for-production"


def _correlation(value: str, *, tenant_id: str, label: str, master_secret: str | None = None) -> str:
    digest = purpose_hmac(
        master_secret or _master_secret(),
        PURPOSE_REDACTION,
        f"{tenant_id}\n{label}\n{value}".encode("utf-8", errors="replace"),
    )
    return digest[:4]


def marker(label: str, value: str, *, tenant_id: str = "default", master_secret: str | None = None) -> str:
    safe = re.sub(r"[^a-z0-9_\-]", "", label.lower())[:32] or "value"
    return f"[REDACTED:{safe}:{_correlation(value, tenant_id=tenant_id, label=safe, master_secret=master_secret)}]"


def sensitive_key(key: str) -> bool:
    text = str(key).strip().lower()
    if text in _HASH_KEYS:
        return False
    if text in _KEY_EXACT:
        return True
    return _KEY_PATTERN.search(text) is not None


def _entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _high_entropy_secret(value: str) -> bool:
    if len(value) < 40 or any(ch.isspace() for ch in value):
        return False
    if _UUID_RE.match(value) or _HEX_HASH_RE.match(value):
        return False
    classes = {c.islower() for c in value if c.isalpha()}
    has_digit = any(c.isdigit() for c in value)
    if True not in classes or False not in classes or not has_digit:
        return False
    return _entropy(value) >= 4.0


def value_label(value: str) -> str | None:
    text = value.strip()
    for label, pattern in _VALUE_PATTERNS:
        if pattern.search(text):
            return label
    if _high_entropy_secret(text):
        return "high_entropy"
    return None


def redact(value: Any, *, tenant_id: str = "default", master_secret: str | None = None, _depth: int = 0, _budget: list[int] | None = None) -> Any:
    """Return a persistence-safe copy. The input object is not mutated."""
    budget = _budget if _budget is not None else [0]
    budget[0] += 1
    if _depth > MAX_DEPTH or budget[0] > MAX_NODES:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if sensitive_key(key_text):
                if isinstance(item, str) and _MARKER_RE.match(item):
                    out[key] = item
                else:
                    rendered = item if isinstance(item, str) else repr(item)
                    out[key] = marker(key_text, rendered[:MAX_STRING], tenant_id=tenant_id, master_secret=master_secret)
            else:
                out[key] = redact(item, tenant_id=tenant_id, master_secret=master_secret, _depth=_depth + 1, _budget=budget)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item, tenant_id=tenant_id, master_secret=master_secret, _depth=_depth + 1, _budget=budget) for item in value]
    if isinstance(value, str):
        if _MARKER_RE.match(value):
            return value
        text = value if len(value) <= MAX_STRING else value[:MAX_STRING]
        label = value_label(text)
        if label:
            return marker(label, text, tenant_id=tenant_id, master_secret=master_secret)
        if len(value) > MAX_STRING:
            return text + "…[TRUNCATED]"
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    try:
        rendered = str(value)
    except Exception:
        return "[TRUNCATED]"
    return redact(rendered, tenant_id=tenant_id, master_secret=master_secret, _depth=_depth + 1, _budget=budget)


def credential_signals(value: Any, *, _depth: int = 0, _budget: list[int] | None = None) -> list[str]:
    """Names of sensitive fields present, without their values."""
    budget = _budget if _budget is not None else [0]
    found: list[str] = []
    if _depth > MAX_DEPTH or budget[0] > MAX_NODES:
        return found
    budget[0] += 1
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if sensitive_key(key_text):
                found.append(key_text.lower())
            else:
                found.extend(credential_signals(item, _depth=_depth + 1, _budget=budget))
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(credential_signals(item, _depth=_depth + 1, _budget=budget))
    elif isinstance(value, str) and value_label(value):
        found.append(value_label(value) or "value")
    # Stable unique order.
    seen: set[str] = set()
    unique: list[str] = []
    for name in found:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


_HTTP_OBJECT_KEYS = frozenset({"auth", "cookies", "cookiejar"})


def _drop_http_objects(value: Any) -> tuple[Any, list[str]]:
    """Remove authentication and cookie objects before transport."""
    dropped: list[str] = []
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower() in _HTTP_OBJECT_KEYS:
                dropped.append(str(key).lower())
                continue
            child, child_dropped = _drop_http_objects(item)
            out[key] = child
            dropped.extend(child_dropped)
        return out, dropped
    if isinstance(value, list):
        out_list = []
        for item in value:
            child, child_dropped = _drop_http_objects(item)
            out_list.append(child)
            dropped.extend(child_dropped)
        return out_list, dropped
    return value, dropped


def minimize_http_for_transport(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop credential material before a guard request leaves the process.

    Header names that were sensitive are reported as credential_signals so
    the control plane can still classify the call without receiving the secret.
    """
    stripped, dropped = _drop_http_objects(payload)
    body = redact(stripped)
    signals = credential_signals(stripped) + dropped
    if signals:
        meta = dict(body.get("metadata") or {})
        meta["credential_signals"] = list(dict.fromkeys(signals))
        body["metadata"] = meta
    return body


def minimize_subprocess_env(kwargs: dict[str, Any], *, baseline_keys: set[str] | None = None) -> dict[str, Any]:
    """Replace an environment mapping with key names and a change set."""
    safe = dict(kwargs)
    env = safe.get("env")
    if isinstance(env, dict):
        keys = sorted(str(k) for k in env.keys())
        changed = keys
        if baseline_keys is not None:
            changed = sorted(set(keys) - set(baseline_keys))
        safe["env_keys"] = keys
        safe["env_changed"] = changed
        safe.pop("env", None)
    return safe


# WebMCP helpers keep their truncation behaviour and now use the same marker.
WEBMCP_MAX_OUTPUT_CHARS = 2000
_OUTPUT_SECRET_TOKEN_RE = re.compile(
    r"(password|secret|api[_\-]?key|private[_\-]?key|credit\s*card)\s*[:=]\s*\S+",
    re.IGNORECASE,
)


def redact_webmcp_value(value, _depth: int = 0):
    return redact(value, _depth=_depth)


def redact_webmcp_output(text: str | None, max_chars: int = WEBMCP_MAX_OUTPUT_CHARS) -> str:
    if not text:
        return ""
    text = str(text)
    text = _OUTPUT_SECRET_TOKEN_RE.sub(lambda m: marker(m.group(1), m.group(0)), text)
    if len(text) > max_chars:
        text = text[:max_chars] + f"…[TRUNCATED {len(text) - max_chars} chars]"
    return text


_SECRET_ARG_RE = re.compile(r"(key|token|secret|password|credential|auth)", re.I)


def redact_mcp_server(server: dict) -> dict:
    row = dict(server)
    import json

    args = row.get("args_json")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = []
    if not isinstance(args, list):
        args = [str(args)]
    redacted_args: list[str] = []
    for arg in args:
        text = str(arg)
        if _SECRET_ARG_RE.search(text) or len(text) > 80 or value_label(text):
            redacted_args.append(marker("arg", text))
        else:
            redacted_args.append(text)
    row["args_json"] = json.dumps(redacted_args)
    if row.get("command") and (_SECRET_ARG_RE.search(str(row.get("command"))) or value_label(str(row.get("command")))):
        row["command"] = marker("command", str(row.get("command")))
    return row
