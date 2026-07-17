from __future__ import annotations
import json
import re

_SECRET_ARG_RE = re.compile(r"(key|token|secret|password|credential|auth)", re.I)

# Shared with varden.webshield.layers.capability so backend redaction and
# capability-mismatch inference never drift apart on what counts as sensitive.
SENSITIVE_FIELD_RE = re.compile(
    r"(wallet|private[_\-]?key|seed[_\-]?phrase|mnemonic|password|passwd|secret|api[_\-]?key|"
    r"auth(entication)?[_\-]?token|access[_\-]?token|session[_\-]?token|cookie|"
    r"credit[_\-]?card|card[_\-]?number|cvv|cvc|ssn|social[_\-]?security|bank[_\-]?account|"
    r"routing[_\-]?number|iban|swift|clipboard)",
    re.IGNORECASE,
)

WEBMCP_MAX_OUTPUT_CHARS = 2000


def redact_webmcp_value(value, _depth: int = 0):
    """Recursively redact dict values whose key looks sensitive (§14).

    Unlike :func:`redact`, this redacts the *value* under a sensitive key,
    not just literal occurrences of a fixed keyword list — required because
    WebMCP schemas use arbitrary property names (``wallet_address``,
    ``private_key``, ``cvv`` ...).
    """

    if _depth > 20:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        out = {}
        for key, sub in value.items():
            if SENSITIVE_FIELD_RE.search(str(key)):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact_webmcp_value(sub, _depth + 1)
        return out
    if isinstance(value, list):
        return [redact_webmcp_value(item, _depth + 1) for item in value[:50]]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…[TRUNCATED]"
    return value


_OUTPUT_SECRET_TOKEN_RE = re.compile(r"(password|secret|api[_\-]?key|private[_\-]?key|credit\s*card)\s*[:=]\s*\S+", re.IGNORECASE)


def redact_webmcp_output(text: str | None, max_chars: int = WEBMCP_MAX_OUTPUT_CHARS) -> str:
    """Cap and lightly redact tool output text before it is ever persisted."""

    if not text:
        return ""
    text = str(text)
    text = _OUTPUT_SECRET_TOKEN_RE.sub(lambda m: m.group(1) + "=[REDACTED]", text)
    if len(text) > max_chars:
        text = text[:max_chars] + f"…[TRUNCATED {len(text) - max_chars} chars]"
    return text


def redact(value):
    text = json.dumps(value, default=str)
    for token in ["password", "secret", "token", "api_key", "credit card"]:
        text = text.replace(token, "[REDACTED]")
    return json.loads(text) if text.startswith("{") or text.startswith("[") else text


def redact_mcp_server(server: dict) -> dict:
    row = dict(server)
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
        if _SECRET_ARG_RE.search(text) or len(text) > 80:
            redacted_args.append("[REDACTED]")
        else:
            redacted_args.append(text)
    row["args_json"] = json.dumps(redacted_args)
    if row.get("command") and _SECRET_ARG_RE.search(str(row.get("command"))):
        row["command"] = "[REDACTED]"
    return row
