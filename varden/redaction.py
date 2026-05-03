from __future__ import annotations
import json
def redact(value):
    text = json.dumps(value, default=str)
    for token in ["password", "secret", "token", "api_key", "credit card"]:
        text = text.replace(token, "[REDACTED]")
    return json.loads(text) if text.startswith("{") or text.startswith("[") else text
