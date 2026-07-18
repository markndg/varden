"""Pre-parse request-body size enforcement.

``_check_payload_size()`` in ``varden/webshield/routes.py`` (and the
equivalent inline checks elsewhere) run *after* FastAPI/Starlette has
already buffered and JSON-decoded the full request body into a Python
``dict`` — by the time that check fires, an attacker has already forced the
server to allocate memory for, and spend CPU parsing, an arbitrarily large
body. That check remains in place as defence in depth (it also validates
the *decoded* structure, which this middleware does not), but on its own it
is not a pre-parse limit.

This module adds the earliest practical enforcement point in the ASGI
stack: a raw ASGI middleware (not ``BaseHTTPMiddleware`` — see below) that:

* rejects immediately, before reading a single byte of the body, if the
  client sent a ``Content-Length`` header that already exceeds the
  configured limit;
* otherwise reads the body itself directly off the raw ASGI ``receive``
  channel, counting bytes as they arrive, and stops as soon as the running
  total exceeds the limit — covering both a missing ``Content-Length`` and
  a ``Content-Length`` that understates the true body size (a client is not
  required to tell the truth in that header, and ASGI servers do not
  enforce it against the actual byte stream on the server's behalf).

Design note: this deliberately does *not* raise an exception and let it
propagate through the ASGI app in the hope some inner exception handler
turns it into a 413. FastAPI/Starlette wrap the whole app in
``ServerErrorMiddleware``, which would intercept a bare exception raised
from inside body parsing and turn it into a generic 500 before our own
middleware ever gets a chance to send a clean response. Instead, this
middleware fully owns the body-read loop for the methods it applies to: it
either decides "too large" and sends the 413 itself without ever calling
into the downstream app at all, or it decides "within bounds" and hands the
already-buffered messages to the downstream app via a small replay
``receive`` wrapper, so FastAPI's own JSON parsing sees a completely normal
byte stream and nothing downstream needs to know this middleware exists.

See ``docs/web-shield-hardening-review.md`` #8 for the full rationale.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Mapping

ASGIApp = Callable[..., Awaitable[None]]

PAYLOAD_TOO_LARGE_ERROR_CODE = "PAYLOAD_TOO_LARGE"


def _match_limit(path: str, path_limits: Mapping[str, int], default_max_bytes: int) -> int:
    # Longest-prefix match so a more specific route (e.g. the higher output
    # limit) wins over a shorter generic prefix covering the same API.
    best_prefix = ""
    best_limit = default_max_bytes
    for prefix, limit in path_limits.items():
        if path.startswith(prefix) and len(prefix) >= len(best_prefix):
            best_prefix = prefix
            best_limit = limit
    return best_limit


class RequestBodySizeLimitMiddleware:
    """Raw ASGI middleware enforcing a byte-size limit before JSON parsing.

    ``default_max_bytes`` applies to any path not covered by ``path_limits``
    (a mapping of path-prefix -> byte limit, so different routes — e.g. the
    larger tool-output endpoint — can have distinct, independently
    configurable limits per objective #8 of the hardening pass).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        default_max_bytes: int,
        path_limits: Mapping[str, int] | None = None,
        only_methods: frozenset[str] = frozenset({"POST", "PUT", "PATCH"}),
    ) -> None:
        self.app = app
        self.default_max_bytes = default_max_bytes
        self.path_limits = dict(path_limits or {})
        self.only_methods = only_methods

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method", "GET").upper() not in self.only_methods:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "") or ""
        max_bytes = _match_limit(path, self.path_limits, self.default_max_bytes)

        raw_headers = scope.get("headers") or []
        content_length_value = None
        for key, value in raw_headers:
            if key.lower() == b"content-length":
                content_length_value = value
                break

        if content_length_value is not None:
            try:
                declared_length = int(content_length_value)
            except ValueError:
                await self._reject(send, max_bytes, "malformed Content-Length header")
                return
            if declared_length > max_bytes:
                await self._reject(send, max_bytes, f"declared Content-Length ({declared_length} bytes) exceeds limit")
                return

        buffered: list[dict[str, Any]] = []
        total = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request":
                # e.g. "http.disconnect" — stop buffering and let the
                # downstream app observe the same message; nothing left to
                # size-check.
                break
            total += len(message.get("body") or b"")
            if total > max_bytes:
                await self._reject(
                    send, max_bytes, f"request body exceeds limit while streaming ({total}+ bytes observed)"
                )
                return
            if not message.get("more_body", False):
                break

        index = 0

        async def replay_receive():
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject(self, send, max_bytes: int, reason: str) -> None:
        detail = f"payload exceeds {max_bytes} byte limit: {reason}"
        body = json.dumps({"detail": detail, "error_code": PAYLOAD_TOO_LARGE_ERROR_CODE}).encode("utf-8")
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})
