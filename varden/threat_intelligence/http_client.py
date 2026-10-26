"""Allowlisted HTTP fetch for threat-intelligence sources.

Feed content never chooses the next URL. Redirects are revalidated against the
source allowlist. Private and metadata addresses are refused. Responses are
size-bounded. This client uses ``http.client`` so it does not pass through
Varden's agent HTTP interceptors.
"""

from __future__ import annotations

import http.client
import ipaddress
import random
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

Clock = Callable[[], float]
Sleeper = Callable[[float], None]


class IntelHttpError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    unchanged: bool = False


@dataclass
class _HostGate:
    next_allowed: dict[str, float] = field(default_factory=dict)

    def wait(self, host: str, min_interval: float, *, now: Clock, sleep: Sleeper) -> None:
        if min_interval <= 0:
            return
        due = self.next_allowed.get(host, 0.0)
        delay = due - now()
        if delay > 0:
            sleep(delay)
        self.next_allowed[host] = now() + min_interval


def _is_global_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(addr.is_global)


def _reject_private_resolution(host: str) -> None:
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "metadata.google.internal"} or lowered.endswith(".local") or lowered.endswith(".internal"):
        raise IntelHttpError("ssrf_rejected", f"host {host!r} is not a public intelligence endpoint")
    try:
        ipaddress.ip_address(lowered)
    except ValueError:
        pass
    else:
        if not _is_global_ip(lowered):
            raise IntelHttpError("ssrf_rejected", f"address {host!r} is not global")
        return
    try:
        infos = socket.getaddrinfo(lowered, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise IntelHttpError("ssrf_rejected", f"could not resolve {host}") from exc
    addresses = {item[4][0] for item in infos}
    if not addresses:
        raise IntelHttpError("ssrf_rejected", f"could not resolve {host}")
    for address in addresses:
        if not _is_global_ip(address):
            raise IntelHttpError("ssrf_rejected", f"{host} resolved to a non-global address")


def validate_url(url: str, allow_hosts: frozenset[str], *, resolve: bool = False) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise IntelHttpError("ssrf_rejected", "only https intelligence URLs are fetched")
    if parts.username or parts.password:
        raise IntelHttpError("ssrf_rejected", "userinfo is not allowed")
    host = (parts.hostname or "").lower()
    if not host or host not in allow_hosts:
        raise IntelHttpError("ssrf_rejected", f"host {host or '(missing)'} is not on the source allowlist")
    if parts.port not in (None, 443):
        raise IntelHttpError("ssrf_rejected", "only port 443 is allowed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise IntelHttpError("ssrf_rejected", f"address {host!r} is not global")
    if resolve:
        _reject_private_resolution(host)
    path = parts.path or "/"
    return urlunsplit(("https", host, path, parts.query, ""))


def _gunzip_limited(data: bytes, limit: int) -> bytes:
    """Inflate gzip without letting a small body expand without a bound.

    ``decompress(max_length=...)`` stops at the cap. A following ``flush()`` of a
    bomb would still allocate the rest, so leftover input is rejected instead.
    """
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = dec.decompress(data, limit + 1)
    except zlib.error as exc:
        raise IntelHttpError("decompression_bomb", "gzip payload could not be decompressed") from exc
    if len(out) > limit or dec.unconsumed_tail:
        raise IntelHttpError("decompression_bomb", "decompressed body exceeded the size limit")
    if not dec.eof:
        try:
            extra = dec.decompress(b"", 1)
        except zlib.error as exc:
            raise IntelHttpError("decompression_bomb", "gzip payload could not be decompressed") from exc
        if extra or dec.unconsumed_tail or not dec.eof:
            raise IntelHttpError("decompression_bomb", "decompressed body exceeded the size limit")
    return out


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to an address already checked, and verify the certificate for the name."""

    def __init__(self, host: str, ip: str, *, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, 443, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _pinned_ip(host: str) -> str:
    """One resolution. Connect to that address. A private answer rejects the host."""
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "metadata.google.internal"} or lowered.endswith(".local") or lowered.endswith(".internal"):
        raise IntelHttpError("ssrf_rejected", f"host {host!r} is not a public intelligence endpoint")
    try:
        literal = ipaddress.ip_address(lowered)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise IntelHttpError("ssrf_rejected", f"address {host!r} is not global")
        return lowered
    try:
        infos = socket.getaddrinfo(lowered, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise IntelHttpError("ssrf_rejected", f"could not resolve {host}") from exc
    addresses = [item[4][0] for item in infos]
    if not addresses or any(not _is_global_ip(address) for address in addresses):
        raise IntelHttpError("ssrf_rejected", f"{host} resolved to a non-global address")
    return addresses[0]


def default_transport(url: str, headers: dict[str, str], timeout: float, max_bytes: int) -> HttpResult:
    parts = urlsplit(url)
    host = parts.hostname or ""
    ip = _pinned_ip(host)
    context = ssl.create_default_context()
    conn = _PinnedHTTPSConnection(host, ip, timeout=timeout, context=context)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        try:
            body = resp.read(max_bytes + 1)
        except http.client.IncompleteRead as exc:
            raise IntelHttpError("partial_response", "connection closed before a complete body") from exc
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        status = int(resp.status)
    except IntelHttpError:
        raise
    except socket.timeout as exc:
        raise IntelHttpError("timeout", "intelligence request timed out") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise IntelHttpError("timeout", "intelligence request timed out") from exc
    except OSError as exc:
        raise IntelHttpError("transport", str(exc) or "transport failure") from exc
    finally:
        conn.close()
    if len(body) > max_bytes:
        raise IntelHttpError("oversized", f"response exceeded {max_bytes} bytes")
    encoding = hdrs.get("content-encoding", "").lower().strip()
    if encoding and encoding not in {"identity", "gzip"}:
        raise IntelHttpError("mime_rejected", f"unsupported content encoding {encoding}")
    if encoding == "gzip":
        body = _gunzip_limited(body, max_bytes)
    return HttpResult(status=status, headers=hdrs, body=body, url=url, unchanged=status == 304)


def _retryable(exc: IntelHttpError) -> bool:
    return exc.code in {"timeout", "transport", "partial_response"}


def _retryable_status(status: int) -> bool:
    return status in {408, 429, 500, 502, 503, 504}


def backoff_delay(attempt: int, *, base: float, cap: float, jitter_ratio: float, rng: random.Random) -> float:
    delay = min(cap, base * (2 ** max(0, attempt)))
    spread = delay * max(0.0, jitter_ratio)
    if spread <= 0:
        return delay
    return max(0.0, delay + rng.uniform(-spread, spread))


class SafeHttpClient:
    def __init__(
        self,
        *,
        timeout: float = 20.0,
        max_bytes: int = 8_000_000,
        max_attempts: int = 3,
        backoff_base_seconds: float = 1.0,
        backoff_cap_seconds: float = 300.0,
        jitter_ratio: float = 0.2,
        user_agent: str = "VardenThreatIntelligence/1",
        max_redirects: int = 2,
        transport: Callable[..., HttpResult] | None = None,
        sleeper: Sleeper | None = None,
        clock: Clock | None = None,
        rng: random.Random | None = None,
        resolve_check: Callable[[str], None] | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_attempts = max(1, max_attempts)
        self.backoff_base_seconds = backoff_base_seconds
        self.backoff_cap_seconds = backoff_cap_seconds
        self.jitter_ratio = jitter_ratio
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        self._transport = transport or default_transport
        self._sleep = sleeper or time.sleep
        self._clock = clock or time.monotonic
        self._rng = rng or random.Random()
        self._gate = _HostGate()
        self._resolve_check = resolve_check
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        allow_hosts: frozenset[str],
        etag: str | None = None,
        last_modified: str | None = None,
        accept: str = "application/json",
        extra_headers: dict[str, str] | None = None,
        min_interval: float = 0.0,
        max_bytes: int | None = None,
        timeout: float | None = None,
    ) -> HttpResult:
        current = self._check(url, allow_hosts)
        redirects_left = self.max_redirects
        headers = {
            "User-Agent": self.user_agent,
            "Accept": accept,
            "Accept-Encoding": "identity",
        }
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        if extra_headers:
            for key, value in extra_headers.items():
                if key.lower() == "authorization":
                    continue
                headers[key] = value
        limit = max_bytes if max_bytes is not None else self.max_bytes
        deadline_timeout = timeout if timeout is not None else self.timeout
        last_error: IntelHttpError | None = None
        attempt = 0
        while attempt < self.max_attempts:
            host = urlsplit(current).hostname or ""
            self._gate.wait(host, min_interval, now=self._clock, sleep=self._sleep)
            self.calls.append(current)
            try:
                result = self._transport(current, headers, deadline_timeout, limit)
            except IntelHttpError as exc:
                last_error = exc
                if not _retryable(exc) or attempt + 1 >= self.max_attempts:
                    raise
                self._sleep(
                    backoff_delay(
                        attempt,
                        base=self.backoff_base_seconds,
                        cap=self.backoff_cap_seconds,
                        jitter_ratio=self.jitter_ratio,
                        rng=self._rng,
                    )
                )
                attempt += 1
                continue
            if result.status in {301, 302, 303, 307, 308}:
                if redirects_left <= 0:
                    raise IntelHttpError("redirect_rejected", "too many redirects")
                redirects_left -= 1
                current = self._follow(current, result, allow_hosts)
                headers.pop("If-None-Match", None)
                headers.pop("If-Modified-Since", None)
                continue
            if _retryable_status(result.status) and attempt + 1 < self.max_attempts:
                retry_after = _retry_after(result.headers)
                delay = retry_after if retry_after is not None else backoff_delay(
                    attempt,
                    base=self.backoff_base_seconds,
                    cap=self.backoff_cap_seconds,
                    jitter_ratio=self.jitter_ratio,
                    rng=self._rng,
                )
                self._sleep(min(self.backoff_cap_seconds, max(0.0, delay)))
                attempt += 1
                continue
            if result.status == 304:
                result.unchanged = True
                return result
            if result.status != 200:
                raise IntelHttpError("http_error", f"upstream returned HTTP {result.status}")
            mime = (result.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if mime == "text/html" or mime == "application/xhtml+xml":
                raise IntelHttpError("mime_rejected", f"refusing HTML content-type {mime}")
            return result
        if last_error:
            raise last_error
        raise IntelHttpError("retry_exhausted", "intelligence request failed")

    def _check(self, url: str, allow_hosts: frozenset[str]) -> str:
        resolve = self._transport is default_transport and self._resolve_check is None
        checked = validate_url(url, allow_hosts, resolve=resolve)
        if self._resolve_check is not None:
            host = urlsplit(checked).hostname or ""
            self._resolve_check(host)
        return checked

    def _follow(self, current: str, result: HttpResult, allow_hosts: frozenset[str]) -> str:
        location = result.headers.get("location") or ""
        if not location:
            raise IntelHttpError("redirect_rejected", "redirect missing location")
        from urllib.parse import urljoin

        target = urljoin(current, location)
        try:
            return self._check(target, allow_hosts)
        except IntelHttpError as exc:
            if exc.code == "ssrf_rejected":
                raise IntelHttpError("redirect_rejected", "redirect left the source allowlist") from exc
            raise


def _retry_after(headers: dict[str, str]) -> float | None:
    raw = headers.get("retry-after")
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if value < 0 or value > 300:
        return None
    return value
