"""One HTTP destination identity for policy, audit, and the socket.

The string the caller sent is kept for evidence. Security decisions use the
canonical host, port, and URL. Forms that common parsers read as different
hosts are rejected instead of guessed.

DNS rebinding is not closed here. A hostname is not the address a later
connect() will use. ``Destination.dns_rebinding`` is ``open`` for names and
``not_applicable`` for literal IPs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_MAX_URL = 8_192
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Cloud instance metadata addresses. This is a classification, not a default block.
_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("fd00:ec2::254"),
}
_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.com",
    }
)

_LABEL = re.compile(r"[a-z0-9_-]{1,63}")


class DestinationRejected(Exception):
    """The URL is not a single unambiguous HTTP destination."""

    def __init__(self, code: str, destination: "Destination"):
        super().__init__(code)
        self.code = code
        self.destination = destination


@dataclass(frozen=True)
class Destination:
    original: str
    canonical_url: str | None
    scheme: str | None
    host: str | None
    port: int | None
    path: str | None
    query: str | None
    ip: str | None
    category: str
    rejection: str | None
    evidence_url: str
    dns_rebinding: str

    @property
    def ok(self) -> bool:
        return self.rejection is None and self.canonical_url is not None


def prepare_outbound_url(url: str) -> str:
    """URL to pass to the HTTP client after a successful policy decision.

    Non-HTTP schemes are returned unchanged. Ambiguous HTTP URLs raise
    ``DestinationRejected`` so fail-open transport handling cannot proceed.
    """
    dest = canonicalize_destination(url)
    if dest.rejection and dest.rejection != "unsupported_scheme":
        raise DestinationRejected(dest.rejection, dest)
    if dest.canonical_url:
        return dest.canonical_url
    return str(url)


def canonicalize_destination(raw: str) -> Destination:
    """Parse ``raw`` into one destination, or a rejection code.

    ``unsupported_scheme`` means the string is not an HTTP(S) URL. Callers
    that are not making an HTTP connection may ignore that code. Every other
    rejection is ambiguous or malformed HTTP and must not be allowed through.
    """
    original = raw if isinstance(raw, str) else ""
    evidence = _evidence_url(original)

    def reject(code: str, *, scheme: str | None = None, category: str = "rejected") -> Destination:
        return Destination(
            original=original,
            canonical_url=None,
            scheme=scheme,
            host=None,
            port=None,
            path=None,
            query=None,
            ip=None,
            category=category,
            rejection=code,
            evidence_url=evidence,
            dns_rebinding="not_applicable",
        )

    if not isinstance(raw, str) or not raw or len(raw) > _MAX_URL:
        return reject("malformed")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return reject("malformed")
    if "\\" in raw:
        return reject("malformed")
    if "@" in urlsplit(raw).netloc or _has_userinfo(raw):
        return reject("userinfo")

    parsed = urlsplit(raw)
    scheme = (parsed.scheme or "").lower()
    if parsed.netloc and any(ch.isspace() for ch in parsed.netloc):
        return reject("malformed", scheme=scheme or None)
    if not scheme:
        return reject("missing_scheme")
    if scheme not in _DEFAULT_PORTS:
        return reject("unsupported_scheme", scheme=scheme)
    if parsed.username is not None or parsed.password is not None:
        return reject("userinfo", scheme=scheme)

    host_raw = parsed.hostname
    if not host_raw:
        return reject("missing_host", scheme=scheme)
    if "%" in host_raw or "%" in (parsed.netloc or ""):
        return reject("percent_encoded_host", scheme=scheme)

    host = host_raw.lower()
    if host.endswith("..") or host == ".":
        return reject("malformed_host", scheme=scheme)
    if host.endswith("."):
        host = host[:-1]
    if not host or ".." in host:
        return reject("malformed_host", scheme=scheme)

    try:
        port = parsed.port
    except ValueError:
        return reject("malformed_port", scheme=scheme)
    if port == _DEFAULT_PORTS[scheme]:
        port = None

    ip_text: str | None = None
    category = "hostname"
    try:
        host, ip_text, category = _classify_host(host)
    except _Ambiguous as exc:
        return reject(exc.code, scheme=scheme)
    except ValueError:
        return reject("malformed_host", scheme=scheme)

    if ip_text is not None and ":" in ip_text:
        host_for_url = f"[{ip_text}]"
    else:
        host_for_url = host

    path = parsed.path or "/"
    query = parsed.query
    netloc = host_for_url if port is None else f"{host_for_url}:{port}"
    canonical = urlunsplit((scheme, netloc, path, query, ""))
    return Destination(
        original=original,
        canonical_url=canonical,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        ip=ip_text,
        category=category,
        rejection=None,
        evidence_url=evidence,
        dns_rebinding="not_applicable" if ip_text else "open",
    )


def canonicalize_host_claim(value: str) -> tuple[str, int | None] | str:
    """Return ``(host, port or None)`` or a rejection code.

    Used for a caller-supplied domain that must agree with the URL host.
    """
    if not isinstance(value, str) or not value or len(value) > 512:
        return "malformed_domain"
    if any(ord(ch) < 33 or ord(ch) == 127 or ch in "\\/" for ch in value):
        return "malformed_domain"
    if "://" in value:
        dest = canonicalize_destination(value)
        if dest.rejection or not dest.host:
            return dest.rejection or "malformed_domain"
        return dest.host, dest.port
    text = value
    if text.startswith("[") and "]" in text:
        host = text[1 : text.index("]")]
        rest = text[text.index("]") + 1 :]
        port = None
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                return "malformed_domain"
            port = int(rest[1:])
        try:
            canon, _ip, _category = _classify_host(host.lower())
        except (_Ambiguous, ValueError):
            return "malformed_domain"
        return canon, port
    if text.count(":") == 1:
        host_part, port_s = text.rsplit(":", 1)
        if port_s.isdigit():
            stripped = _strip_one_dot(host_part.lower())
            if stripped is None:
                return "malformed_domain"
            try:
                canon, _ip, _category = _classify_host(stripped)
            except _Ambiguous as exc:
                return exc.code
            except ValueError:
                return "malformed_domain"
            return canon, int(port_s)
    stripped = _strip_one_dot(text.lower())
    if stripped is None:
        return "malformed_domain"
    try:
        canon, _ip, _category = _classify_host(stripped)
    except _Ambiguous as exc:
        return exc.code
    except ValueError:
        return "malformed_domain"
    return canon, None


def hosts_equivalent(left: object, right: object) -> bool:
    """True when both values name the same canonical host."""
    if left is None or right is None:
        return False
    a = canonicalize_host_claim(str(left))
    b = canonicalize_host_claim(str(right))
    if isinstance(a, str) or isinstance(b, str):
        return False
    return a[0] == b[0]


class _Ambiguous(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _strip_one_dot(host: str) -> str | None:
    if host.endswith(".."):
        return None
    if host.endswith("."):
        return host[:-1]
    return host


def _classify_host(host: str) -> tuple[str, str | None, str]:
    """Return ``(canonical host, ip text or None, category)``.

    ``host`` is already lowercased and has at most one trailing dot removed.
    """
    if ":" in host:
        try:
            ip = ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise ValueError("malformed ipv6") from exc
        if ip.ipv4_mapped is not None:
            raise _Ambiguous("ipv4_mapped")
        return ip.compressed, ip.compressed, _ip_category(ip)

    if _looks_like_ambiguous_ipv4(host):
        raise _Ambiguous("ambiguous_ip")

    parts = host.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        if any(len(part) > 1 and part.startswith("0") for part in parts):
            raise _Ambiguous("ambiguous_ip")
        try:
            numbers = [int(part) for part in parts]
        except ValueError as exc:
            raise _Ambiguous("ambiguous_ip") from exc
        if any(number > 255 for number in numbers):
            raise ValueError("ipv4 octet")
        ip = ipaddress.IPv4Address(".".join(str(number) for number in numbers))
        text = str(ip)
        return text, text, _ip_category(ip)

    if not _dns_ok(host):
        raise ValueError("dns")
    try:
        a_label = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("idna") from exc
    if not _dns_ok(a_label):
        raise ValueError("idna")
    category = "metadata" if a_label in _METADATA_HOSTS else "hostname"
    return a_label, None, category


def _ip_category(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip in _METADATA_IPS:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified or ip.is_reserved:
        return "reserved"
    return "public"


def _looks_like_ambiguous_ipv4(host: str) -> bool:
    if host.isdigit():
        return True
    lowered = host.lower()
    if lowered.startswith("0x"):
        return True
    parts = host.split(".")
    if len(parts) in {1, 2, 3} and all(part.isdigit() for part in parts):
        return True
    return False


def _dns_ok(host: str) -> bool:
    if not host or len(host) > 253 or host.startswith(".") or host.endswith("."):
        return False
    return all(_LABEL.fullmatch(label) and not (label.startswith("-") or label.endswith("-")) for label in host.split("."))


def _has_userinfo(raw: str) -> bool:
    # urlsplit treats ``http://expected@evil`` as userinfo. Also catch the
    # backslash form before a parser drops it into the path.
    parsed = urlsplit(raw)
    return parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or "")


def _evidence_url(raw: str) -> str:
    """Original URL with userinfo removed, for audit storage."""
    if not isinstance(raw, str) or not raw:
        return ""
    if len(raw) > _MAX_URL:
        return raw[:_MAX_URL]
    parsed = urlsplit(raw)
    if parsed.username is None and parsed.password is None and "@" not in (parsed.netloc or ""):
        return raw
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]" if port is None else f"[{host}]:{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
