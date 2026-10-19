"""One HTTP destination identity for policy, audit, and the socket.

The string the caller sent is kept for evidence. Security decisions use the
canonical host, port, and URL. Forms that common parsers read as different
hosts are rejected instead of guessed.

DNS rebinding is not closed here. A hostname is not the address a later
connect() will use. ``Destination.dns_rebinding`` is ``open`` for names and
``not_applicable`` for literal IPs. Connection pinning, when the supported
HTTP client actually connects, lives in ``varden.destination_binding``.
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
    parsed = _safe_urlsplit(raw)
    if parsed is None:
        return reject("malformed_authority")
    try:
        netloc = parsed.netloc or ""
        username = parsed.username
        password = parsed.password
    except ValueError:
        return reject("malformed_authority")
    scheme = (parsed.scheme or "").lower()
    if username is not None or password is not None or "@" in netloc:
        return reject("userinfo", scheme=scheme or None)
    if netloc and any(ch.isspace() for ch in netloc):
        return reject("malformed", scheme=scheme or None)
    if not scheme:
        return reject("missing_scheme")
    if scheme not in _DEFAULT_PORTS:
        return reject("unsupported_scheme", scheme=scheme)
    if "%" in netloc:
        return reject("percent_encoded_host", scheme=scheme)
    if netloc.count(":") > 1 and not netloc.startswith("["):
        return reject("malformed_authority", scheme=scheme)
    bracket_problem = _bracket_authority(netloc)
    if bracket_problem:
        return reject(bracket_problem, scheme=scheme)
    port_text = _explicit_port(netloc)
    if port_text is not None and not _valid_port_text(port_text):
        return reject("malformed_port", scheme=scheme)

    try:
        host_raw = parsed.hostname
    except ValueError:
        return reject("malformed_authority", scheme=scheme)
    if not host_raw:
        return reject("missing_host", scheme=scheme)
    if "%" in host_raw:
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
    if port is not None and not 1 <= port <= 65535:
        return reject("malformed_port", scheme=scheme)
    if port == _DEFAULT_PORTS[scheme]:
        port = None

    ip_text: str | None = None
    category = "hostname"
    try:
        host, ip_text, category = _classify_host(host)
    except _Ambiguous as exc:
        return reject(exc.code, scheme=scheme)
    except ValueError as exc:
        code = exc.args[0] if exc.args and exc.args[0] in {"invalid_idna", "malformed_ipv6"} else "malformed_host"
        return reject(code, scheme=scheme)

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
            if not rest.startswith(":") or not _valid_port_text(rest[1:]):
                return "malformed_domain"
            port = int(rest[1:])
        try:
            canon, _ip, _category = _classify_host(host.lower())
        except _Ambiguous as exc:
            return exc.code
        except ValueError as exc:
            return _host_error_code(exc)
        return canon, port
    if text.count(":") == 1:
        host_part, port_s = text.rsplit(":", 1)
        if port_s.isdigit():
            stripped = _strip_one_dot(host_part.lower())
            if stripped is None:
                return "malformed_domain"
            if not _valid_port_text(port_s):
                return "malformed_domain"
            try:
                canon, _ip, _category = _classify_host(stripped)
            except _Ambiguous as exc:
                return exc.code
            except ValueError as exc:
                return _host_error_code(exc)
            return canon, int(port_s)
    stripped = _strip_one_dot(text.lower())
    if stripped is None:
        return "malformed_domain"
    try:
        canon, _ip, _category = _classify_host(stripped)
    except _Ambiguous as exc:
        return exc.code
    except ValueError as exc:
        return _host_error_code(exc)
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
            raise ValueError("malformed_ipv6") from exc
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

    a_label = _idna_hostname(host)
    if not _dns_ok(a_label):
        raise ValueError("malformed_host")
    category = "metadata" if a_label in _METADATA_HOSTS else "hostname"
    return a_label, None, category


def ip_category(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Category of an already-parsed address. See ``_ip_category``."""
    return _ip_category(ip)


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


def _idna_hostname(host: str) -> str:
    """ASCII A-label form of a DNS name.

    Unicode is encoded before hostname validation. Equality ignores ASCII
    case only. A mapping such as sharp-s to ``ss`` is ambiguous and is rejected.
    """
    if host.isascii():
        for label in host.split("."):
            if label.startswith("xn--"):
                try:
                    label.encode("ascii").decode("idna")
                except UnicodeError as exc:
                    raise ValueError("invalid_idna") from exc
        return host
    try:
        a_label = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid_idna") from exc
    try:
        decoded = a_label.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise ValueError("invalid_idna") from exc
    if _ascii_casefold(decoded) != _ascii_casefold(host):
        raise _Ambiguous("ambiguous_idna")
    return a_label


def _ascii_casefold(text: str) -> str:
    """Lowercase A-Z only. Unicode casefold would hide IDNA transitions such as ß."""
    return "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in text)


def _host_error_code(exc: ValueError) -> str:
    if exc.args and exc.args[0] in {"invalid_idna", "malformed_ipv6", "ambiguous_idna"}:
        return str(exc.args[0])
    return "malformed_domain"


def _safe_urlsplit(raw: str):
    try:
        return urlsplit(raw)
    except ValueError:
        return None


def _is_plain_ipv6(text: str) -> bool:
    if not text or "%" in text:
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _bracket_authority(netloc: str) -> str | None:
    """Rejection code for a bracketed authority, or None when it is well formed."""
    if "[" not in netloc and "]" not in netloc:
        return None
    if not netloc.startswith("[") or netloc.find("]") == -1:
        return "malformed_authority"
    end = netloc.index("]")
    inside = netloc[1:end]
    after = netloc[end + 1 :]
    if after and not after.startswith(":"):
        return "malformed_authority"
    if not _is_plain_ipv6(inside):
        return "malformed_ipv6"
    return None


def _explicit_port(netloc: str) -> str | None:
    """Port text when the authority contains a port separator, else None."""
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            return None
        rest = netloc[end + 1 :]
        if rest.startswith(":"):
            return rest[1:]
        return None
    if netloc.count(":") == 1:
        return netloc.split(":", 1)[1]
    return None


def _valid_port_text(text: str) -> bool:
    if not text or len(text) > 5 or not text.isascii() or not text.isdecimal():
        return False
    return 1 <= int(text) <= 65535


def _redact_unparsed_userinfo(raw: str) -> str:
    """Drop userinfo without calling the URL parser."""
    scheme, sep, rest = raw.partition("://")
    if not sep:
        return raw
    cut = len(rest)
    for marker in "/?#":
        index = rest.find(marker)
        if index != -1:
            cut = min(cut, index)
    authority, tail = rest[:cut], rest[cut:]
    if "@" not in authority:
        return raw
    return f"{scheme}://{authority.rsplit('@', 1)[-1]}{tail}"


def _evidence_url(raw: str) -> str:
    """Original URL with userinfo removed, for audit storage.

    Parser failures return a redacted string. They do not propagate.
    """
    if not isinstance(raw, str) or not raw:
        return ""
    if len(raw) > _MAX_URL:
        raw = raw[:_MAX_URL]
    parsed = _safe_urlsplit(raw)
    if parsed is None:
        return _redact_unparsed_userinfo(raw)
    try:
        username = parsed.username
        password = parsed.password
        netloc = parsed.netloc or ""
        host = parsed.hostname or ""
    except ValueError:
        return _redact_unparsed_userinfo(raw)
    if username is None and password is None and "@" not in netloc:
        return raw
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None and not 1 <= port <= 65535:
        port = None
    authority = host
    if port:
        authority = f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        authority = f"[{host}]" if port is None else f"[{host}]:{port}"
    try:
        return urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, ""))
    except ValueError:
        return _redact_unparsed_userinfo(raw)
