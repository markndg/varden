"""Bind an authorized HTTP destination to the socket that actually connects.

Canonicalization does not close DNS rebinding. A hostname's
``Destination.dns_rebinding`` stays ``open`` because the name is not an
address. This module is the connection boundary for the supported Python
HTTP clients:

* Resolve the name once, before the policy decision.
* Give policy every address and the most severe category.
* While the authorized send runs, ``socket.getaddrinfo`` for that host
  returns only those addresses. A later lookup cannot select a new IP.
* The URL host is left unchanged, so TLS SNI and certificate verification
  still use the hostname.
* Pooled connections whose peer is not in the authorized set are closed
  before the send.
* An HTTP proxy is a different connection. The TCP peer is the proxy.
  The proxy resolves the target. That hop is not socket-bound.

Custom transports and adapters are not bound. Replacing ``socket.getaddrinfo``
removes the pin; coverage then refuses to stay ENFORCED. This is not an
operating-system sandbox. ``ctypes`` connect and a saved socket reference
are outside the hook.
"""

from __future__ import annotations

import contextvars
import ipaddress
import queue
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from varden.url_identity import canonicalize_destination

Resolver = Callable[[str, int], list[str]]

_SEVERITY = {
    "metadata": 0,
    "loopback": 1,
    "link_local": 2,
    "private": 3,
    "multicast": 4,
    "reserved": 5,
    "public": 6,
    "hostname": 7,
}

_resolver: contextvars.ContextVar[Resolver | None] = contextvars.ContextVar(
    "varden_destination_resolver", default=None
)
_lock = threading.Lock()
_original_getaddrinfo: Callable[..., Any] | None = None
_pins: dict[str, list[tuple[str, ...]]] = {}
_hook_installed = False


class DestinationBindingError(Exception):
    """The direct connection cannot be bound to an authorized address."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ResolvedAddress:
    ip: str
    category: str


@dataclass(frozen=True)
class DestinationBinding:
    """One authorization-time view of where a hop may connect."""

    url: str
    host: str | None
    port: int | None
    scheme: str | None
    addresses: tuple[ResolvedAddress, ...]
    status: str
    error: str | None = None
    proxy: str | None = None
    socket_bound: bool = False
    reason: str | None = None

    @property
    def address_ips(self) -> tuple[str, ...]:
        return tuple(item.ip for item in self.addresses)

    @property
    def worst_category(self) -> str | None:
        if not self.addresses:
            return None
        return min(self.addresses, key=lambda item: _SEVERITY.get(item.category, 99)).category

    @property
    def blocks_direct_connection(self) -> bool:
        """True when a direct socket must not be opened.

        Proxy hops and custom transports are not direct bindings. Their
        residual risk is recorded on ``status`` instead of being pretended
        away. A direct hop with no usable address set is a failure.
        """
        return self.socket_bound and self.status in {"unresolved", "malformed"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "addresses": [{"ip": item.ip, "category": item.category} for item in self.addresses],
            "worst_category": self.worst_category,
            "error": self.error,
            "proxy": self.proxy,
            "socket_bound": self.socket_bound,
            "reason": self.reason,
        }


_redirect_pins: contextvars.ContextVar[list[DestinationBinding] | None] = contextvars.ContextVar(
    "varden_redirect_pins", default=None
)


def address_category(text: str) -> str | None:
    """Classify one IP string. Malformed input returns None.

    IPv4-mapped IPv6 addresses use the embedded IPv4 category so a mapped
    loopback address is not treated as a public IPv6 destination.
    """
    if not isinstance(text, str):
        return None
    raw = text.strip()
    if not raw:
        return None
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    from varden.url_identity import ip_category

    return ip_category(ip)


def worst_category(categories: list[str]) -> str | None:
    usable = [item for item in categories if item in _SEVERITY]
    if not usable:
        return None
    return min(usable, key=lambda item: _SEVERITY[item])


def use_resolver(resolver: Resolver | None) -> contextvars.Token[Resolver | None]:
    """Install a process-local resolver for the current context.

    Tests use this so DNS answers are deterministic. Production leaves it
    unset and uses ``socket.getaddrinfo``.
    """
    return _resolver.set(resolver)


def reset_resolver(token: contextvars.Token[Resolver | None]) -> None:
    _resolver.reset(token)


@contextmanager
def resolver_scope(resolver: Resolver | None) -> Iterator[None]:
    token = use_resolver(resolver)
    try:
        yield
    finally:
        reset_resolver(token)


def _default_resolver(host: str, port: int) -> list[str]:
    lookup = _original_getaddrinfo or socket.getaddrinfo
    try:
        rows = lookup(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except UnicodeError as exc:
        raise DestinationBindingError("malformed") from exc
    except socket.gaierror as exc:
        raise DestinationBindingError("unresolved") from exc
    except OSError as exc:
        raise DestinationBindingError("unresolved") from exc
    found: list[str] = []
    for row in rows:
        try:
            sockaddr = row[4]
            ip = sockaddr[0]
        except (IndexError, TypeError):
            continue
        if isinstance(ip, str) and ip:
            found.append(ip)
    return found


def _active_resolver() -> Resolver:
    current = _resolver.get()
    return current or _default_resolver


def _effective_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    return 443 if scheme == "https" else 80


def _unbound(url: str, *, status: str, reason: str, proxy: str | None = None, host: str | None = None, port: int | None = None, scheme: str | None = None) -> DestinationBinding:
    return DestinationBinding(
        url=url,
        host=host,
        port=port,
        scheme=scheme,
        addresses=(),
        status=status,
        error=None,
        proxy=proxy,
        socket_bound=False,
        reason=reason,
    )


def resolve_binding(
    url: str,
    *,
    socket_bound: bool = True,
    proxy: str | None = None,
    resolver: Resolver | None = None,
) -> DestinationBinding:
    """Resolve ``url`` into the address set a direct connection may use.

    ``socket_bound`` is false for proxies and custom transports. The
    addresses are still recorded when resolution succeeds so policy can see
    them, but the socket hook will not claim those addresses are the ones
    the proxy connects to.
    """
    dest = canonicalize_destination(str(url))
    if not dest.ok or not dest.host or not dest.scheme:
        return DestinationBinding(
            url=str(url),
            host=dest.host,
            port=dest.port,
            scheme=dest.scheme,
            addresses=(),
            status="malformed",
            error=dest.rejection or "malformed",
            proxy=proxy,
            socket_bound=False,
            reason="destination_rejected",
        )
    port = _effective_port(dest.scheme, dest.port)
    if not socket_bound:
        # Still classify a literal target. Do not pretend a hostname was pinned.
        if dest.ip:
            category = address_category(dest.ip) or "public"
            return DestinationBinding(
                url=str(url),
                host=dest.host,
                port=port,
                scheme=dest.scheme,
                addresses=(ResolvedAddress(dest.ip, category),),
                status="proxy" if proxy else "unbound",
                proxy=proxy,
                socket_bound=False,
                reason="proxy" if proxy else "not_socket_bound",
            )
        return _unbound(
            str(url),
            status="proxy" if proxy else "unbound",
            reason="proxy_resolves_target" if proxy else "not_socket_bound",
            proxy=proxy,
            host=dest.host,
            port=port,
            scheme=dest.scheme,
        )

    if dest.ip:
        category = address_category(dest.ip)
        if category is None:
            return DestinationBinding(
                url=str(url),
                host=dest.host,
                port=port,
                scheme=dest.scheme,
                addresses=(),
                status="malformed",
                error="malformed",
                socket_bound=True,
                reason="literal_not_an_ip",
            )
        return DestinationBinding(
            url=str(url),
            host=dest.host,
            port=port,
            scheme=dest.scheme,
            addresses=(ResolvedAddress(dest.ip, category),),
            status="literal",
            socket_bound=True,
            reason="literal_ip",
        )

    lookup = resolver or _active_resolver()
    try:
        raw_answers = list(lookup(dest.host, port))
    except DestinationBindingError as exc:
        return DestinationBinding(
            url=str(url),
            host=dest.host,
            port=port,
            scheme=dest.scheme,
            addresses=(),
            status="malformed" if exc.code == "malformed" else "unresolved",
            error=exc.code,
            socket_bound=True,
            reason="resolver_failed",
        )
    except Exception as exc:
        code = "malformed" if isinstance(exc, (UnicodeError, ValueError)) else "unresolved"
        return DestinationBinding(
            url=str(url),
            host=dest.host,
            port=port,
            scheme=dest.scheme,
            addresses=(),
            status=code,
            error=code,
            socket_bound=True,
            reason="resolver_failed",
        )

    addresses: list[ResolvedAddress] = []
    malformed = 0
    for item in raw_answers:
        if not isinstance(item, str):
            malformed += 1
            continue
        category = address_category(item)
        if category is None:
            malformed += 1
            continue
        addresses.append(ResolvedAddress(item, category))
    if not addresses:
        return DestinationBinding(
            url=str(url),
            host=dest.host,
            port=port,
            scheme=dest.scheme,
            addresses=(),
            status="malformed" if malformed or raw_answers else "unresolved",
            error="malformed" if malformed or raw_answers else "unresolved",
            socket_bound=True,
            reason="no_usable_address",
        )
    return DestinationBinding(
        url=str(url),
        host=dest.host,
        port=port,
        scheme=dest.scheme,
        addresses=tuple(addresses),
        status="pinned",
        socket_bound=True,
        reason="resolved",
    )


def _pin_key(host: str) -> str:
    text = str(host).strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if text.endswith("."):
        text = text[:-1]
    return text


def hook_installed() -> bool:
    return _hook_installed and socket.getaddrinfo is _pinned_getaddrinfo


def install_resolution_hook() -> None:
    """Install the getaddrinfo pin. Safe to call more than once."""
    global _original_getaddrinfo, _hook_installed
    with _lock:
        current = socket.getaddrinfo
        if current is _pinned_getaddrinfo:
            _hook_installed = True
            return
        if _original_getaddrinfo is None or current is _original_getaddrinfo:
            _original_getaddrinfo = current
            socket.getaddrinfo = _pinned_getaddrinfo
            _hook_installed = True
            return
        # A foreign resolver is already installed. Do not override it.
        _hook_installed = False


def restore_resolution_hook() -> None:
    """Remove the pin hook when it is still ours. Do not touch a foreign one."""
    global _hook_installed
    with _lock:
        if socket.getaddrinfo is _pinned_getaddrinfo and _original_getaddrinfo is not None:
            socket.getaddrinfo = _original_getaddrinfo
        _pins.clear()
        _hook_installed = False


def _activate(binding: DestinationBinding) -> None:
    if not binding.socket_bound or not binding.host or not binding.addresses:
        return
    key = _pin_key(binding.host)
    with _lock:
        _pins.setdefault(key, []).append(binding.address_ips)


def _deactivate(binding: DestinationBinding) -> None:
    if not binding.host:
        return
    key = _pin_key(binding.host)
    with _lock:
        stack = _pins.get(key)
        if not stack:
            return
        needle = binding.address_ips
        for index in range(len(stack) - 1, -1, -1):
            if stack[index] == needle:
                del stack[index]
                break
        if not stack:
            _pins.pop(key, None)


def note_redirect_binding(binding: DestinationBinding) -> None:
    """Keep a redirect hop's pin until the enclosing ``pinned_connection`` exits.

    urllib follows the redirect inside the original ``urlopen``, after
    ``redirect_request`` has returned. The extra pin has to outlive that
    method and end with the outer send.
    """
    if not binding.socket_bound or not binding.addresses:
        return
    current = _redirect_pins.get()
    if current is None:
        return
    _activate(binding)
    current.append(binding)


@contextmanager
def pinned_connection(binding: DestinationBinding) -> Iterator[DestinationBinding]:
    """Force lookups of ``binding.host`` to the authorized addresses."""
    if binding.socket_bound and binding.addresses and not hook_installed():
        raise DestinationBindingError("binding_hook_missing")
    token = _redirect_pins.set([])
    _activate(binding)
    try:
        yield binding
    finally:
        extras = _redirect_pins.get() or []
        for extra in extras:
            _deactivate(extra)
        _deactivate(binding)
        _redirect_pins.reset(token)


def _addrinfo_rows(addresses: tuple[str, ...], port: int, family: int, socktype: int, proto: int) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for ip in addresses:
        category_ip = ip.split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(category_ip)
        except ValueError:
            continue
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            # Hand the mapped address back as IPv4 when that family was requested.
            if family in (socket.AF_UNSPEC, socket.AF_INET):
                sockaddr = (str(parsed.ipv4_mapped), port)
                rows.append((socket.AF_INET, socktype or socket.SOCK_STREAM, proto, "", sockaddr))
            continue
        if isinstance(parsed, ipaddress.IPv4Address):
            if family not in (socket.AF_UNSPEC, socket.AF_INET):
                continue
            rows.append((socket.AF_INET, socktype or socket.SOCK_STREAM, proto, "", (ip, port)))
        else:
            if family not in (socket.AF_UNSPEC, socket.AF_INET6):
                continue
            rows.append((socket.AF_INET6, socktype or socket.SOCK_STREAM, proto, "", (ip, port, 0, 0)))
    return rows


def _pinned_getaddrinfo(host: Any, port: Any, family: int = 0, socktype: int = 0, proto: int = 0, flags: int = 0) -> list[Any]:
    if host is None:
        lookup = _original_getaddrinfo or socket.getaddrinfo
        return lookup(host, port, family, socktype, proto, flags)
    key = _pin_key(str(host))
    with _lock:
        stack = list(_pins.get(key) or [])
    if not stack:
        lookup = _original_getaddrinfo
        if lookup is None:
            raise socket.gaierror(socket.EAI_FAIL, "destination binding hook has no resolver")
        return lookup(host, port, family, socktype, proto, flags)
    top = stack[-1]
    if any(item != top for item in stack):
        raise socket.gaierror(socket.EAI_FAIL, "conflicting destination pins")
    try:
        numeric_port = int(port) if port not in (None, "") else 0
    except (TypeError, ValueError):
        numeric_port = 0
    rows = _addrinfo_rows(top, numeric_port, int(family or 0), int(socktype or 0), int(proto or 0))
    if not rows:
        raise socket.gaierror(socket.EAI_NONAME, "authorized address family is empty")
    return rows


def _peer_ip(sock: Any) -> str | None:
    if sock is None:
        return None
    try:
        peer = sock.getpeername()
    except OSError:
        return None
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return None


def _hosts_match(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return _pin_key(left) == _pin_key(right)


def scrub_urllib3_pools(session: Any, binding: DestinationBinding) -> int:
    """Close pooled sockets for this host whose peer is not authorized.

    A reused connection does not call ``getaddrinfo`` again. Dropping a
    mismatched peer forces the next send to connect under the pin.
    ``None`` pool slots are preserved so the pool can open a new socket.
    """
    if not binding.socket_bound or not binding.addresses or not binding.host:
        return 0
    allowed = set(binding.address_ips)
    dropped = 0
    adapters = getattr(session, "adapters", None) or {}
    for adapter in adapters.values():
        manager = getattr(adapter, "poolmanager", None)
        pools = getattr(manager, "pools", None) if manager is not None else None
        if pools is None:
            continue
        try:
            keys = list(pools.keys())
        except Exception:
            continue
        for key in keys:
            host = getattr(key, "key_host", None)
            if not _hosts_match(None if host is None else str(host), binding.host):
                continue
            try:
                pool = pools[key]
            except Exception:
                continue
            dropped += _scrub_queue(getattr(pool, "pool", None), allowed)
    return dropped


def _scrub_queue(q: Any, allowed: set[str]) -> int:
    if q is None:
        return 0
    saved: list[Any] = []
    dropped = 0
    while True:
        try:
            conn = q.get_nowait()
        except queue.Empty:
            break
        except Exception:
            break
        if conn is None:
            saved.append(None)
            continue
        peer = _peer_ip(getattr(conn, "sock", None))
        if peer and peer not in allowed:
            try:
                conn.close()
            except Exception:
                pass
            saved.append(None)
            dropped += 1
        else:
            saved.append(conn)
    for item in saved:
        try:
            q.put_nowait(item)
        except Exception:
            if item is not None:
                try:
                    item.close()
                except Exception:
                    pass
    return dropped


def scrub_httpx_pool(client: Any, url: str, binding: DestinationBinding) -> int:
    if not binding.socket_bound or not binding.addresses or not binding.host:
        return 0
    transport = _httpx_transport(client, url)
    pool = getattr(transport, "_pool", None)
    connections = getattr(pool, "_connections", None)
    if not isinstance(connections, list):
        return 0
    allowed = set(binding.address_ips)
    kept: list[Any] = []
    dropped = 0
    for conn in list(connections):
        origin = getattr(conn, "_origin", None)
        origin_host = getattr(origin, "host", None)
        if isinstance(origin_host, bytes):
            origin_host = origin_host.decode("ascii", "replace")
        peer = _httpx_peer(conn)
        if _hosts_match(None if origin_host is None else str(origin_host), binding.host) and peer and peer not in allowed:
            try:
                conn.close()
            except Exception:
                pass
            dropped += 1
            continue
        kept.append(conn)
    connections[:] = kept
    return dropped


def _httpx_peer(conn: Any) -> str | None:
    stream = getattr(conn, "_network_stream", None)
    if stream is None:
        return None
    if hasattr(stream, "get_extra_info"):
        try:
            info = stream.get_extra_info("server_addr")
        except Exception:
            info = None
        if isinstance(info, tuple) and info:
            return str(info[0])
    sock = getattr(stream, "_sock", None)
    if sock is None:
        inner = getattr(stream, "_stream", None)
        sock = getattr(inner, "_raw_socket", None) if inner is not None else None
    return _peer_ip(sock)


def _httpx_transport(client: Any, url: str) -> Any:
    selector = getattr(client, "_transport_for_url", None)
    if selector is None:
        return getattr(client, "_transport", None)
    try:
        import httpx

        return selector(httpx.URL(url))
    except Exception:
        return getattr(client, "_transport", None)


def httpx_route(client: Any, url: str) -> tuple[str, str | None]:
    """Return ``(direct|proxy|custom, proxy_url)`` for the transport httpx would use."""
    transport = _httpx_transport(client, url)
    if transport is None:
        return "custom", None
    name = type(transport).__name__
    if name not in {"HTTPTransport", "AsyncHTTPTransport"}:
        return "custom", None
    pool = getattr(transport, "_pool", None)
    if pool is None:
        return "custom", None
    pool_name = type(pool).__name__
    if "Proxy" in pool_name:
        return "proxy", _proxy_url_text(pool)
    if pool_name in {"ConnectionPool", "AsyncConnectionPool"}:
        return "direct", None
    return "custom", None


def _proxy_url_text(pool: Any) -> str | None:
    proxy = getattr(pool, "_proxy_url", None)
    if proxy is None:
        return None
    scheme = getattr(proxy, "scheme", None)
    host = getattr(proxy, "host", None)
    port = getattr(proxy, "port", None)
    if isinstance(scheme, bytes):
        scheme = scheme.decode("ascii", "replace")
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not scheme or not host:
        return None
    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def requests_proxy_url(session: Any, url: str, explicit: dict[str, Any] | None = None) -> str | None:
    """Proxy URL requests would use for ``url``, or None for a direct connection."""
    try:
        from requests.utils import get_environ_proxies, select_proxy
    except Exception:
        return None
    merged: dict[str, Any] = {}
    if getattr(session, "trust_env", True):
        try:
            merged.update(get_environ_proxies(url) or {})
        except Exception:
            pass
    session_proxies = getattr(session, "proxies", None)
    if isinstance(session_proxies, dict):
        merged.update(session_proxies)
    if explicit:
        merged.update({str(key): value for key, value in explicit.items()})
    try:
        selected = select_proxy(url, merged)
    except Exception:
        return None
    if not selected:
        return None
    return str(selected)


def requests_adapter_kind(session: Any, url: str) -> str:
    try:
        import requests.adapters

        adapter = session.get_adapter(url)
    except Exception:
        return "custom"
    if type(adapter) is requests.adapters.HTTPAdapter:
        return "default"
    return "custom"


def urllib_proxy_url(url: str) -> str | None:
    try:
        import urllib.request
    except Exception:
        return None
    dest = canonicalize_destination(str(url))
    if not dest.ok or not dest.scheme or not dest.host:
        return None
    try:
        if urllib.request.proxy_bypass(dest.host):
            return None
    except Exception:
        return None
    try:
        proxies = urllib.request.getproxies()
    except Exception:
        return None
    selected = proxies.get(dest.scheme) or proxies.get("all")
    if not selected:
        return None
    return str(selected)


def proxy_host(proxy_url: str | None) -> str | None:
    if not proxy_url:
        return None
    try:
        parsed = urlsplit(proxy_url)
    except ValueError:
        return None
    return parsed.hostname
