"""Bind an authorized HTTP destination to the socket that actually connects.

Canonicalization does not close DNS rebinding. A hostname's
``Destination.dns_rebinding`` stays ``open`` because the name is not an
address. This module is the connection boundary for the supported Python
HTTP clients:

* Resolve the name once, before the policy decision.
* Give policy every address and the most severe category.
* The authorization is stored on the operation, not in a process-wide
  hostname table. Another thread, task, or library lookup does not inherit it.
* Supported clients dial those addresses directly. The URL host is left
  unchanged, so TLS SNI and certificate verification still use the hostname.
* A pooled connection is reused only when its peer is verified to be in
  that operation's address set. An unknown or failed peer check is not reused.
* An HTTP proxy is a different connection. The TCP peer is the proxy.
  The proxy resolves the target. That hop is not socket-bound.

Custom transports and adapters are not bound. This is not an
operating-system sandbox. ``ctypes`` connect, a saved socket, and a client
that does not use these connection paths are outside the binding.
"""

from __future__ import annotations

import contextvars
import errno
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
# Bindings for the current operation only. Not a process-wide hostname map.
_operation_bindings: contextvars.ContextVar[tuple[DestinationBinding, ...]] = contextvars.ContextVar(
    "varden_operation_bindings", default=()
)
# Tokens pushed by redirect hops, reset when the enclosing operation exits.
_redirect_tokens: contextvars.ContextVar[list[contextvars.Token[tuple[DestinationBinding, ...]]] | None] = contextvars.ContextVar(
    "varden_redirect_tokens", default=None
)
_install_lock = threading.Lock()
_saved_methods: dict[str, Any] = {}
_transport_installed = False


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
            "binding_scope": "operation" if self.socket_bound else self.status,
            "peer_verification": "required" if self.socket_bound else "not_applicable",
        }


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
    try:
        rows = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
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


def _norm_ip(text: str) -> str | None:
    raw = str(text).strip()
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _pin_key(host: str) -> str:
    text = str(host).strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if text.endswith("."):
        text = text[:-1]
    return text


def operation_bindings() -> tuple[DestinationBinding, ...]:
    """Bindings active in this context. Empty in every other thread or task."""
    return _operation_bindings.get()


def binding_for_host(host: str | None) -> DestinationBinding | None:
    """Innermost socket-bound authorization for ``host`` in this operation.

    A nested operation hides an outer one for the same host. A different
    context does not see this stack.
    """
    if not host:
        return None
    key = _pin_key(host)
    for binding in reversed(_operation_bindings.get()):
        if binding.socket_bound and binding.host and binding.addresses and _pin_key(binding.host) == key:
            return binding
    return None


def mark_request_binding(request: Any, binding: DestinationBinding) -> None:
    """Attach this hop's addresses to the request the transport will dial.

    httpcore reads this on the connection object. It does not consult a
    process-wide hostname table, and it does not need the calling context
    to survive a worker thread.
    """
    if not binding.socket_bound or not binding.addresses:
        return
    extensions = getattr(request, "extensions", None)
    if not isinstance(extensions, dict):
        return
    extensions["varden.socket_bound"] = True
    extensions["varden.allowed_ips"] = tuple(binding.address_ips)


def _allowed_set(binding: DestinationBinding) -> set[str]:
    found = set()
    for ip in binding.address_ips:
        normal = _norm_ip(ip)
        if normal:
            found.add(normal)
    return found


def transport_binding_installed() -> bool:
    return _transport_installed


def hook_installed() -> bool:
    """True when the operation-scoped transport bindings are installed.

    This is not a ``socket.getaddrinfo`` hook. Unrelated lookups are unchanged.
    """
    return transport_binding_installed()


def _method_key(owner: Any, name: str) -> str:
    return f"{getattr(owner, '__module__', '?')}.{getattr(owner, '__qualname__', getattr(owner, '__name__', '?'))}.{name}"


def _install_method(owner: Any, name: str, factory: Callable[[Any], Any]) -> bool:
    current = getattr(owner, name, None)
    if current is None:
        return False
    if getattr(current, "_varden_transport_binding", False):
        return True
    key = _method_key(owner, name)
    saved = _saved_methods.get(key)
    if saved is None:
        _saved_methods[key] = current
        saved = current
    if current is not saved:
        return False
    wrapped = factory(saved)
    wrapped._varden_transport_binding = True  # type: ignore[attr-defined]
    setattr(owner, name, wrapped)
    return True


def _restore_method(owner: Any, name: str) -> None:
    current = getattr(owner, name, None)
    key = _method_key(owner, name)
    saved = _saved_methods.get(key)
    if saved is None or current is None:
        return
    if getattr(current, "_varden_transport_binding", False):
        setattr(owner, name, saved)


class _BoundSyncBackend:
    def __init__(self, inner: Any, ips: tuple[str, ...]):
        self._inner = inner
        self._ips = ips

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options: Any = None) -> Any:
        last: BaseException | None = None
        for ip in self._ips:
            try:
                return self._inner.connect_tcp(
                    host=ip,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:
                last = exc
        raise last if last is not None else OSError("no authorized address")


class _BoundAsyncBackend:
    def __init__(self, inner: Any, ips: tuple[str, ...]):
        self._inner = inner
        self._ips = ips

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options: Any = None) -> Any:
        last: BaseException | None = None
        for ip in self._ips:
            try:
                return await self._inner.connect_tcp(
                    host=ip,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:
                last = exc
        raise last if last is not None else OSError("no authorized address")


def _dial_authorized(original: Any, connection: Any, request: Any, *, async_backend: bool) -> Any:
    extensions = getattr(request, "extensions", None) or {}
    if not extensions.get("varden.socket_bound"):
        return original(connection, request)
    if getattr(connection, "_uds", None):
        raise DestinationBindingError("unix_socket_unbound")
    ips = tuple(extensions.get("varden.allowed_ips") or ())
    if not ips:
        raise DestinationBindingError("binding_missing_addresses")
    backend = connection._network_backend
    replacement = _BoundAsyncBackend(backend, ips) if async_backend else _BoundSyncBackend(backend, ips)
    connection._network_backend = replacement
    try:
        return original(connection, request)
    finally:
        connection._network_backend = backend


def _make_sync_connect(original: Any) -> Any:
    def _connect(self: Any, request: Any) -> Any:
        return _dial_authorized(original, self, request, async_backend=False)

    return _connect


def _make_async_connect(original: Any) -> Any:
    async def _connect(self: Any, request: Any) -> Any:
        extensions = getattr(request, "extensions", None) or {}
        if not extensions.get("varden.socket_bound"):
            return await original(self, request)
        if getattr(self, "_uds", None):
            raise DestinationBindingError("unix_socket_unbound")
        ips = tuple(extensions.get("varden.allowed_ips") or ())
        if not ips:
            raise DestinationBindingError("binding_missing_addresses")
        backend = self._network_backend
        self._network_backend = _BoundAsyncBackend(backend, ips)
        try:
            return await original(self, request)
        finally:
            self._network_backend = backend

    return _connect


def _make_stdlib_connect(original: Any) -> Any:
    def connect(self: Any) -> None:
        binding = binding_for_host(getattr(self, "host", None))
        if binding is None:
            original(self)
            return
        last: BaseException | None = None
        for ip in binding.address_ips:
            try:
                self.sock = self._create_connection((ip, self.port), self.timeout, self.source_address)
            except OSError as exc:
                last = exc
                sock = getattr(self, "sock", None)
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    self.sock = None
                continue
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as exc:
                if exc.errno != errno.ENOPROTOOPT:
                    raise
            if getattr(self, "_tunnel_host", None):
                self._tunnel()
            return
        raise last if last is not None else OSError("no authorized address")

    return connect


def _make_urllib3_new_conn(original: Any) -> Any:
    def _new_conn(self: Any) -> Any:
        binding = binding_for_host(getattr(self, "host", None))
        if binding is None:
            return original(self)
        saved = getattr(self, "_dns_host", None)
        last: BaseException | None = None
        try:
            for ip in binding.address_ips:
                self._dns_host = ip
                try:
                    return original(self)
                except Exception as exc:
                    last = exc
        finally:
            self._dns_host = saved
        raise last if last is not None else OSError("no authorized address")

    return _new_conn


def _urllib3_verdict(conn: Any, allowed: set[str]) -> str:
    """``fresh``, ``reuse``, or ``drop``. Unknown and failed peers are ``drop``."""
    sock = getattr(conn, "sock", None)
    if sock is None:
        return "fresh"
    try:
        from urllib3.util.connection import is_connection_dropped

        if is_connection_dropped(conn):
            return "drop"
    except Exception:
        return "drop"
    try:
        peer = sock.getpeername()
    except Exception:
        return "drop"
    if not isinstance(peer, tuple) or not peer:
        return "drop"
    normal = _norm_ip(str(peer[0]))
    if normal is None or normal not in allowed:
        return "drop"
    return "reuse"


def _make_urllib3_get_conn(original: Any) -> Any:
    def _get_conn(self: Any, timeout: float | None = None) -> Any:
        binding = binding_for_host(getattr(self, "host", None))
        pool = getattr(self, "pool", None)
        if binding is None or pool is None:
            return original(self, timeout)
        allowed = _allowed_set(binding)
        if not allowed:
            raise DestinationBindingError("binding_missing_addresses")
        limit = int(getattr(pool, "maxsize", 0) or 0) + 8
        for _ in range(max(limit, 1)):
            try:
                conn = pool.get(block=False)
            except queue.Empty:
                if getattr(self, "block", False):
                    from urllib3.exceptions import EmptyPoolError

                    raise EmptyPoolError(self, "Pool is empty and a new connection can't be opened due to blocking mode.") from None
                return self._new_conn()
            except Exception as exc:
                raise DestinationBindingError("pool_uninspectable") from exc
            if conn is None:
                continue
            verdict = _urllib3_verdict(conn, allowed)
            if verdict == "reuse" or verdict == "fresh":
                return conn
            try:
                conn.close()
            except Exception:
                pass
        return self._new_conn()

    return _get_conn


def _connection_peer(connection: Any) -> str | None:
    inner = getattr(connection, "_connection", None)
    stream = None
    if inner is not None:
        stream = getattr(inner, "_network_stream", None)
    if stream is None:
        stream = getattr(connection, "_network_stream", None)
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
        nested = getattr(stream, "_stream", None)
        sock = getattr(nested, "_raw_socket", None) if nested is not None else None
    if sock is None:
        return None
    try:
        peer = sock.getpeername()
    except Exception:
        return None
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return None


def _request_allowed_ips(request: Any) -> set[str] | None:
    extensions = getattr(request, "extensions", None) or {}
    if not extensions.get("varden.socket_bound"):
        return None
    found = set()
    for ip in extensions.get("varden.allowed_ips") or ():
        normal = _norm_ip(str(ip))
        if normal:
            found.add(normal)
    return found


def _queued_bound_request(pool: Any, origin: Any) -> Any | None:
    for pool_request in list(getattr(pool, "_requests", ()) or ()):
        try:
            queued = pool_request.is_queued()
        except Exception:
            continue
        if not queued:
            continue
        request = getattr(pool_request, "request", None)
        if request is None:
            continue
        try:
            if request.url.origin != origin:
                continue
        except Exception:
            continue
        if _request_allowed_ips(request) is not None:
            return request
    return None


def _reuse_allowed(pool: Any, connection: Any, origin: Any) -> bool:
    request = _queued_bound_request(pool, origin)
    if request is None:
        return True
    allowed = _request_allowed_ips(request)
    if not allowed:
        return False
    peer = _connection_peer(connection)
    if peer is None:
        return False
    normal = _norm_ip(peer)
    return normal is not None and normal in allowed


def _guard_pool_reuse(pool: Any) -> None:
    connections = getattr(pool, "_connections", None)
    if not isinstance(connections, list):
        return
    for connection in list(connections):
        if getattr(connection, "_varden_reuse_guard", False):
            continue
        original = getattr(connection, "can_handle_request", None)
        if original is None:
            continue

        def can_handle_request(origin: Any, _conn: Any = connection, _orig: Any = original, _pool: Any = pool) -> bool:
            try:
                if not _orig(origin):
                    return False
            except Exception:
                return False
            return _reuse_allowed(_pool, _conn, origin)

        connection.can_handle_request = can_handle_request
        connection._varden_reuse_guard = True


def _take_unverifiable(pool: Any) -> list[Any]:
    """Remove idle established connections whose peer cannot be verified.

    Called while the pool lock is held. The caller closes them outside the lock.
    A verified peer that is simply outside this request's set stays in the pool
    for the operation that authorized it.
    """
    connections = getattr(pool, "_connections", None)
    if not isinstance(connections, list):
        return []
    if not any(_request_allowed_ips(getattr(item, "request", None)) is not None for item in list(getattr(pool, "_requests", ()) or ())):
        # Still guard reuse below. Evict only when a socket-bound request is queued,
        # otherwise an unrelated client keeps its own idle sockets.
        return []
    doomed: list[Any] = []
    for connection in list(connections):
        try:
            idle = bool(connection.is_idle())
        except Exception:
            idle = False
        if not idle:
            continue
        if _connection_peer(connection) is not None:
            continue
        inner = getattr(connection, "_connection", None)
        established = inner is not None or getattr(connection, "_network_stream", None) is not None
        if not established:
            continue
        try:
            connections.remove(connection)
        except ValueError:
            continue
        doomed.append(connection)
    return doomed


def _make_assign(original: Any) -> Any:
    def _assign(self: Any) -> Any:
        _guard_pool_reuse(self)
        doomed = _take_unverifiable(self)
        closing = original(self)
        if isinstance(closing, list):
            closing.extend(doomed)
            return closing
        return closing

    return _assign


_REQUIRED_TRANSPORTS: tuple[tuple[str, str, str], ...] = (
    ("urllib3.connection", "HTTPConnection", "_new_conn"),
    ("urllib3.connectionpool", "HTTPConnectionPool", "_get_conn"),
    ("http.client", "HTTPConnection", "connect"),
    ("httpcore._sync.connection", "HTTPConnection", "_connect"),
    ("httpcore._async.connection", "AsyncHTTPConnection", "_connect"),
    ("httpcore._sync.connection_pool", "ConnectionPool", "_assign_requests_to_connections"),
    ("httpcore._async.connection_pool", "AsyncConnectionPool", "_assign_requests_to_connections"),
)


def _transport_targets() -> list[tuple[Any, str, Callable[[Any], Any]]]:
    import http.client
    import importlib

    urllib3_connection = importlib.import_module("urllib3.connection")
    urllib3_pool = importlib.import_module("urllib3.connectionpool")
    sync_connection = importlib.import_module("httpcore._sync.connection")
    async_connection = importlib.import_module("httpcore._async.connection")
    sync_pool = importlib.import_module("httpcore._sync.connection_pool")
    async_pool = importlib.import_module("httpcore._async.connection_pool")
    return [
        (urllib3_connection.HTTPConnection, "_new_conn", _make_urllib3_new_conn),
        (urllib3_pool.HTTPConnectionPool, "_get_conn", _make_urllib3_get_conn),
        (http.client.HTTPConnection, "connect", _make_stdlib_connect),
        (sync_connection.HTTPConnection, "_connect", _make_sync_connect),
        (async_connection.AsyncHTTPConnection, "_connect", _make_async_connect),
        (sync_pool.ConnectionPool, "_assign_requests_to_connections", _make_assign),
        (async_pool.AsyncConnectionPool, "_assign_requests_to_connections", _make_assign),
    ]


def _targets_current() -> bool:
    try:
        targets = _transport_targets()
    except Exception:
        return False
    if len(targets) != len(_REQUIRED_TRANSPORTS):
        return False
    for owner, name, _factory in targets:
        current = getattr(owner, name, None)
        if not getattr(current, "_varden_transport_binding", False):
            return False
    return True


def install_transport_bindings() -> bool:
    """Install operation-scoped dialing and pool checks. Do not override a foreign method."""
    global _transport_installed
    with _install_lock:
        try:
            targets = _transport_targets()
        except Exception:
            _transport_installed = False
            return False
        ok = True
        for owner, name, factory in targets:
            if not _install_method(owner, name, factory):
                ok = False
        _transport_installed = ok and _targets_current()
        return _transport_installed


def restore_transport_bindings() -> None:
    """Remove our transport wrappers. Leave a foreign replacement in place."""
    global _transport_installed
    with _install_lock:
        try:
            targets = _transport_targets()
        except Exception:
            targets = []
        for owner, name, _factory in targets:
            _restore_method(owner, name)
        _transport_installed = False


def install_resolution_hook() -> None:
    install_transport_bindings()


def restore_resolution_hook() -> None:
    restore_transport_bindings()


def note_redirect_binding(binding: DestinationBinding) -> None:
    """Push a redirect hop's authorization until the enclosing operation exits.

    urllib connects after ``redirect_request`` returns, still inside ``urlopen``.
    The extra binding is visible only in this context.
    """
    if not binding.socket_bound or not binding.addresses or not binding.host:
        return
    extras = _redirect_tokens.get()
    if extras is None:
        return
    token = _operation_bindings.set(_operation_bindings.get() + (binding,))
    extras.append(token)


@contextmanager
def pinned_connection(binding: DestinationBinding) -> Iterator[DestinationBinding]:
    """Make ``binding`` the current operation's destination. It does not leak."""
    if binding.socket_bound and binding.addresses and not transport_binding_installed():
        raise DestinationBindingError("binding_hook_missing")
    extras: list[contextvars.Token[tuple[DestinationBinding, ...]]] = []
    extra_token = _redirect_tokens.set(extras)
    op_token = None
    if binding.socket_bound and binding.addresses and binding.host:
        op_token = _operation_bindings.set(_operation_bindings.get() + (binding,))
    try:
        yield binding
    finally:
        for token in reversed(extras):
            _operation_bindings.reset(token)
        if op_token is not None:
            _operation_bindings.reset(op_token)
        _redirect_tokens.reset(extra_token)


def _peer_ip(sock: Any) -> str | None:
    if sock is None:
        return None
    try:
        peer = sock.getpeername()
    except Exception:
        return None
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return None


def _hosts_match(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return _pin_key(left) == _pin_key(right)


def scrub_urllib3_pools(session: Any, binding: DestinationBinding) -> int:
    """Drop idle pooled sockets that are not a verified allowed peer.

    Checkout in ``_get_conn`` is the authoritative check. This pass removes
    connections that are already idle so a later checkout cannot observe them.
    An unknown peer is dropped. The pool lock is the queue itself.
    """
    if not binding.socket_bound or not binding.addresses or not binding.host:
        return 0
    allowed = _allowed_set(binding)
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
        verdict = _urllib3_verdict(conn, allowed)
        if verdict == "drop":
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
    """httpcore reuse is decided under the pool lock in ``_assign``.

    Mutating ``_connections`` here would race a concurrent request. The
    assignment wrapper refuses an unverified peer. This function reports that
    the check is deferred rather than pretending a lock-free edit is complete.
    """
    del client, url, binding
    return 0

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
