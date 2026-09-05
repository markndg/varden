from __future__ import annotations

import atexit
import contextvars
import functools
import importlib
import importlib.abc
import importlib.machinery
import inspect
import json
import os
import subprocess
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from varden.runtime.coverage import ENFORCED, NOT_ROUTED, OBSERVATIONAL, PARTIAL, UNCOVERED, format_startup_attestation, get_coverage_registry
from varden.runtime.modes import GUARDED, default_fail_mode, enforce_compat_mode, is_enforcing, normalize_mode
from varden.runtime.boundary import enrich_action_runtime_metadata
from varden_sdk import patches as _runtime_patches



def _decode_body_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode('utf-8')
        except Exception:
            return repr(bytes(value))
    return value


def _extract_httpx_body(request: httpx.Request) -> Any:
    content = None
    try:
        content = request.content
    except Exception:
        try:
            content = request.read()
        except Exception:
            content = None
    content = _decode_body_value(content)
    if isinstance(content, str):
        stripped = content.strip()
        if stripped.startswith('{') or stripped.startswith('['):
            try:
                return json.loads(stripped)
            except Exception:
                return content
    return content
_current_guard: contextvars.ContextVar[VardenGuard | None] = contextvars.ContextVar('varden_guard', default=None)
_current_agent: contextvars.ContextVar[str | None] = contextvars.ContextVar('varden_agent', default=None)
_current_workflow: contextvars.ContextVar[str | None] = contextvars.ContextVar('varden_workflow', default=None)
_current_lineage: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar('varden_lineage', default=None)
_current_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar('varden_trace_id', default=None)
_current_parent_event_id: contextvars.ContextVar[int | None] = contextvars.ContextVar('varden_parent_event_id', default=None)
_current_provenance: contextvars.ContextVar[list[dict[str, Any]] | None] = contextvars.ContextVar('varden_provenance', default=None)

_PATCH_LOCK = threading.Lock()
_PATCHED = False
_ORIGINALS: dict[str, Any] = {}
_IMPORT_HOOK_INSTALLED = False
_IMPORT_HOOK = None
_SUPPORTED_IMPORTS = {'requests', 'httpx', 'openai', 'anthropic', 'subprocess', 'urllib', 'pathlib'}


@dataclass
class TaggedData:
    value: Any
    lineage: list[str] = field(default_factory=list)
    classification: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def unwrap(self) -> Any:
        return self.value


@dataclass
class GuardResult:
    decision: dict[str, Any]
    action: dict[str, Any]
    event_id: int | None = None

    @property
    def blocked(self) -> bool:
        # require_approval is non-executable without a scoped server approval.
        return (self.decision or {}).get('action') in {'block', 'require_approval'}

    @property
    def warned(self) -> bool:
        return (self.decision or {}).get('action') == 'warn'


class VardenBlockedError(RuntimeError):
    def __init__(self, message: str, decision: dict[str, Any] | None = None):
        super().__init__(message)
        self.decision = decision or {}


class VardenClient:
    def __init__(self, base_url: str, api_key: str | None = None, bearer_token: str | None = None, timeout: float = 5.0):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.bearer_token = bearer_token
        self._client = httpx.Client(timeout=timeout)

    def headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers['x-api-key'] = self.api_key
        elif self.bearer_token:
            headers['Authorization'] = f'Bearer {self.bearer_token}'
        return headers

    def bootstrap(self) -> dict[str, Any]:
        resp = self._client.get(f'{self.base_url}/sdk/bootstrap')
        data = _parse_json(resp)
        resp.raise_for_status()
        return data if isinstance(data, dict) else {}

    def ensure_credentials(self) -> None:
        if self.api_key or self.bearer_token:
            return
        try:
            bootstrap = self.bootstrap()
        except Exception:
            return
        self.api_key = bootstrap.get('bootstrap_api_key') or self.api_key
        self.base_url = str(bootstrap.get('base_url') or self.base_url).rstrip('/')

    def guard(self, payload: dict[str, Any]) -> GuardResult:
        self.ensure_credentials()
        resp = self._client.post(f'{self.base_url}/sdk/guard', headers=self.headers(), json=payload)
        data = _parse_json(resp)
        if resp.status_code == 403:
            detail = data.get('detail') if isinstance(data, dict) else str(data)
            decision = data.get('detail') if isinstance(data, dict) and isinstance(data.get('detail'), dict) else data if isinstance(data, dict) else None
            raise VardenBlockedError(detail or 'blocked by Varden', decision)
        resp.raise_for_status()
        return GuardResult(decision=data['decision'], action=data['action'], event_id=data.get('event_id'))

    def log_result(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.ensure_credentials()
        resp = self._client.post(f'{self.base_url}/sdk/log', headers=self.headers(), json=payload)
        data = _parse_json(resp)
        resp.raise_for_status()
        return data


class VardenGuard:
    def __init__(
        self,
        base_url: str = 'http://127.0.0.1:8000',
        api_key: str | None = None,
        bearer_token: str | None = None,
        app_name: str = 'python-app',
        tenant: str = 'default',
        mode: str = 'guarded',
        auto_instrument: bool = True,
        fail_mode: str | None = None,
        timeout: float = 5.0,
        require_coverage: list[str] | None = None,
        emit_attestation: bool = True,
        allow_uncovered: list[str] | None = None,
        mcp_config: str | None = None,
    ):
        self.client = VardenClient(base_url=base_url, api_key=api_key, bearer_token=bearer_token, timeout=timeout)
        self.app_name = app_name
        self.tenant = tenant
        # Product modes: observe | guarded | strict (enforce → guarded alias).
        self.product_mode = normalize_mode(mode, default=GUARDED)
        self.mode = enforce_compat_mode(self.product_mode)  # enforce|observe for legacy patch checks
        if fail_mode is None:
            fail_mode = default_fail_mode(self.product_mode)
        self.fail_mode = fail_mode
        self.auto_instrument = auto_instrument
        self.require_coverage = list(require_coverage or [])
        self.allow_uncovered = list(allow_uncovered or [])
        self.mcp_config = mcp_config or os.getenv('VARDEN_MCP_CONFIG')
        self.emit_attestation = emit_attestation
        self._tool_registry: dict[str, dict[str, Any]] = {}
        self._mode_locked = False
        if self.product_mode == 'strict' and self.fail_mode != 'closed':
            raise ValueError("strict mode cannot use fail_mode=open (refuses silent downgrade)")
        if is_enforcing(self.product_mode) and self.fail_mode == 'open':
            import logging
            import warnings
            msg = (
                f"VardenGuard weakens enforcement: mode={self.product_mode} with fail_mode=open "
                "allows side effects when the control plane is unreachable. "
                "Prefer fail_mode=closed (the default for guarded/strict)."
            )
            warnings.warn(msg, UserWarning, stacklevel=2)
            logging.getLogger('varden_sdk').warning(msg)

    def activate(self) -> 'VardenGuard':
        self.client.ensure_credentials()
        _current_guard.set(self)
        if self.auto_instrument:
            patch_runtime(self)
        reg = get_coverage_registry()
        reg.set_session(
            mode=self.product_mode,
            fail_mode=self.fail_mode,
            require_coverage=self.require_coverage,
            allow_uncovered=self.allow_uncovered,
            lock_mode=True,
        )
        self._mode_locked = True
        # Mark always-available tool surface.
        reg.mark('tools.python', status=PARTIAL, interceptor='guard_tool/@tool/register_tool', active=True, applicable=True)
        # LangChain remains non-applicable until the framework is actually in use.
        # Discover MCP configs — strict must not silently READY when NOT_ROUTED.
        discovered_mcp = _discover_mcp_configs(self.mcp_config)
        if discovered_mcp:
            mcp_surf = reg.get('mcp')
            if not (mcp_surf and mcp_surf.status == ENFORCED and mcp_surf.active):
                reg.discover(
                    'mcp',
                    detail={
                        'reason': f"{discovered_mcp['count']} configured server(s) detected",
                        'paths': discovered_mcp.get('paths') or [],
                        'servers': discovered_mcp.get('servers') or [],
                    },
                )
                reg.mark(
                    'mcp',
                    status=NOT_ROUTED,
                    active=False,
                    applicable=True,
                    limitations=['MCP config discovered but traffic is not routed through the Varden gateway.'],
                    evidence=discovered_mcp,
                )
        # Privileged registered tools without guard path → discover.
        for name, meta in self._tool_registry.items():
            authorities = meta.get('authorities') or []
            if any(a in {'ADMIN', 'WRITE_DATABASE', 'DELETE', 'EXECUTE_PRIVILEGED'} for a in authorities):
                reg.discover(f'tools.custom.{name}', detail={'reason': 'privileged custom tool registered', 'authorities': authorities})
        if self.product_mode == 'strict' or self.require_coverage:
            required = self.require_coverage or ['http', 'subprocess']
            missing = reg.missing_required(required)
            blocking = reg.discovered_blocking()
            if self.product_mode == 'strict' and (missing or blocking):
                parts = []
                if missing:
                    parts.append('required coverage missing: ' + ', '.join(missing))
                if blocking:
                    parts.append(
                        'discovered surfaces unenforced: '
                        + ', '.join(f"{b['surface']} ({b['state']})" for b in blocking)
                    )
                raise RuntimeError(
                    'strict mode not ready — ' + '; '.join(parts)
                    + '. Route MCP via gateway or pass allow_uncovered=[...].'
                )
        if self.emit_attestation:
            import logging
            logging.getLogger('varden').info("\n" + format_startup_attestation(reg))
            try:
                print(format_startup_attestation(reg), flush=True)
            except Exception:
                pass
        return self

    def _is_control_plane_url(self, url: str | None) -> bool:
        return _is_control_plane_request(url, self)

    def register_tool(
        self,
        name: str,
        *,
        authorities: list[str] | None = None,
        sensitivity: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Register custom tool authority metadata (optional precision aid)."""
        self._tool_registry[name] = {
            'authorities': list(authorities or []),
            'sensitivity': sensitivity,
            'metadata': dict(metadata or {}),
        }

    def guarded_action(self, *, type: str, tool: str | None = None, url: str | None = None, method: str | None = None,
                       args: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None, payload: Any = None,
                       agent_name: str | None = None, workflow_id: str | None = None) -> GuardResult | None:
        workflow_id = workflow_id or _current_workflow.get()
        agent_name = agent_name or _current_agent.get() or self.app_name
        trace_id = _current_trace_id.get() or workflow_id or str(uuid.uuid4())
        parent_event_id = _current_parent_event_id.get()
        lineage = _merge_lineage(_current_lineage.get() or {}, payload, args or {})
        auto_meta = _infer_metadata(payload if payload is not None else args or {}, url=url, tool=tool, method=method)
        provenance_sources = list(_current_provenance.get() or [])
        merged_meta = {'app_name': self.app_name, 'tenant': self.tenant, **auto_meta, **(metadata or {}), 'lineage': lineage}
        surface = ((metadata or {}).get('runtime') or {}).get('surface') or (auto_meta.get('execution_surface') if isinstance(auto_meta, dict) else None) or type
        merged_meta = enrich_action_runtime_metadata(
            merged_meta,
            surface=str(surface),
            mode=self.product_mode,
            pre_execution=True,
        )
        if tool and tool in self._tool_registry:
            reg_meta = self._tool_registry[tool]
            merged_meta.setdefault('tool_registration', reg_meta)
            if reg_meta.get('authorities'):
                merged_meta.setdefault('authority', {'required': reg_meta['authorities']})
            if reg_meta.get('sensitivity'):
                merged_meta.setdefault('sensitivity', reg_meta['sensitivity'])
        if provenance_sources:
            existing = list(merged_meta.get('provenance_sources') or [])
            merged_meta['provenance_sources'] = existing + provenance_sources
            # Incomplete observation unless an integration explicitly marks complete.
            merged_meta.setdefault('provenance_complete', False)
        action = {
            'type': type,
            'tool': tool,
            'url': url,
            'method': method,
            'domain': urlparse(url).netloc if url else None,
            'args': _json_safe(args or {}),
            'metadata': _json_safe(merged_meta),
            'agent_name': agent_name,
            'workflow_id': workflow_id,
            'parent_event_id': parent_event_id,
            'trace_id': trace_id,
            'tenant_id': self.tenant,
        }
        guard_payload = {'action': action, 'payload': _json_safe(payload if payload is not None else args or {})}
        try:
            result = self.client.guard(guard_payload)
            if result and result.event_id:
                _current_trace_id.set(trace_id)
                _current_parent_event_id.set(result.event_id)
            return result
        except VardenBlockedError as exc:
            # Observe mode records the block but must not prevent side effects.
            if not is_enforcing(self.product_mode):
                detail = exc.decision if isinstance(exc.decision, dict) else {}
                if isinstance(detail.get('decision'), dict):
                    return GuardResult(
                        decision=detail['decision'],
                        action=detail.get('action') or action,
                        event_id=detail.get('event_id'),
                    )
                return GuardResult(decision=detail or {'action': 'block', 'reason': str(exc)}, action=action, event_id=None)
            raise
        except Exception:
            if self.fail_mode == 'closed':
                raise
            return None

    def record_result(self, *, action: dict[str, Any], decision: dict[str, Any], input_payload: Any = None,
                      output_payload: Any = None, error: str | None = None) -> dict[str, Any] | None:
        def _status_from_decision(d: dict[str, Any]) -> str:
            text = str(d.get('action') or '').strip().lower()
            if text in {'block', 'blocked', 'require_approval', 'approval_required'}:
                return 'blocked'
            if text in {'warn', 'warned'}:
                return 'warned'
            if text == 'monitor':
                return 'monitor'
            return 'allowed'

        payload = {
            'action': _json_safe(action),
            'decision': _json_safe(decision),
            'input_payload': _json_safe(input_payload),
            'output_payload': _json_safe(output_payload),
            'status': _status_from_decision(decision),
            'error': error,
        }
        try:
            result = self.client.log_result(payload)
            if isinstance(result, dict) and result.get('event_id'):
                _current_parent_event_id.set(result.get('event_id'))
            return result
        except Exception:
            if self.fail_mode == 'closed':
                raise
            return None

    def guard_tool(self, fn: Callable[..., Any], name: str | None = None) -> Callable[..., Any]:
        tool_name = name or getattr(fn, '__name__', 'tool')
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = self.guarded_action(type='tool_call', tool=tool_name, args={'args': list(args), 'kwargs': kwargs}, payload={'args': list(args), 'kwargs': kwargs})
                if result and result.blocked and is_enforcing(self.product_mode):
                    raise VardenBlockedError(f'{tool_name} blocked', result.decision)
                try:
                    value = await fn(*args, **kwargs)
                    if result:
                        self.record_result(action=result.action, decision=result.decision, input_payload={'args': args, 'kwargs': kwargs}, output_payload=value)
                    return value
                except Exception as exc:
                    if result:
                        self.record_result(action=result.action, decision=result.decision, input_payload={'args': args, 'kwargs': kwargs}, error=str(exc))
                    raise
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = self.guarded_action(type='tool_call', tool=tool_name, args={'args': list(args), 'kwargs': kwargs}, payload={'args': list(args), 'kwargs': kwargs})
            if result and result.blocked and is_enforcing(self.product_mode):
                raise VardenBlockedError(f'{tool_name} blocked', result.decision)
            try:
                value = fn(*args, **kwargs)
                if result:
                    self.record_result(action=result.action, decision=result.decision, input_payload={'args': args, 'kwargs': kwargs}, output_payload=value)
                return value
            except Exception as exc:
                if result:
                    self.record_result(action=result.action, decision=result.decision, input_payload={'args': args, 'kwargs': kwargs}, error=str(exc))
                raise
        return wrapper


def _json_safe(value: Any) -> Any:
    if isinstance(value, TaggedData):
        return {'value': _json_safe(value.value), 'lineage': value.lineage, 'classification': value.classification, 'metadata': value.metadata}
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    try:
        json.dumps(value)
        return value
    except Exception:
        return repr(value)


def _flatten_text(value: Any) -> str:
    if isinstance(value, TaggedData):
        value = value.value
    if isinstance(value, dict):
        return ' '.join(_flatten_text(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return ' '.join(_flatten_text(v) for v in value)
    return str(value)


def _merge_lineage(existing: dict[str, Any], *payloads: Any) -> dict[str, Any]:
    lineage = dict(existing)
    sources = set(lineage.get('sources') or [])
    classifications = set(lineage.get('classifications') or [])
    for payload in payloads:
        for item in _iter_tagged(payload):
            sources.update(item.lineage)
            if item.classification:
                classifications.add(item.classification)
            if item.metadata:
                lineage.setdefault('tags', []).append(item.metadata)
    if sources:
        lineage['sources'] = sorted(sources)
    if classifications:
        lineage['classifications'] = sorted(classifications)
    return lineage


def _iter_tagged(value: Any):
    if isinstance(value, TaggedData):
        yield value
        value = value.value
    if isinstance(value, dict):
        for v in value.values():
            yield from _iter_tagged(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _iter_tagged(v)


def _infer_metadata(payload: Any, *, url: str | None = None, tool: str | None = None, method: str | None = None) -> dict[str, Any]:
    text = _flatten_text(payload).lower()
    internal_hits = [token for token in ('internal', 'confidential', 'customer data', 'internal_db', 'sharepoint', 's3://') if token in text]
    secret_hits = [token for token in ('password', 'token', 'api_key', 'api-key', 'secret') if token in text]
    pii_hits = [token for token in ('@', 'ssn', 'passport', 'dob') if token in text]
    metadata: dict[str, Any] = {
        'auto_classification': {
            'internal': bool(internal_hits),
            'secrets': bool(secret_hits),
            'pii': bool(pii_hits),
            'sensitive': bool(internal_hits or secret_hits or pii_hits),
        }
    }
    if internal_hits:
        metadata['auto_internal_markers'] = internal_hits
    if secret_hits:
        metadata['auto_secret_markers'] = secret_hits
    if pii_hits:
        metadata['auto_pii_markers'] = pii_hits
    if url:
        parsed = urlparse(url)
        metadata['destination'] = {'scheme': parsed.scheme, 'host': parsed.netloc, 'path': parsed.path, 'external': parsed.netloc not in ('', 'localhost', '127.0.0.1')}
    if tool:
        metadata['observed_tool'] = tool
    if method:
        metadata['observed_method'] = method
    return metadata


def _parse_json(resp: httpx.Response) -> Any:
    ctype = resp.headers.get('content-type', '')
    if 'application/json' in ctype:
        return resp.json()
    try:
        return resp.json()
    except Exception:
        return {'detail': resp.text}


def current_guard() -> VardenGuard | None:
    return _current_guard.get()


def current_provenance_sources() -> list[dict[str, Any]]:
    return list(_current_provenance.get() or [])


def _discover_mcp_configs(explicit: str | None = None) -> dict[str, Any] | None:
    """Detect MCP server configs so strict mode cannot ignore NOT_ROUTED MCP."""
    from pathlib import Path

    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_path = os.getenv('VARDEN_MCP_CONFIG')
    if env_path:
        candidates.append(Path(env_path))
    cwd = Path.cwd()
    candidates.extend(
        [
            cwd / 'mcp.json',
            cwd / '.cursor' / 'mcp.json',
            cwd / 'claude_desktop_config.json',
            Path.home() / '.cursor' / 'mcp.json',
        ]
    )
    servers: list[str] = []
    paths: list[str] = []
    for path in candidates:
        try:
            if not path.is_file():
                continue
            data = json.loads(path.read_text(encoding='utf-8'))
            block = data.get('mcpServers') or data.get('servers') or {}
            if isinstance(block, dict) and block:
                paths.append(str(path))
                servers.extend(sorted(block.keys()))
        except Exception:
            continue
    if not servers:
        return None
    return {'count': len(set(servers)), 'servers': sorted(set(servers)), 'paths': paths}


class _PatchedImportLoader(importlib.abc.Loader):
    def __init__(self, original_loader: Any, fullname: str):
        self.original_loader = original_loader
        self.fullname = fullname

    def create_module(self, spec):
        if hasattr(self.original_loader, 'create_module'):
            return self.original_loader.create_module(spec)
        return None

    def exec_module(self, module):
        self.original_loader.exec_module(module)
        guard = current_guard()
        if guard:
            _patch_module_for_name(self.fullname, guard)


class _VardenImportFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split('.', 1)[0]
        if root not in _SUPPORTED_IMPORTS:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec and spec.loader and not isinstance(spec.loader, _PatchedImportLoader):
            spec.loader = _PatchedImportLoader(spec.loader, fullname)
        return spec


def _install_import_hook() -> None:
    global _IMPORT_HOOK_INSTALLED, _IMPORT_HOOK
    if _IMPORT_HOOK_INSTALLED:
        return
    _IMPORT_HOOK = _VardenImportFinder()
    import sys
    sys.meta_path.insert(0, _IMPORT_HOOK)
    _IMPORT_HOOK_INSTALLED = True


def _remove_import_hook() -> None:
    global _IMPORT_HOOK_INSTALLED, _IMPORT_HOOK
    if not _IMPORT_HOOK_INSTALLED:
        return
    import sys
    sys.meta_path = [finder for finder in sys.meta_path if finder is not _IMPORT_HOOK]
    _IMPORT_HOOK = None
    _IMPORT_HOOK_INSTALLED = False


def unpatch_runtime() -> None:
    global _PATCHED
    with _PATCH_LOCK:
        for key, original in list(_ORIGINALS.items()):
            try:
                if key == 'requests.sessions.Session.request':
                    import requests
                    requests.sessions.Session.request = original
                elif key == 'httpx.Client.send':
                    httpx.Client.send = original
                elif key == 'httpx.AsyncClient.send':
                    httpx.AsyncClient.send = original
                elif key == 'openai.responses.create':
                    from openai.resources.responses.responses import Responses
                    Responses.create = original
                elif key == 'openai.chat.completions.create':
                    from openai.resources.chat.completions.completions import Completions
                    Completions.create = original
                elif key == 'anthropic.messages.create':
                    import anthropic
                    anthropic.resources.messages.Messages.create = original
                elif key == 'subprocess.Popen':
                    subprocess.Popen = original
                elif key == 'subprocess.run':
                    subprocess.run = original
            except Exception:
                pass
        _runtime_patches.restore_extended(_ORIGINALS)
        _ORIGINALS.clear()
        _remove_import_hook()
        _PATCHED = False
        get_coverage_registry().reset()


def patch_runtime(guard: VardenGuard) -> None:
    global _PATCHED
    with _PATCH_LOCK:
        _install_import_hook()
        _patch_requests(guard)
        _patch_httpx(guard)
        _patch_openai(guard)
        _patch_anthropic(guard)
        _patch_subprocess(guard)
        _runtime_patches.patch_subprocess_extended(guard, _ORIGINALS)
        _runtime_patches.patch_urllib(guard, _ORIGINALS)
        _runtime_patches.patch_filesystem(guard, _ORIGINALS)
        reg = get_coverage_registry()
        if 'requests.sessions.Session.request' in _ORIGINALS:
            reg.mark('http.requests', status=ENFORCED, interceptor='requests.Session.request', active=True, applicable=True)

            def _check_requests():
                try:
                    import requests
                    return requests.sessions.Session.request is not _ORIGINALS.get('requests.sessions.Session.request')
                except Exception:
                    return False

            reg.register_interceptor_check('http.requests', _check_requests)
        if 'httpx.Client.send' in _ORIGINALS:
            reg.mark('http.httpx', status=ENFORCED, interceptor='httpx.Client/AsyncClient.send', active=True, applicable=True)

            def _check_httpx():
                return httpx.Client.send is not _ORIGINALS.get('httpx.Client.send')

            reg.register_interceptor_check('http.httpx', _check_httpx)
        reg.mark('http.raw_sockets', status=UNCOVERED, active=False, applicable=True)
        reg.mark('http.aiohttp', status='UNSUPPORTED', active=False, applicable=True)
        reg.mark('http.urllib3', status=UNCOVERED, active=False, applicable=True)
        if 'subprocess.Popen' in _ORIGINALS:
            reg.mark('subprocess', status=ENFORCED, interceptor='subprocess.*', active=True, applicable=True)

            def _check_subprocess():
                return subprocess.Popen is not _ORIGINALS.get('subprocess.Popen')

            reg.register_interceptor_check('subprocess', _check_subprocess)
        if 'openai.responses.create' in _ORIGINALS or 'openai.chat.completions.create' in _ORIGINALS:
            reg.mark('llm.openai', status=ENFORCED, interceptor='openai', active=True, applicable=True)
        if 'anthropic.messages.create' in _ORIGINALS:
            reg.mark('llm.anthropic', status=ENFORCED, interceptor='anthropic', active=True, applicable=True)
        # MCP stays non-applicable until discover()/gateway marks it. Do not
        # claim NOT_ROUTED merely because protect() ran without MCP configs.
        _PATCHED = True


def _patch_module_for_name(fullname: str, guard: VardenGuard) -> None:
    root = fullname.split('.', 1)[0]
    if root == 'requests':
        _patch_requests(guard)
    elif root == 'httpx':
        _patch_httpx(guard)
    elif root == 'openai':
        _patch_openai(guard)
    elif root == 'anthropic':
        _patch_anthropic(guard)
    elif root == 'subprocess':
        _patch_subprocess(guard)
        _runtime_patches.patch_subprocess_extended(guard, _ORIGINALS)
    elif root == 'urllib':
        _runtime_patches.patch_urllib(guard, _ORIGINALS)
    elif root == 'pathlib':
        _runtime_patches.patch_filesystem(guard, _ORIGINALS)




def _is_control_plane_request(url: str | None, guard: VardenGuard) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(str(url))
        if parsed.hostname in {"testserver", "test"}:
            return True
        return str(url).startswith(guard.client.base_url.rstrip('/'))
    except Exception:
        return False
def _patch_requests(guard: VardenGuard) -> None:
    try:
        import requests
    except Exception:
        return
    key = 'requests.sessions.Session.request'
    if key in _ORIGINALS:
        return
    _ORIGINALS[key] = requests.sessions.Session.request

    @functools.wraps(_ORIGINALS[key])
    def wrapper(self, method: str, url: str, *args: Any, **kwargs: Any):
        current = current_guard() or guard
        if _is_control_plane_request(url, current):
            return _ORIGINALS[key](self, method, url, *args, **kwargs)
        body = kwargs.get('json')
        if body is None:
            body = _decode_body_value(kwargs.get('data'))
        payload = {'args': list(args), 'kwargs': _json_safe(kwargs), 'body': _json_safe(body)}
        result = current.guarded_action(type='http_request', tool='requests', url=url, method=method.upper(), args=payload, payload=payload, metadata={'runtime': {'surface': 'http', 'boundary': True}})
        if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
            raise VardenBlockedError(f'HTTP request to {url} blocked', result.decision)
        try:
            response = _ORIGINALS[key](self, method, url, *args, **kwargs)
            if result:
                current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload={'status_code': getattr(response, 'status_code', None), 'url': str(getattr(response, 'url', url))})
            return response
        except Exception as exc:
            if result:
                current.record_result(action=result.action, decision=result.decision, input_payload=payload, error=str(exc))
            raise
    requests.sessions.Session.request = wrapper


def _patch_httpx(guard: VardenGuard) -> None:
    key = 'httpx.Client.send'
    if key not in _ORIGINALS:
        _ORIGINALS[key] = httpx.Client.send

        @functools.wraps(_ORIGINALS[key])
        def send_wrapper(self, request: httpx.Request, *args: Any, **kwargs: Any):
            current = current_guard() or guard
            request_url = str(request.url)
            if _is_control_plane_request(request_url, current):
                return _ORIGINALS[key](self, request, *args, **kwargs)
            body = _extract_httpx_body(request)
            payload = {'headers': dict(request.headers), 'method': request.method, 'body': _json_safe(body)}
            result = current.guarded_action(type='http_request', tool='httpx', url=request_url, method=request.method, args=payload, payload=payload, metadata={'runtime': {'surface': 'http', 'boundary': True}})
            if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                raise VardenBlockedError(f'HTTPX request to {request.url} blocked', result.decision)
            try:
                response = _ORIGINALS[key](self, request, *args, **kwargs)
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload={'status_code': response.status_code, 'url': str(request.url)})
                return response
            except Exception as exc:
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, error=str(exc))
                raise
        httpx.Client.send = send_wrapper

    key_async = 'httpx.AsyncClient.send'
    if key_async not in _ORIGINALS:
        _ORIGINALS[key_async] = httpx.AsyncClient.send

        @functools.wraps(_ORIGINALS[key_async])
        async def send_async_wrapper(self, request: httpx.Request, *args: Any, **kwargs: Any):
            current = current_guard() or guard
            request_url = str(request.url)
            if _is_control_plane_request(request_url, current):
                return await _ORIGINALS[key_async](self, request, *args, **kwargs)
            body = _extract_httpx_body(request)
            payload = {'headers': dict(request.headers), 'method': request.method, 'body': _json_safe(body)}
            result = current.guarded_action(type='http_request', tool='httpx_async', url=request_url, method=request.method, args=payload, payload=payload, metadata={'runtime': {'surface': 'http', 'boundary': True}})
            if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                raise VardenBlockedError(f'HTTPX request to {request.url} blocked', result.decision)
            try:
                response = await _ORIGINALS[key_async](self, request, *args, **kwargs)
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload={'status_code': response.status_code, 'url': str(request.url)})
                return response
            except Exception as exc:
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, error=str(exc))
                raise
        httpx.AsyncClient.send = send_async_wrapper


def _llm_usage_output_payload(provider: str, response: Any, *, kwargs: dict[str, Any] | None = None) -> dict[str, Any]:
    usage_raw = getattr(response, "usage", None)
    model = getattr(response, "model", None) or (kwargs or {}).get("model")
    usage: dict[str, Any] = {}
    if usage_raw is not None:
        if hasattr(usage_raw, "model_dump"):
            usage = usage_raw.model_dump()
        elif isinstance(usage_raw, dict):
            usage = usage_raw
        else:
            usage = {
                "input_tokens": getattr(usage_raw, "input_tokens", None) or getattr(usage_raw, "prompt_tokens", None),
                "output_tokens": getattr(usage_raw, "output_tokens", None) or getattr(usage_raw, "completion_tokens", None),
            }
    normalized = {
        "input_tokens": int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0),
        "output_tokens": int(usage.get("output_tokens") or usage.get("completion_tokens") or 0),
    }
    return {
        "provider": provider,
        "model": model,
        "usage": normalized,
        "object": getattr(response, "object", None),
    }


def _patch_openai(guard: VardenGuard) -> None:
    try:
        from openai.resources.responses.responses import Responses
    except Exception:
        Responses = None
    if Responses is not None:
        key = 'openai.responses.create'
        if key not in _ORIGINALS:
            _ORIGINALS[key] = Responses.create

            @functools.wraps(_ORIGINALS[key])
            def wrapper(self, *args: Any, **kwargs: Any):
                current = current_guard() or guard
                payload = {'args': _json_safe(args), 'kwargs': _json_safe(kwargs)}
                result = current.guarded_action(type='llm_call', tool='openai.responses.create', args=payload, payload=payload)
                if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                    raise VardenBlockedError('OpenAI response call blocked', result.decision)
                response = _ORIGINALS[key](self, *args, **kwargs)
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload=_llm_usage_output_payload('openai', response, kwargs=kwargs))
                return response
            Responses.create = wrapper

    try:
        from openai.resources.chat.completions.completions import Completions
    except Exception:
        Completions = None
    if Completions is not None:
        key = 'openai.chat.completions.create'
        if key not in _ORIGINALS:
            _ORIGINALS[key] = Completions.create

            @functools.wraps(_ORIGINALS[key])
            def wrapper(self, *args: Any, **kwargs: Any):
                current = current_guard() or guard
                payload = {'args': _json_safe(args), 'kwargs': _json_safe(kwargs)}
                result = current.guarded_action(type='llm_call', tool='openai.chat.completions.create', args=payload, payload=payload)
                if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                    raise VardenBlockedError('OpenAI chat completion blocked', result.decision)
                response = _ORIGINALS[key](self, *args, **kwargs)
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload=_llm_usage_output_payload('openai', response, kwargs=kwargs))
                return response
            Completions.create = wrapper


def _patch_anthropic(guard: VardenGuard) -> None:
    try:
        import anthropic
        Messages = anthropic.resources.messages.Messages
    except Exception:
        Messages = None
    if Messages is not None:
        key = 'anthropic.messages.create'
        if key not in _ORIGINALS:
            _ORIGINALS[key] = Messages.create

            @functools.wraps(_ORIGINALS[key])
            def wrapper(self, *args: Any, **kwargs: Any):
                current = current_guard() or guard
                payload = {'args': _json_safe(args), 'kwargs': _json_safe(kwargs)}
                result = current.guarded_action(type='llm_call', tool='anthropic.messages.create', args=payload, payload=payload)
                if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                    raise VardenBlockedError('Anthropic message blocked', result.decision)
                response = _ORIGINALS[key](self, *args, **kwargs)
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload=_llm_usage_output_payload('anthropic', response, kwargs=kwargs))
                return response
            Messages.create = wrapper


def _patch_subprocess(guard: VardenGuard) -> None:
    key = 'subprocess.Popen'
    if key not in _ORIGINALS:
        _ORIGINALS[key] = subprocess.Popen

        class GuardedPopen(subprocess.Popen):
            def __init__(self, args, *pargs, **kwargs):
                current = current_guard() or guard
                payload = {'args': _json_safe(args), 'kwargs': _json_safe(kwargs)}
                result = current.guarded_action(type='tool_call', tool='subprocess.Popen', args=payload, payload=payload, metadata={'execution_surface': 'subprocess'})
                if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                    raise VardenBlockedError('Subprocess execution blocked', result.decision)
                super().__init__(args, *pargs, **kwargs)
                if result:
                    current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload={'pid': getattr(self, 'pid', None)})
        subprocess.Popen = GuardedPopen

    key_run = 'subprocess.run'
    if key_run not in _ORIGINALS:
        _ORIGINALS[key_run] = subprocess.run

        @functools.wraps(_ORIGINALS[key_run])
        def run_wrapper(*popenargs, **kwargs):
            current = current_guard() or guard
            payload = {'args': _json_safe(list(popenargs)), 'kwargs': _json_safe(kwargs)}
            result = current.guarded_action(type='tool_call', tool='subprocess.run', args=payload, payload=payload, metadata={'execution_surface': 'subprocess'})
            if result and result.blocked and is_enforcing(getattr(current, 'product_mode', current.mode)):
                raise VardenBlockedError('Subprocess execution blocked', result.decision)
            response = _ORIGINALS[key_run](*popenargs, **kwargs)
            if result:
                current.record_result(action=result.action, decision=result.decision, input_payload=payload, output_payload={'returncode': getattr(response, 'returncode', None)})
            return response
        subprocess.run = run_wrapper


def protect_from_env(**overrides: Any) -> VardenGuard:
    raw_fail = os.getenv('VARDEN_FAIL_MODE')
    # Unset → None so VardenGuard applies mode-based default (enforce→closed).
    # Explicit open/closed from the environment is respected and, for open+enforce,
    # emits a conspicuous warning in VardenGuard.__init__.
    resolved_fail = raw_fail if raw_fail in {'open', 'closed'} else None
    cfg = {
        'base_url': os.getenv('VARDEN_BASE_URL', 'http://127.0.0.1:8000'),
        'api_key': os.getenv('VARDEN_API_KEY'),
        'bearer_token': os.getenv('VARDEN_BEARER_TOKEN'),
        'app_name': os.getenv('VARDEN_APP_NAME', 'python-app'),
        'tenant': os.getenv('VARDEN_TENANT', 'default'),
        'mode': os.getenv('VARDEN_MODE', 'guarded'),
        'auto_instrument': os.getenv('VARDEN_AUTO_INSTRUMENT', 'true').lower() == 'true',
        'fail_mode': resolved_fail,
        'timeout': float(os.getenv('VARDEN_TIMEOUT', '5.0')),
    }
    cfg.update({k: v for k, v in overrides.items() if v is not None})
    return protect(**cfg)


def protect(**kwargs: Any) -> VardenGuard:
    guard = VardenGuard(**kwargs).activate()
    atexit.register(unpatch_runtime)
    return guard


def tagged(value: Any, *, lineage: list[str] | None = None, classification: str | None = None, metadata: dict[str, Any] | None = None, source: str | None = None, **extra: Any) -> TaggedData:
    computed_lineage = list(lineage or ([] if source is None else [source]))
    computed_meta = dict(metadata or {})
    computed_meta.update(extra)
    return TaggedData(value=value, lineage=computed_lineage, classification=classification, metadata=computed_meta)


def observe_provenance(
    *,
    source_type: str = "unknown",
    origin: str = "",
    trust_level: str = "untrusted",
    principal: str = "",
    provenance_complete: bool = False,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Attach an observed provenance source to the current causal context.

    Client-side trust claims of ``trusted``/``delegated`` are downgraded to
    ``unknown`` — only the control plane can mint verified trust.
    """
    if trust_level in {"trusted", "delegated"}:
        trust_level = "unknown"
    entry = {
        "source_type": source_type,
        "origin": origin,
        "principal": principal,
        "trust_level": trust_level,
        "integrity": "unverified",
        "provenance_complete": bool(provenance_complete),
        "metadata": dict(metadata or {}),
    }
    current = list(_current_provenance.get() or [])
    current.append(entry)
    _current_provenance.set(current)


@contextmanager
def provenance_scope(sources: list[dict[str, Any]] | None = None):
    token = _current_provenance.set(list(sources or []))
    try:
        yield
    finally:
        _current_provenance.reset(token)


def register_tool(
    name: str,
    *,
    authorities: list[str] | None = None,
    sensitivity: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Register tool authority metadata on the active guard (optional precision)."""
    guard = current_guard()
    if guard is None:
        raise RuntimeError("register_tool requires an active varden.protect() guard")
    guard.register_tool(name, authorities=authorities, sensitivity=sensitivity, metadata=metadata)


def tool(name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any):
                guard = current_guard()
                wrapped = guard.guard_tool(fn, name=name) if guard else fn
                return await wrapped(*args, **kwargs)
            return async_wrapper
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            guard = current_guard()
            wrapped = guard.guard_tool(fn, name=name) if guard else fn
            return wrapped(*args, **kwargs)
        return wrapper
    return decorator


@contextmanager
def trace_agent(agent_name: str, workflow_id: str | None = None, lineage: dict[str, Any] | None = None, trace_id: str | None = None, provenance: list[dict[str, Any]] | None = None):
    tok_agent = _current_agent.set(agent_name)
    effective_workflow_id = workflow_id or str(uuid.uuid4())
    effective_trace_id = trace_id or effective_workflow_id
    tok_workflow = _current_workflow.set(effective_workflow_id)
    tok_lineage = _current_lineage.set(lineage or {})
    tok_trace = _current_trace_id.set(effective_trace_id)
    tok_parent = _current_parent_event_id.set(None)
    tok_prov = _current_provenance.set(list(provenance or []))
    try:
        yield {'agent_name': agent_name, 'workflow_id': _current_workflow.get(), 'trace_id': _current_trace_id.get()}
    finally:
        _current_agent.reset(tok_agent)
        _current_workflow.reset(tok_workflow)
        _current_lineage.reset(tok_lineage)
        _current_trace_id.reset(tok_trace)
        _current_parent_event_id.reset(tok_parent)
        _current_provenance.reset(tok_prov)
