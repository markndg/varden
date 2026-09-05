"""Additional runtime boundary patches (filesystem, urllib, expanded subprocess)."""

from __future__ import annotations

import builtins
import functools
import os
import subprocess
from typing import Any, Callable

from varden.runtime.coverage import ENFORCED, PARTIAL, get_coverage_registry
from varden.runtime.filesystem import classify_path
from varden.runtime.modes import is_enforcing

SHELL_ELEVATED = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "fish",
        "powershell",
        "pwsh",
        "cmd",
        "python",
        "python3",
        "node",
        "ruby",
        "perl",
        "php",
    }
)


def _enforcing(guard: Any) -> bool:
    mode = getattr(guard, "product_mode", None) or getattr(guard, "mode", None)
    return is_enforcing(mode) or mode == "enforce"


def _blocked_error(guard: Any):
    from varden_sdk.sdk import VardenBlockedError

    return VardenBlockedError


def patch_urllib(guard: Any, originals: dict[str, Any]) -> None:
    try:
        import urllib.request as urllib_request
    except Exception:
        return
    key = "urllib.request.urlopen"
    if key in originals:
        return
    originals[key] = urllib_request.urlopen

    @functools.wraps(originals[key])
    def wrapper(url, *args, **kwargs):
        from varden_sdk.sdk import current_guard

        current = current_guard() or guard
        url_s = url if isinstance(url, str) else getattr(url, "full_url", None) or str(url)
        if hasattr(current, "_is_control_plane_url") and current._is_control_plane_url(url_s):
            return originals[key](url, *args, **kwargs)
        payload = {"url": url_s, "args": list(args), "kwargs": {k: str(type(v)) for k, v in kwargs.items()}}
        result = current.guarded_action(
            type="http_request",
            tool="urllib",
            url=str(url_s),
            method="GET",
            args=payload,
            payload=payload,
            metadata={"runtime": {"surface": "http", "boundary": True}},
        )
        if result and result.blocked and _enforcing(current):
            raise _blocked_error(current)(f"urllib request to {url_s} blocked", result.decision)
        return originals[key](url, *args, **kwargs)

    urllib_request.urlopen = wrapper
    get_coverage_registry().mark(
        "http.urllib",
        status=ENFORCED,
        interceptor="urllib.request.urlopen",
        active=True,
        applicable=True,
        enforcement_mode="enforced",
    )


def patch_filesystem(guard: Any, originals: dict[str, Any]) -> None:
    import contextvars

    _fs_depth: contextvars.ContextVar[int] = contextvars.ContextVar("varden_fs_depth", default=0)

    def _should_enforce(path: Any, mode: str, info: dict[str, Any]) -> bool:
        # Secrets/system always; supply-chain workspace mutations always.
        if info.get("classification") in {"secrets", "system"}:
            return True
        mutation = str(info.get("mutation") or "")
        if mutation in {"WRITE_CI", "WRITE_CONFIG", "WRITE_CODE"}:
            return True
        return False

    key = "builtins.open"
    if key not in originals:
        originals[key] = builtins.open

        @functools.wraps(originals[key])
        def open_wrapper(file, *args, **kwargs):
            from varden_sdk.sdk import current_guard

            if _fs_depth.get() > 0:
                return originals[key](file, *args, **kwargs)
            token = _fs_depth.set(_fs_depth.get() + 1)
            try:
                current = current_guard() or guard
                path = file if isinstance(file, (str, os.PathLike)) else None
                if path is not None:
                    mode = args[0] if args else kwargs.get("mode", "r")
                    info = classify_path(path, workspace=os.getcwd(), mode=str(mode))
                    if _should_enforce(path, mode, info):
                        payload = {"path": str(path), "mode": mode, "classification": info}
                        result = current.guarded_action(
                            type="filesystem",
                            tool="open",
                            args=payload,
                            payload=payload,
                            metadata={
                                "runtime": {"surface": "filesystem", "boundary": True},
                                "filesystem": info,
                                "sensitivity": info.get("sensitivity"),
                                "mutation": info.get("mutation"),
                                "required_authority": info.get("required_authority"),
                            },
                        )
                        if result and result.blocked and _enforcing(current):
                            raise _blocked_error(current)(f"filesystem open blocked: {path}", result.decision)
                return originals[key](file, *args, **kwargs)
            finally:
                _fs_depth.reset(token)

        builtins.open = open_wrapper

    try:
        from pathlib import Path

        key_po = "pathlib.Path.open"
        if key_po not in originals:
            originals[key_po] = Path.open

            @functools.wraps(originals[key_po])
            def path_open(self, *args, **kwargs):
                from varden_sdk.sdk import current_guard

                if _fs_depth.get() > 0:
                    return originals[key_po](self, *args, **kwargs)
                token = _fs_depth.set(_fs_depth.get() + 1)
                try:
                    current = current_guard() or guard
                    mode = args[0] if args else kwargs.get("mode", "r")
                    info = classify_path(self, workspace=os.getcwd(), mode=str(mode))
                    if _should_enforce(self, mode, info):
                        payload = {"path": str(self), "classification": info, "mode": mode}
                        result = current.guarded_action(
                            type="filesystem",
                            tool="pathlib.Path.open",
                            args=payload,
                            payload=payload,
                            metadata={"runtime": {"surface": "filesystem", "boundary": True}, "filesystem": info},
                        )
                        if result and result.blocked and _enforcing(current):
                            raise _blocked_error(current)(f"filesystem Path.open blocked: {self}", result.decision)
                    return originals[key_po](self, *args, **kwargs)
                finally:
                    _fs_depth.reset(token)

            Path.open = path_open
    except Exception:
        pass

    for name, fn_name in (("os.remove", "remove"), ("os.unlink", "unlink"), ("os.rename", "rename"), ("os.replace", "replace")):
        if not hasattr(os, fn_name):
            continue
        key_os = name
        if key_os in originals:
            continue
        originals[key_os] = getattr(os, fn_name)

        def _make(original: Callable[..., Any], tool: str):
            @functools.wraps(original)
            def wrapper(*args, **kwargs):
                from varden_sdk.sdk import current_guard

                if _fs_depth.get() > 0:
                    return original(*args, **kwargs)
                token = _fs_depth.set(_fs_depth.get() + 1)
                try:
                    current = current_guard() or guard
                    path = args[0] if args else None
                    info = classify_path(path, workspace=os.getcwd(), mode='w') if path is not None else {}
                    if _should_enforce(path, "w", info):
                        payload = {"args": [str(a) for a in args], "classification": info}
                        result = current.guarded_action(
                            type="filesystem",
                            tool=tool,
                            args=payload,
                            payload=payload,
                            metadata={"runtime": {"surface": "filesystem", "boundary": True}, "filesystem": info},
                        )
                        if result and result.blocked and _enforcing(current):
                            raise _blocked_error(current)(f"filesystem {tool} blocked", result.decision)
                    return original(*args, **kwargs)
                finally:
                    _fs_depth.reset(token)

            return wrapper

        setattr(os, fn_name, _make(originals[key_os], name))

    get_coverage_registry().mark(
        "filesystem",
        status=PARTIAL,
        interceptor="builtins.open+pathlib+os.remove/unlink/rename/replace",
        active=True,
        applicable=True,
        enforcement_mode="partial",
        limitations=[
            "Python filesystem APIs: ENFORCED for secrets/system paths",
            "Benign workspace/home reads and writes may not hit the control plane",
            "Native extensions / external processes: PARTIAL",
            "OS-global filesystem: NOT GUARANTEED",
        ],
    )



def _subprocess_meta(args: Any) -> dict[str, Any]:
    argv = args
    if isinstance(args, (str, bytes)):
        argv = [args]
    try:
        seq = list(argv)
    except Exception:
        seq = [str(args)]
    exe = str(seq[0]) if seq else ""
    base = os.path.basename(exe).lower()
    elevated = False
    if base in SHELL_ELEVATED:
        elevated = True
    join = " ".join(str(x) for x in seq)
    for marker in (" -c ", " /c ", " -e ", " -r ", "bash -c", "sh -c", "zsh -c", "python -c", "node -e"):
        if marker in f" {join} " or join.startswith(marker.strip()):
            elevated = True
    return {
        "execution_surface": "subprocess",
        "runtime": {"surface": "subprocess", "boundary": True},
        "subprocess": {"executable": exe, "argv": [str(x) for x in seq], "elevated_uncertainty": elevated},
        "authority_hint": "ADMIN" if elevated else "EXECUTE",
    }


def patch_subprocess_extended(guard: Any, originals: dict[str, Any]) -> None:
    """Cover call/check_call/check_output/os.system/os.popen beyond Popen/run."""
    for attr in ("call", "check_call", "check_output"):
        key = f"subprocess.{attr}"
        if key in originals or not hasattr(subprocess, attr):
            continue
        originals[key] = getattr(subprocess, attr)

        def _make(original: Callable[..., Any], tool: str):
            @functools.wraps(original)
            def wrapper(*popenargs, **kwargs):
                from varden_sdk.sdk import current_guard

                current = current_guard() or guard
                args0 = popenargs[0] if popenargs else kwargs.get("args")
                meta = _subprocess_meta(args0)
                payload = {"args": list(popenargs), "kwargs": {k: str(type(v)) for k, v in kwargs.items()}}
                result = current.guarded_action(
                    type="tool_call",
                    tool=tool,
                    args=payload,
                    payload=payload,
                    metadata=meta,
                )
                if result and result.blocked and _enforcing(current):
                    raise _blocked_error(current)("Subprocess execution blocked", result.decision)
                return original(*popenargs, **kwargs)

            return wrapper

        setattr(subprocess, attr, _make(originals[key], key))

    if "os.system" not in originals:
        originals["os.system"] = os.system

        @functools.wraps(originals["os.system"])
        def system_wrapper(command):
            from varden_sdk.sdk import current_guard

            current = current_guard() or guard
            meta = _subprocess_meta(["sh", "-c", str(command)])
            payload = {"command": str(command)}
            result = current.guarded_action(
                type="tool_call",
                tool="os.system",
                args=payload,
                payload=payload,
                metadata=meta,
            )
            if result and result.blocked and _enforcing(current):
                raise _blocked_error(current)("os.system blocked", result.decision)
            return originals["os.system"](command)

        os.system = system_wrapper

    if "os.popen" not in originals:
        originals["os.popen"] = os.popen

        @functools.wraps(originals["os.popen"])
        def popen_wrapper(command, *args, **kwargs):
            from varden_sdk.sdk import current_guard

            current = current_guard() or guard
            meta = _subprocess_meta(["sh", "-c", str(command)])
            payload = {"command": str(command)}
            result = current.guarded_action(
                type="tool_call",
                tool="os.popen",
                args=payload,
                payload=payload,
                metadata=meta,
            )
            if result and result.blocked and _enforcing(current):
                raise _blocked_error(current)("os.popen blocked", result.decision)
            return originals["os.popen"](command, *args, **kwargs)

        os.popen = popen_wrapper

    # asyncio subprocess
    try:
        import asyncio

        for attr in ("create_subprocess_exec", "create_subprocess_shell"):
            key = f"asyncio.{attr}"
            if key in originals or not hasattr(asyncio, attr):
                continue
            originals[key] = getattr(asyncio, attr)

            def _make_async(original: Callable[..., Any], tool: str):
                @functools.wraps(original)
                async def wrapper(*args, **kwargs):
                    from varden_sdk.sdk import current_guard

                    current = current_guard() or guard
                    meta = _subprocess_meta(args[0] if tool.endswith("shell") else args)
                    payload = {"args": [str(a) for a in args[:8]], "tool": tool}
                    result = current.guarded_action(
                        type="tool_call",
                        tool=tool,
                        args=payload,
                        payload=payload,
                        metadata=meta,
                    )
                    if result and result.blocked and _enforcing(current):
                        raise _blocked_error(current)("asyncio subprocess blocked", result.decision)
                    return await original(*args, **kwargs)

                return wrapper

            setattr(asyncio, attr, _make_async(originals[key], key))
    except Exception:
        pass

    get_coverage_registry().mark(
        "subprocess",
        status=ENFORCED,
        interceptor="subprocess+os.system/popen+asyncio",
        active=True,
        enforcement_mode="enforced",
        limitations=[
            "Saved pre-patch function references bypass monkeypatching.",
            "Native forks from extensions are outside Python hooks.",
        ],
    )


def restore_extended(originals: dict[str, Any]) -> None:
    mapping = {
        "urllib.request.urlopen": ("urllib.request", "urlopen"),
        "builtins.open": None,
        "os.system": ("os", "system"),
        "os.popen": ("os", "popen"),
        "os.remove": ("os", "remove"),
        "os.unlink": ("os", "unlink"),
        "os.rename": ("os", "rename"),
        "os.replace": ("os", "replace"),
        "subprocess.call": ("subprocess", "call"),
        "subprocess.check_call": ("subprocess", "check_call"),
        "subprocess.check_output": ("subprocess", "check_output"),
        "asyncio.create_subprocess_exec": ("asyncio", "create_subprocess_exec"),
        "asyncio.create_subprocess_shell": ("asyncio", "create_subprocess_shell"),
    }
    for key, original in list(originals.items()):
        try:
            if key == "builtins.open":
                builtins.open = original
            elif key == "pathlib.Path.open":
                from pathlib import Path

                Path.open = original
            elif key in mapping and mapping[key]:
                mod_name, attr = mapping[key]
                mod = __import__(mod_name)
                if mod_name == "urllib.request":
                    import urllib.request as mod
                setattr(mod, attr, original)
        except Exception:
            pass
