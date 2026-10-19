"""Additional runtime boundary patches (filesystem, urllib, expanded subprocess)."""

from __future__ import annotations

import builtins
import functools
import os
import subprocess
from typing import Any, Callable

from varden.runtime.coverage import ENFORCED, PARTIAL, UNCOVERED, get_coverage_registry
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
    """Whether side effects must be blocked on deny.

    Locked ``enforcement_contract()`` is authoritative — a mutated or swapped
    live guard cannot silently observe-out of enforcement.
    """
    try:
        contract = get_coverage_registry().enforcement_contract()
    except Exception:
        # Cannot read the lock. Do not trust mutable guard attributes.
        return True
    if contract.get("mode_locked"):
        mode = contract.get("mode")
        return is_enforcing(mode) or mode == "enforce"
    mode = getattr(guard, "product_mode", None) or getattr(guard, "mode", None)
    return is_enforcing(mode) or mode == "enforce"


def _fail_closed(guard: Any) -> bool:
    try:
        contract = get_coverage_registry().enforcement_contract()
    except Exception:
        return True
    if contract.get("mode_locked"):
        return str(contract.get("fail_mode") or "").lower() == "closed"
    return str(getattr(guard, "fail_mode", "") or "").lower() == "closed"


def _blocked_error(guard: Any):
    from varden_sdk.sdk import VardenBlockedError

    return VardenBlockedError


def _call_path(args: tuple[Any, ...], kwargs: dict[str, Any], index: int, names: tuple[str, ...]) -> Any:
    """Read a path from positional arguments or the matching keyword.

    ``os.remove(path=...)`` and ``os.rename(src=..., dst=...)`` are real
    Python calls. Looking only at ``args`` skips mediation and still runs
    the original function.
    """
    if len(args) > index:
        return args[index]
    for name in names:
        if name in kwargs:
            return kwargs[name]
    return None


def _os_open_writes(flags: Any) -> bool:
    try:
        value = int(flags)
    except (TypeError, ValueError):
        return True
    write_bits = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    return bool(value & write_bits)


def patch_urllib(guard: Any, originals: dict[str, Any]) -> None:
    try:
        import urllib.request as urllib_request
    except Exception:
        return
    from varden_sdk import sdk as sdk_mod

    key = "urllib.request.urlopen"
    wrapper = sdk_mod._WRAPPERS.get(key)
    if key in originals and wrapper is not None and urllib_request.urlopen is wrapper:
        return
    if key not in originals:
        originals[key] = urllib_request.urlopen
    elif urllib_request.urlopen is not originals[key] and wrapper is None:
        # Foreign wrapper — do not fight; leave attestation to verify.
        return
    original = originals[key]

    @functools.wraps(original)
    def wrapper(url, *args, **kwargs):
        from varden_sdk.sdk import _authorize_http, current_guard

        current = current_guard() or guard
        url_s = url if isinstance(url, str) else getattr(url, "full_url", None) or str(url)
        if hasattr(current, "_is_control_plane_url") and current._is_control_plane_url(url_s):
            return original(url, *args, **kwargs)
        payload = {"url": url_s, "args": list(args), "kwargs": {k: str(type(v)) for k, v in kwargs.items()}}
        canonical, _result = _authorize_http(
            current,
            tool="urllib",
            url=str(url_s),
            method="GET",
            args=payload,
            payload=payload,
            metadata={"runtime": {"surface": "http", "boundary": True}},
        )
        target = canonical if isinstance(url, str) else url
        if not isinstance(url, str) and hasattr(url, "full_url") and canonical != url_s:
            try:
                url.full_url = canonical
            except Exception:
                target = canonical
        return original(target, *args, **kwargs)

    urllib_request.urlopen = wrapper
    sdk_mod._WRAPPERS[key] = wrapper
    redirect_key = "urllib.request.HTTPRedirectHandler.redirect_request"
    if redirect_key not in originals:
        originals[redirect_key] = urllib_request.HTTPRedirectHandler.redirect_request

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            from varden_sdk.sdk import _authorize_http, current_guard

            current = current_guard() or guard
            payload = {"url": str(newurl), "redirect_from": getattr(req, "full_url", None)}
            canonical, _result = _authorize_http(
                current,
                tool="urllib",
                url=str(newurl),
                method="GET",
                args=payload,
                payload=payload,
                metadata={"runtime": {"surface": "http", "boundary": True, "redirect": True}},
            )
            return originals[redirect_key](self, req, fp, code, msg, headers, canonical)

        urllib_request.HTTPRedirectHandler.redirect_request = redirect_request
    try:
        get_coverage_registry().install_interceptor(
            "http.urllib",
            checker=lambda: urllib_request.urlopen is wrapper,
            interceptor="urllib.request.urlopen",
        )
    except RuntimeError:
        get_coverage_registry().mark(
            "http.urllib",
            status=UNCOVERED,
            active=False,
            installed=True,
            verified=False,
            applicable=True,
        )


def patch_filesystem(guard: Any, originals: dict[str, Any]) -> None:
    import contextvars

    from varden.runtime import filesystem as fs_mod

    _fs_depth: contextvars.ContextVar[int] = contextvars.ContextVar("varden_fs_depth", default=0)

    def _should_enforce(path: Any, mode: str, info: dict[str, Any]) -> bool:
        # Secrets/system always; supply-chain workspace mutations always.
        if info.get("classification") in {"secrets", "system"}:
            return True
        mutation = str(info.get("mutation") or "")
        if mutation in {"WRITE_CI", "WRITE_CONFIG", "WRITE_CODE"}:
            return True
        return False

    def _ambiguous_resolution_blocks(current: Any, path: Any, mode: str, info: dict[str, Any]) -> bool:
        if not (fs_mod.resolution_blocks_under_fail_closed(info) and _enforcing(current) and _fail_closed(current)):
            return False
        return bool(
            _should_enforce(path, mode, info)
            or info.get("symlink_involved")
            or info.get("classification") in {"secrets", "system", "unknown"}
        )

    def _guard_filesystem(
        current: Any,
        *,
        tool: str,
        path: Any,
        mode: str,
        info: dict[str, Any],
        payload: dict[str, Any],
        metadata_extra: dict[str, Any] | None = None,
    ) -> None:
        """Raise when policy blocks or when fail-closed resolution is ambiguous."""
        if _ambiguous_resolution_blocks(current, path, mode, info):
            raise _blocked_error(current)(
                f"filesystem {tool} blocked: path resolution failed ({info.get('resolution')})",
                {"action": "block", "reason": f"filesystem_resolution_{info.get('resolution')}"},
            )

        if not _should_enforce(path, mode, info):
            return
        meta = {
            "runtime": {"surface": "filesystem", "boundary": True},
            "filesystem": info,
            "sensitivity": info.get("sensitivity"),
            "mutation": info.get("mutation"),
            "required_authority": info.get("required_authority"),
        }
        if metadata_extra:
            meta.update(metadata_extra)
        result = current.guarded_action(
            type="filesystem",
            tool=tool,
            args=payload,
            payload=payload,
            metadata=meta,
        )
        if result and result.blocked and _enforcing(current):
            raise _blocked_error(current)(f"filesystem {tool} blocked: {path}", result.decision)

    def _recheck_effective_target(
        current: Any,
        *,
        tool: str,
        path: Any,
        mode: str,
        prior_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Re-resolve immediately before the underlying call (TOCTOU narrowing).

        Does not claim race-free mediation. If the effective target changed to a
        newly security-sensitive destination after policy evaluation, fail closed
        under enforcing + fail-closed modes.
        """
        fresh = fs_mod.classify_path(path, workspace=os.getcwd(), mode=str(mode))
        prior_eff = prior_info.get("real_path")
        fresh_eff = fresh.get("real_path")
        mutated = prior_eff != fresh_eff or (
            bool(fresh.get("symlink_involved")) and not bool(prior_info.get("symlink_involved"))
        )
        if not mutated:
            return fresh
        if not (_enforcing(current) and _fail_closed(current)):
            return fresh
        if _should_enforce(path, mode, fresh) or fs_mod.resolution_blocks_under_fail_closed(fresh):
            raise _blocked_error(current)(
                f"filesystem {tool} blocked: effective target changed between check and use",
                {"action": "block", "reason": "filesystem_toctou_target_changed"},
            )
        if fresh.get("classification") in {"secrets", "system"} or fresh.get("mutation") in {
            "WRITE_CI",
            "WRITE_CONFIG",
            "WRITE_CODE",
        }:
            raise _blocked_error(current)(
                f"filesystem {tool} blocked: effective target changed between check and use",
                {"action": "block", "reason": "filesystem_toctou_target_changed"},
            )
        return fresh

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
                    info = fs_mod.classify_path(path, workspace=os.getcwd(), mode=str(mode))
                    payload = {
                        "path": str(path),
                        "mode": mode,
                        "classification": info,
                        "effective_path": info.get("real_path"),
                        "resolution": info.get("resolution"),
                    }
                    _guard_filesystem(current, tool="open", path=path, mode=str(mode), info=info, payload=payload)
                    _recheck_effective_target(current, tool="open", path=path, mode=str(mode), prior_info=info)
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
                    info = fs_mod.classify_path(self, workspace=os.getcwd(), mode=str(mode))
                    payload = {
                        "path": str(self),
                        "classification": info,
                        "mode": mode,
                        "effective_path": info.get("real_path"),
                        "resolution": info.get("resolution"),
                    }
                    _guard_filesystem(
                        current, tool="pathlib.Path.open", path=self, mode=str(mode), info=info, payload=payload
                    )
                    _recheck_effective_target(
                        current, tool="pathlib.Path.open", path=self, mode=str(mode), prior_info=info
                    )
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
                    if tool in {"os.rename", "os.replace"}:
                        src = _call_path(args, kwargs, 0, ("src", "path"))
                        dst = _call_path(args, kwargs, 1, ("dst",))
                    else:
                        src = _call_path(args, kwargs, 0, ("path", "src"))
                        dst = None
                    src_info = fs_mod.classify_path(src, workspace=os.getcwd(), mode="w") if src is not None else {}
                    # Dual-target: rename/replace destinations are independently sensitive.
                    if tool in {"os.rename", "os.replace"} and dst is not None:
                        dst_info = fs_mod.classify_path(dst, workspace=os.getcwd(), mode="w")
                        enforce_src = _should_enforce(src, "w", src_info)
                        enforce_dst = _should_enforce(dst, "w", dst_info)
                        for side, info, side_path in (
                            ("source", src_info, src),
                            ("destination", dst_info, dst),
                        ):
                            if _ambiguous_resolution_blocks(current, side_path, "w", info):
                                raise _blocked_error(current)(
                                    f"filesystem {tool} blocked: {side} path resolution failed",
                                    {"action": "block", "reason": f"filesystem_resolution_{info.get('resolution')}"},
                                )
                        if enforce_src or enforce_dst:
                            payload = {
                                "path": str(src),
                                "destination": str(dst),
                                "source_classification": src_info,
                                "destination_classification": dst_info,
                                "args": [str(a) for a in args],
                                "effective_path": src_info.get("real_path"),
                                "destination_effective_path": dst_info.get("real_path"),
                            }
                            # Use the more sensitive of the two for primary metadata.
                            primary = dst_info if enforce_dst else src_info
                            result = current.guarded_action(
                                type="filesystem",
                                tool=tool,
                                args=payload,
                                payload=payload,
                                metadata={
                                    "runtime": {"surface": "filesystem", "boundary": True},
                                    "filesystem": primary,
                                    "filesystem_source": src_info,
                                    "filesystem_destination": dst_info,
                                    "sensitivity": primary.get("sensitivity"),
                                    "mutation": primary.get("mutation"),
                                    "required_authority": primary.get("required_authority"),
                                },
                            )
                            if result and result.blocked and _enforcing(current):
                                raise _blocked_error(current)(f"filesystem {tool} blocked", result.decision)
                        _recheck_effective_target(current, tool=tool, path=src, mode="w", prior_info=src_info)
                        _recheck_effective_target(current, tool=tool, path=dst, mode="w", prior_info=dst_info)
                    else:
                        payload = {
                            "path": str(src) if src is not None else None,
                            "args": [str(a) for a in args],
                            "classification": src_info,
                            "effective_path": src_info.get("real_path"),
                            "resolution": src_info.get("resolution"),
                        }
                        _guard_filesystem(
                            current, tool=tool, path=src, mode="w", info=src_info, payload=payload
                        )
                        if src is not None:
                            _recheck_effective_target(current, tool=tool, path=src, mode="w", prior_info=src_info)
                    return original(*args, **kwargs)
                finally:
                    _fs_depth.reset(token)

            return wrapper

        setattr(os, fn_name, _make(originals[key_os], name))

    if hasattr(os, "open") and "os.open" not in originals:
        originals["os.open"] = os.open

        @functools.wraps(originals["os.open"])
        def os_open_wrapper(*args, **kwargs):
            from varden_sdk.sdk import current_guard

            if _fs_depth.get() > 0:
                return originals["os.open"](*args, **kwargs)
            token = _fs_depth.set(_fs_depth.get() + 1)
            try:
                current = current_guard() or guard
                path = _call_path(args, kwargs, 0, ("path", "file"))
                flags = args[1] if len(args) > 1 else kwargs.get("flags")
                if path is None or flags is None:
                    return originals["os.open"](*args, **kwargs)
                mode = "w" if _os_open_writes(flags) else "r"
                info = fs_mod.classify_path(path, workspace=os.getcwd(), mode=mode)
                payload = {
                    "path": str(path),
                    "flags": flags,
                    "classification": info,
                    "effective_path": info.get("real_path"),
                    "resolution": info.get("resolution"),
                }
                _guard_filesystem(current, tool="os.open", path=path, mode=mode, info=info, payload=payload)
                _recheck_effective_target(current, tool="os.open", path=path, mode=mode, prior_info=info)
                return originals["os.open"](*args, **kwargs)
            finally:
                _fs_depth.reset(token)

        os.open = os_open_wrapper

    for name, fn_name in (("os.link", "link"), ("os.symlink", "symlink")):
        if not hasattr(os, fn_name) or name in originals:
            continue
        originals[name] = getattr(os, fn_name)

        def _make_link(original: Callable[..., Any], tool: str):
            @functools.wraps(original)
            def wrapper(*args, **kwargs):
                from varden_sdk.sdk import current_guard

                if _fs_depth.get() > 0:
                    return original(*args, **kwargs)
                token = _fs_depth.set(_fs_depth.get() + 1)
                try:
                    current = current_guard() or guard
                    src = _call_path(args, kwargs, 0, ("src", "path"))
                    dst = _call_path(args, kwargs, 1, ("dst",))
                    src_info = fs_mod.classify_path(src, workspace=os.getcwd(), mode="w") if src is not None else {}
                    dst_info = fs_mod.classify_path(dst, workspace=os.getcwd(), mode="w") if dst is not None else {}
                    for side, info, side_path in (
                        ("source", src_info, src),
                        ("destination", dst_info, dst),
                    ):
                        if side_path is None:
                            continue
                        if _ambiguous_resolution_blocks(current, side_path, "w", info):
                            raise _blocked_error(current)(
                                f"filesystem {tool} blocked: {side} path resolution failed",
                                {"action": "block", "reason": f"filesystem_resolution_{info.get('resolution')}"},
                            )
                    enforce_src = _should_enforce(src, "w", src_info) if src is not None else False
                    enforce_dst = _should_enforce(dst, "w", dst_info) if dst is not None else False
                    if enforce_src or enforce_dst:
                        primary = src_info if enforce_src else dst_info
                        payload = {
                            "path": None if src is None else str(src),
                            "destination": None if dst is None else str(dst),
                            "source_classification": src_info,
                            "destination_classification": dst_info,
                            "effective_path": src_info.get("real_path"),
                            "destination_effective_path": dst_info.get("real_path"),
                        }
                        result = current.guarded_action(
                            type="filesystem",
                            tool=tool,
                            args=payload,
                            payload=payload,
                            metadata={
                                "runtime": {"surface": "filesystem", "boundary": True},
                                "filesystem": primary,
                                "filesystem_source": src_info,
                                "filesystem_destination": dst_info,
                                "sensitivity": primary.get("sensitivity"),
                                "mutation": primary.get("mutation"),
                                "required_authority": primary.get("required_authority"),
                            },
                        )
                        if result and result.blocked and _enforcing(current):
                            raise _blocked_error(current)(f"filesystem {tool} blocked", result.decision)
                    if src is not None:
                        _recheck_effective_target(current, tool=tool, path=src, mode="w", prior_info=src_info)
                    if dst is not None:
                        _recheck_effective_target(current, tool=tool, path=dst, mode="w", prior_info=dst_info)
                    return original(*args, **kwargs)
                finally:
                    _fs_depth.reset(token)

            return wrapper

        setattr(os, fn_name, _make_link(originals[name], name))

    get_coverage_registry().mark(
        "filesystem",
        status=PARTIAL,
        interceptor="builtins.open+pathlib+os.open+os.remove/unlink/rename/replace/link/symlink",
        active=True,
        applicable=True,
        enforcement_mode="partial",
        limitations=[
            "Patched calls: builtins.open, pathlib.Path.open, os.open, os.remove, os.unlink, os.rename, os.replace, os.link, os.symlink (positional and keyword).",
            "Secrets, system paths, and supply-chain workspace mutations are mediated on those calls. Benign workspace and home reads and writes may not hit the control plane.",
            "dir_fd forms are classified from the path string only. A benign relative name opened against an untracked directory descriptor is not contained.",
            "Re-check before the syscall narrows TOCTOU. It does not close a race between that re-check and the kernel operation.",
            "Hard links created before interception, raw file descriptors, os.read/os.write, shutil paths that avoid patched calls, and native extensions are not mediated.",
            "OS-global filesystem isolation is NOT GUARANTEED.",
        ],
    )



def _subprocess_meta(args: Any, *, shell: bool = False) -> dict[str, Any]:
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
    if shell:
        elevated = True
    return {
        "execution_surface": "subprocess",
        "runtime": {"surface": "subprocess", "boundary": True},
        "subprocess": {
            "executable": exe,
            "argv": [str(x) for x in seq],
            "elevated_uncertainty": elevated,
            "shell": bool(shell),
        },
        "authority_hint": "ADMIN" if elevated else "EXECUTE",
    }


def _extended_subprocess_payload(popenargs: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Keep enforcement-relevant kwargs visible. Redact environment values."""
    safe: dict[str, Any] = {}
    for key, value in kwargs.items():
        if key == "env":
            keys = sorted(str(item) for item in value) if isinstance(value, dict) else []
            safe[key] = {"redacted": True, "keys": keys}
        elif key in {"shell", "cwd", "executable"} and isinstance(value, (str, bytes, bool, int, type(None))):
            safe[key] = value
        else:
            safe[key] = str(type(value))
    return {"args": list(popenargs), "kwargs": safe}


def patch_subprocess_extended(guard: Any, originals: dict[str, Any]) -> None:
    """Cover call/check_call/check_output/os.system/os.popen beyond Popen/run."""
    for attr in ("call", "check_call", "check_output"):
        key = f"subprocess.{attr}"
        if not hasattr(subprocess, attr):
            continue
        current_fn = getattr(subprocess, attr)
        if key in originals and current_fn is not originals[key]:
            continue
        if key not in originals:
            originals[key] = current_fn

        def _make(original: Callable[..., Any], tool: str):
            @functools.wraps(original)
            def wrapper(*popenargs, **kwargs):
                from varden_sdk.sdk import current_guard

                current = current_guard() or guard
                args0 = popenargs[0] if popenargs else kwargs.get("args")
                meta = _subprocess_meta(args0, shell=bool(kwargs.get("shell")))
                payload = _extended_subprocess_payload(popenargs, kwargs)
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

    # Subprocess ENFORCED attestation is owned by ``patch_runtime.install_interceptor``
    # (sealed probe). Do not mark ENFORCED here — that would allow false attestation.


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
        "os.open": ("os", "open"),
        "os.link": ("os", "link"),
        "os.symlink": ("os", "symlink"),
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
