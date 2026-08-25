"""Varden session: prepend PATH with shims that route CLIs through policy."""

from __future__ import annotations

import atexit
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

SHIM_CLI_NAMES: tuple[str, ...] = (
    "railway",
    "supabase",
    "vercel",
    "fly",
    "render",
    "kubectl",
    "terraform",
    "aws",
    "gcloud",
    "az",
    "psql",
    "mysql",
    "git",
    "npm",
    "pip",
    "pip3",
    "docker",
    "docker-compose",
    "cursor",
    "curl",
    "wget",
    "ssh",
    "scp",
)


def _write_unix_shims(shim_dir: Path, py: str) -> None:
    for name in SHIM_CLI_NAMES:
        path = shim_dir / name
        body = f'#!/bin/sh\nexec "{py}" -m varden_monitor.shim_runner "{name}" "$@"\n'
        path.write_text(body, encoding="utf-8")
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_windows_shims(shim_dir: Path, py: str) -> None:
    for name in SHIM_CLI_NAMES:
        path = shim_dir / f"{name}.cmd"
        body = f'@echo off\n"{py}" -m varden_monitor.shim_runner {name} %*\r\n'
        path.write_text(body, encoding="utf-8")


def parse_session_argv(argv: list[str]) -> tuple[str, bool, list[str] | None, str]:
    """Return (cwd, passive, command_or_none, mode). mode: observe|guarded|strict."""
    a = list(argv)
    passive = False
    mode = "guarded"
    while a and a[0] in {"--passive", "--strict", "--enforce", "--observe"}:
        flag = a.pop(0)
        if flag == "--passive" or flag == "--observe":
            passive = True
            mode = "observe"
        elif flag == "--strict":
            mode = "strict"
            passive = False
        elif flag == "--enforce":
            mode = "guarded"
            passive = False
    if "--" in a:
        idx = a.index("--")
        left, right = a[:idx], a[idx + 1 :]
        if len(left) > 1:
            raise ValueError("at most one directory is allowed before --")
        d = left[0] if left else "."
        return d, passive, right if right else None, mode
    if not a:
        return ".", passive, None, mode
    if len(a) == 1:
        return a[0], passive, None, mode
    return a[0], passive, a[1:], mode


def start_session(cwd: str, passive: bool, command: list[str] | None, mode: str = "guarded") -> int:
    cwd_path = Path(cwd).resolve()
    if not cwd_path.is_dir():
        print(f"varden session: not a directory: {cwd_path}", file=sys.stderr)
        return 2

    shim_dir = Path(tempfile.mkdtemp(prefix="varden-session-"))
    py = sys.executable
    if os.name == "nt":
        _write_windows_shims(shim_dir, py)
    else:
        _write_unix_shims(shim_dir, py)

    orig_path = os.environ.get("PATH", "")
    env = os.environ.copy()
    env["PATH"] = str(shim_dir) + os.pathsep + orig_path
    env["VARDEN_SESSION_SHIM_DIR"] = str(shim_dir)
    env["VARDEN_SESSION_ORIG_PATH"] = orig_path
    env["VARDEN_SESSION_FRONT_PATH"] = env["PATH"]
    env["VARDEN_MODE"] = "observe" if passive else mode
    env["VARDEN_FAIL_MODE"] = "open" if passive else "closed"
    if passive:
        env["VARDEN_SESSION_PASSIVE"] = "1"
    else:
        env.pop("VARDEN_SESSION_PASSIVE", None)
    env.setdefault("VARDEN_SESSION_ID", str(uuid.uuid4()))
    if not env.get("VARDEN_TRACE_ID"):
        env["VARDEN_TRACE_ID"] = str(uuid.uuid4())
    env.setdefault("VARDEN_AGENT_NAME", "varden-session")
    env.setdefault("VARDEN_EXECUTION_SURFACE", "varden_session")
    # Correlation only — never client-authoritative trust/delegation claims.
    env.setdefault("VARDEN_BOUNDARY_URL", env.get("VARDEN_BASE_URL", "http://127.0.0.1:8000"))

    def _cleanup() -> None:
        shutil.rmtree(shim_dir, ignore_errors=True)

    atexit.register(_cleanup)

    label = "passive (log-only)" if passive else f"{mode} (guard before exec)"
    print(f"Varden session [{label}] — shims in {shim_dir}", file=sys.stderr)
    print("CLIs:", ", ".join(SHIM_CLI_NAMES[:8]), "… (see docs). Exit shell to tear down.", file=sys.stderr)
    if mode == "strict":
        print(
            "Strict mode: fail-closed; PATH shims are one layer — not a complete OS sandbox.",
            file=sys.stderr,
        )

    if command:
        rc = subprocess.call(command, env=env, cwd=str(cwd_path))
        return int(rc if rc is not None else 1)

    if os.name == "nt":
        shell = env.get("COMSPEC", "cmd.exe")
        rc = subprocess.call([shell], env=env, cwd=str(cwd_path))
    else:
        shell = env.get("SHELL", "/bin/sh")
        rc = subprocess.call([shell], env=env, cwd=str(cwd_path))
    return int(rc if rc is not None else 0)


def session_argv(argv: list[str] | None) -> int:
    raw = list(argv if argv is not None else [])
    if raw and raw[0] == "session":
        raw = raw[1:]
    try:
        d, passive, cmd, mode = parse_session_argv(raw)
    except ValueError as e:
        print(f"varden session: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"varden session: {e}", file=sys.stderr)
        return 1
    return start_session(d, passive, cmd, mode=mode)


def main(argv: list[str] | None = None) -> int:
    return session_argv(argv)


if __name__ == "__main__":
    raise SystemExit(main())
