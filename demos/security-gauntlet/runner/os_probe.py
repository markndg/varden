"""Resolve the in-tree supervisor and probe one contained write.

``VARDEN_INTEGRITY_ROOT`` overrides the repository. An override that does not
contain the supervisor is not replaced with this checkout. A platform is
verified only when this process ran that platform's adapter and the contained
write failed with a non-zero exit and an unchanged hash.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _has_supervisor(path: Path) -> bool:
    return (path / "varden" / "monitoring_integrity" / "platforms.py").is_file()


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_supervisor() -> dict[str, Any]:
    """Prefer an explicit root. Otherwise use this repository when it has the supervisor."""
    override = os.environ.get("VARDEN_INTEGRITY_ROOT", "").strip()
    if override:
        path = Path(override).expanduser().resolve()
        if _has_supervisor(path):
            return {"root": path, "source": "VARDEN_INTEGRITY_ROOT", "available": True}
        return {
            "root": None,
            "source": "VARDEN_INTEGRITY_ROOT",
            "available": False,
            "detail": f"{path} has no varden/monitoring_integrity/platforms.py. The repository was not substituted.",
        }
    repo = repository_root()
    if _has_supervisor(repo):
        return {"root": repo, "source": "repository", "available": True}
    return {"root": None, "source": "none", "available": False, "detail": "This repository has no monitoring-integrity supervisor."}


def integrity_root() -> Path | None:
    found = resolve_supervisor()
    root = found.get("root")
    return root if isinstance(root, Path) else None


def enforcement_capabilities(
    *,
    system: str | None = None,
    sandbox_exec: bool | None = None,
    bwrap: bool | None = None,
    windows: bool | None = None,
) -> dict[str, Any]:
    """Declare what each adapter can be asked to do. None of them are verified here."""
    host = system or platform.system()
    seatbelt = Path("/usr/bin/sandbox-exec").is_file() if sandbox_exec is None else sandbox_exec
    bubblewrap = shutil.which("bwrap") is not None if bwrap is None else bwrap
    win32 = sys.platform == "win32" if windows is None else windows
    return {
        "Darwin": {
            "mechanism": "macos_seatbelt_experimental",
            "implementation": "present",
            "tool_present": seatbelt,
            "this_host": host == "Darwin",
            "runnable_on_this_host": host == "Darwin" and seatbelt,
            "verified": False,
        },
        "Linux": {
            "mechanism": "linux_bubblewrap_unverified",
            "implementation": "present",
            "tool_present": bubblewrap,
            "this_host": host == "Linux",
            "runnable_on_this_host": host == "Linux" and bubblewrap,
            "verified": False,
        },
        "Windows": {
            "mechanism": "windows_restricted_token_unverified",
            "implementation": "present",
            "tool_present": win32,
            "this_host": host == "Windows",
            "runnable_on_this_host": host == "Windows" and win32,
            "verified": False,
        },
    }


def platform_status() -> dict[str, Any]:
    found = resolve_supervisor()
    root = found.get("root")
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "sdk_guard": "available",
        "predictive_authority": "available_off_by_default",
        "os_enforcement_in_this_tree": False,
        "supervisor_available": bool(found.get("available")),
        "supervisor_source": found.get("source"),
        "integrity_root_configured": found.get("source") == "VARDEN_INTEGRITY_ROOT" and bool(found.get("available")),
        "integrity_root": str(root) if isinstance(root, Path) else None,
        "adapters": enforcement_capabilities(),
        "this_host_os_enforcement": "not_run",
    }


def interpret_contained(probe: dict[str, Any]) -> dict[str, Any]:
    """Turn probe facts into an OS-leg observation. A hash or an exit code alone is not a denial."""
    executed = bool(probe.get("executed_on_host")) and bool(probe.get("supported"))
    before = probe.get("before_sha256")
    after = probe.get("after_sha256")
    returncode = probe.get("returncode")
    completed = bool(probe.get("contained_completed"))
    hashes_unchanged = bool(before) and before == after
    denied_exit = isinstance(returncode, int) and returncode != 0
    if not executed:
        return {"attempted": False, "completed": False, "decision": "", "telemetry": False, "supported": False, "executed_on_host": False}
    if completed or not hashes_unchanged:
        return {"attempted": True, "completed": True, "decision": "block", "telemetry": True, "supported": True, "executed_on_host": True}
    if denied_exit:
        return {"attempted": True, "completed": False, "decision": "block", "telemetry": True, "supported": True, "executed_on_host": True}
    return {"attempted": True, "completed": False, "decision": "", "telemetry": True, "supported": True, "executed_on_host": True}


def run_os_probe() -> dict[str, Any]:
    """Try one contained write and one same-user write outside the profile."""
    status = platform_status()
    found = resolve_supervisor()
    root = found.get("root")
    if not isinstance(root, Path):
        return {
            **status,
            "executed_on_host": False,
            "supported": False,
            "contained_completed": False,
            "outside_completed": False,
            "mechanism": "unavailable",
            "detail": str(found.get("detail") or "The supervisor was not resolved. No boundary command was started."),
        }
    script = r"""
import hashlib, json, sys, tempfile
from pathlib import Path

def digest(path):
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()

home = Path.home()
root = Path(tempfile.mkdtemp(prefix="varden-gauntlet-os-", dir=str(home)))
workspace = root / "work"
protected = root / "protected"
state = root / "state"
for path in (workspace, protected, state):
    path.mkdir()
target = protected / "monitoring.json"
original = '{"audit": true}\n'
target.write_text(original, encoding="utf-8")
before = digest(target)
try:
    from varden.monitoring_integrity.platforms import select_boundary
    adapter = select_boundary()
    prepared = adapter.prepare(workspace=workspace, protected=protected, state_dir=state, directory=root, gateway_ports=())
    if not prepared.ok:
        print(json.dumps({
            "executed_on_host": False,
            "supported": False,
            "mechanism": prepared.mechanism,
            "detail": prepared.reason,
            "limitations": list(prepared.limitations),
            "contained_completed": False,
            "outside_completed": False,
        }))
        raise SystemExit(0)
    contained = adapter.run_captured(
        prepared,
        [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('disabled\\n', encoding='utf-8')", str(target)],
        cwd=workspace,
    )
    after = digest(target)
    outside = root / "outside-profile.json"
    outside_before = digest(outside)
    outside.write_text('{"written":"outside-profile"}\n', encoding="utf-8")
    parent_target = protected / "same-user.json"
    parent_target.write_text(original, encoding="utf-8")
    parent_before = digest(parent_target)
    parent_target.write_text('{"written":"same-user"}\n', encoding="utf-8")
    print(json.dumps({
        "executed_on_host": True,
        "supported": True,
        "mechanism": prepared.mechanism,
        "experimental": bool(prepared.experimental),
        "limitations": list(prepared.limitations),
        "returncode": contained.returncode,
        "stderr": (contained.stderr or "")[-300],
        "before_sha256": before,
        "after_sha256": after,
        "contained_completed": before != after,
        "outside_completed": digest(outside) != outside_before,
        "same_user_protected_write_completed": digest(parent_target) != parent_before,
        "detail": f"Contained python write used {prepared.mechanism}. returncode={contained.returncode}. The same user then wrote a file outside that process.",
    }))
except Exception as exc:
    print(json.dumps({
        "executed_on_host": False,
        "supported": False,
        "mechanism": "macos_seatbelt_experimental",
        "contained_completed": False,
        "outside_completed": False,
        "detail": f"{exc.__class__.__name__}: {exc}",
    }))
finally:
    import shutil
    shutil.rmtree(root, ignore_errors=True)
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            **status,
            "executed_on_host": False,
            "supported": False,
            "contained_completed": False,
            "outside_completed": False,
            "mechanism": "macos_seatbelt_experimental",
            "detail": f"probe process failed: {exc.__class__.__name__}",
        }
    line = (proc.stdout or "").strip().splitlines()
    payload: dict[str, Any] = {}
    if line:
        try:
            parsed = json.loads(line[-1])
            if isinstance(parsed, dict):
                payload = parsed
        except json.JSONDecodeError:
            payload = {}
    if not payload:
        return {
            **status,
            "executed_on_host": False,
            "supported": False,
            "contained_completed": False,
            "outside_completed": False,
            "mechanism": "macos_seatbelt_experimental",
            "detail": f"probe returned no JSON (exit {proc.returncode}): {(proc.stderr or '')[-300]}",
        }
    payload["integrity_commit"] = _commit(root)
    payload["supervisor_source"] = found.get("source")
    host_caps = enforcement_capabilities()
    mechanism = str(payload.get("mechanism") or "")
    proved = (
        bool(payload.get("executed_on_host"))
        and bool(payload.get("supported"))
        and not payload.get("contained_completed")
        and isinstance(payload.get("returncode"), int)
        and payload.get("returncode") != 0
        and payload.get("before_sha256")
        and payload.get("before_sha256") == payload.get("after_sha256")
    )
    for name, cap in host_caps.items():
        cap["verified"] = bool(proved and cap["this_host"] and cap["mechanism"] == mechanism)
    payload["adapters"] = host_caps
    payload["this_host_os_enforcement"] = "verified_for_launched_process" if proved else "not_verified"
    payload["os_enforcement_in_this_tree"] = False
    return payload


def _commit(root: Path) -> str:
    git = shutil.which("git")
    if not git:
        return "unknown"
    proc = subprocess.run([git, "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return (proc.stdout or "unknown").strip() or "unknown"
