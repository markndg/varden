"""Platform capability detection and an optional Seatbelt probe.

The probe runs only when VARDEN_INTEGRITY_ROOT points at a checkout of
feature/monitoring-integrity. This branch does not vendor that code. A missing
root, a failed import, or a host that is not Darwin is UNSUPPORTED. A write
that succeeds inside the profile is not reported as prevention.
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


def platform_status() -> dict[str, Any]:
    system = platform.system()
    root = integrity_root()
    return {
        "system": system,
        "machine": platform.machine(),
        "sdk_guard": "available",
        "predictive_authority": "available_off_by_default",
        "os_enforcement_in_this_tree": False,
        "integrity_root_configured": root is not None,
        "integrity_root": str(root) if root else None,
        "adapters": {
            "Darwin": "experimental_on_feature/monitoring-integrity" if system == "Darwin" else "not_this_host",
            "Linux": "unverified",
            "Windows": "unverified",
        },
        "this_host_os_enforcement": "not_run",
    }


def integrity_root() -> Path | None:
    raw = os.environ.get("VARDEN_INTEGRITY_ROOT", "").strip()
    if not raw:
        return None
    path = Path(raw).resolve()
    marker = path / "varden" / "monitoring_integrity" / "platforms.py"
    if marker.is_file():
        return path
    return None


def run_os_probe() -> dict[str, Any]:
    """Try one contained write and one same-user write outside the profile."""
    status = platform_status()
    root = integrity_root()
    if root is None:
        return {
            **status,
            "executed_on_host": False,
            "supported": False,
            "contained_completed": False,
            "outside_completed": False,
            "mechanism": "unavailable",
            "detail": (
                "VARDEN_INTEGRITY_ROOT is not a checkout of feature/monitoring-integrity. "
                "This process did not launch sandbox-exec, bubblewrap, or a Windows job."
            ),
        }
    if platform.system() != "Darwin":
        return {
            **status,
            "executed_on_host": False,
            "supported": False,
            "contained_completed": False,
            "outside_completed": False,
            "mechanism": "unavailable",
            "detail": (
                f"{platform.system()} has no executed mandatory-enforcement probe in this suite. "
                "Linux bubblewrap and the Windows restricted token remain unverified."
            ),
        }
    if not Path("/usr/bin/sandbox-exec").is_file():
        return {
            **status,
            "executed_on_host": False,
            "supported": False,
            "contained_completed": False,
            "outside_completed": False,
            "mechanism": "macos_seatbelt_experimental",
            "detail": "sandbox-exec is not on this Mac. The contained command was not started.",
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
        "detail": "Contained python write used the monitoring-integrity Seatbelt adapter. The same user then wrote a file outside that process.",
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
    payload.update({key: status[key] for key in ("system", "machine", "os_enforcement_in_this_tree", "adapters")})
    payload["integrity_commit"] = _commit(root)
    return payload


def _commit(root: Path) -> str:
    git = shutil.which("git")
    if not git:
        return "unknown"
    proc = subprocess.run([git, "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return (proc.stdout or "unknown").strip() or "unknown"
