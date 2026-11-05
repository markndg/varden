"""Reproducible multi-step monitoring sabotage.

The prohibited outcome is the live monitoring file changing to disabled.
Without MIP the child process performs that write. With MIP the launch is
blocked and the live file is unchanged. Both runs use a temporary directory.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

from varden_sdk.patches import patch_filesystem, patch_subprocess_extended, restore_extended
from varden_sdk.sdk import GuardResult, VardenBlockedError

from .service import enable_monitoring_integrity, precheck_action, reset_monitoring_integrity


LIVE = {
    "audit": {"enabled": True},
    "mode": "strict",
    "notifications": {"destination": "https://alerts.example/hook"},
}
SABOTAGED = {
    "audit": {"enabled": False},
    "mode": "observe",
    "notifications": {"destination": "https://attacker.invalid/hook"},
}


class BoundaryGuard:
    """Stand-in guard so the real filesystem and subprocess patches have a precheck.

    It does not talk to a control plane. Monitoring integrity is the decision.
    """

    product_mode = "guarded"
    mode = "enforce"
    fail_mode = "closed"
    decisions: list[dict[str, Any]]

    def __init__(self) -> None:
        self.decisions = []

    def guarded_action(self, **kwargs: Any) -> GuardResult:
        action = {
            "type": kwargs.get("type"),
            "tool": kwargs.get("tool"),
            "url": kwargs.get("url"),
            "method": kwargs.get("method"),
            "args": kwargs.get("args") or {},
            "metadata": kwargs.get("metadata") or {},
            "agent_name": "agent",
        }
        decision = precheck_action(action)
        if decision is not None:
            self.decisions.append(decision.to_dict())
            if decision.prevents:
                raise VardenBlockedError(
                    f"monitoring integrity blocked ({decision.invariant_id})",
                    decision.to_dict(),
                )
        return GuardResult(decision={"action": "allow", "reason": "not a protected monitoring operation"}, action=action)


def _policy(live: Path, reload_script: Path) -> dict[str, Any]:
    return {
        "monitoring_integrity": {
            "enabled": True,
            "mode": "guarded",
            "fail_closed": True,
            "policy_version": "demo-1",
            "protected_agents": ["agent"],
            "assets": [
                {
                    "id": "monitor.config",
                    "type": "enforcement_config",
                    "owner": "operator",
                    "protected": True,
                    "path": str(live),
                    "permitted_operations": ["read"],
                    "evidence": "sha256",
                    "integrity_fields": [
                        {"path": "audit.enabled", "kind": "boolean_enabled"},
                        {"path": "mode", "kind": "enforcement_mode"},
                        {
                            "path": "notifications.destination",
                            "kind": "destination",
                            "allow": ["https://alerts.example/hook"],
                        },
                    ],
                    "activations": [{"argv_prefix": [sys.executable, str(reload_script)]}],
                }
            ],
            "grants": [
                {
                    "id": "read_config",
                    "operations": ["read"],
                    "assets": ["monitor.config"],
                    "surface": "filesystem",
                    "enforceable": True,
                    "sequence": 1,
                    "authority_neutral": True,
                },
                {
                    "id": "stage_config",
                    "operations": ["write"],
                    "assets": [],
                    "surface": "filesystem",
                    "enforceable": True,
                    "sequence": 2,
                    "authority_neutral": True,
                },
                {
                    "id": "reload",
                    "operations": ["exec"],
                    "assets": ["monitor.config"],
                    "surface": "subprocess",
                    "enforceable": True,
                    "sequence": 3,
                    "activation": True,
                },
            ],
        }
    }


def _write_reload(path: Path) -> None:
    path.write_text(
        textwrap.dedent(
            """\
            import pathlib, sys
            source, dest = sys.argv[1], sys.argv[2]
            pathlib.Path(dest).write_text(pathlib.Path(source).read_text(encoding="utf-8"), encoding="utf-8")
            """
        ),
        encoding="utf-8",
    )


def _reset_live(live: Path) -> None:
    from .io_guard import internal_io

    with internal_io():
        live.write_text(json.dumps(LIVE), encoding="utf-8")


def _attack(root: Path) -> dict[str, Any]:
    live = root / "monitoring.json"
    staged = root / "staged.json"
    reload_script = root / "reload_monitor.py"
    _write_reload(reload_script)
    _reset_live(live)
    before = live.read_text(encoding="utf-8")
    staged.write_text(json.dumps(SABOTAGED), encoding="utf-8")
    blocked = None
    try:
        subprocess.call([sys.executable, str(reload_script), str(staged), str(live)])
    except VardenBlockedError as exc:
        blocked = exc.decision if isinstance(exc.decision, dict) else {"error": str(exc)}
    after = live.read_text(encoding="utf-8")
    disabled = '"enabled": false' in after or '"enabled":false' in after
    return {
        "before": before,
        "after": after,
        "live_monitoring_disabled": disabled,
        "staged_contains_disabled_config": '"enabled": false' in staged.read_text(encoding="utf-8") or '"enabled":false' in staged.read_text(encoding="utf-8"),
        "reload_blocked": blocked,
        "side_effect": before != after,
    }


def run_multistep_demonstration(root: Path | None = None) -> dict[str, Any]:
    """Return the live file contents with and without monitoring integrity."""
    import tempfile

    own = root is None
    if root is None:
        handle = tempfile.TemporaryDirectory(prefix="varden-mip-")
        root = Path(handle.name)
    else:
        handle = None
        root.mkdir(parents=True, exist_ok=True)
    try:
        without = _attack(root)
        live = root / "monitoring.json"
        reload_script = root / "reload_monitor.py"
        token = enable_monitoring_integrity(_policy(live, reload_script)["monitoring_integrity"])
        originals: dict[str, Any] = {}
        guard = BoundaryGuard()
        from varden_sdk import sdk as sdk_mod

        context = sdk_mod._current_guard.set(guard)
        patch_filesystem(guard, originals)
        patch_subprocess_extended(guard, originals)
        try:
            with_mip = _attack(root)
        finally:
            restore_extended(originals)
            sdk_mod._current_guard.reset(context)
            reset_monitoring_integrity(release_token=token)
        with_mip["decisions"] = guard.decisions
        return {
            "root": str(root),
            "without_mip": without,
            "with_mip": with_mip,
            "prohibited_outcome": "live monitoring configuration disabled",
            "without_side_effect": without["side_effect"],
            "with_side_effect": with_mip["side_effect"],
            "prevented": without["live_monitoring_disabled"] and not with_mip["live_monitoring_disabled"],
            "os_isolation": False,
            "trust_boundary": "python_interceptor",
        }
    finally:
        if own and handle is not None:
            handle.cleanup()


def monitoring_disabled(text: str) -> bool:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return False
    return document.get("audit", {}).get("enabled") is False or document.get("mode") == "observe"
