"""Process-local Monitoring Integrity facade.

Disabled unless an operator enables it. Enabling seals the asset catalogue
for this process. Arbitrary in-process code can still undo monkeypatches;
that is not an independent watchdog.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import secrets
import threading
from typing import Any

from varden.models import Decision

from .analysis import analyse, invalidate_analysis
from .contract import platform_matrix
from .approvals import ApprovalStore
from .assets import AssetRegistry
from .decide import Decider, IntegrityDecision, Outcome, strengthen
from .evidence import EvidenceLog
from .invariants import invariant_catalog
from .io_guard import internal_io_active

_BOUND = contextvars.ContextVar("varden_mip_registry", default=None)
_ARMED = contextvars.ContextVar("varden_mip_armed_approval", default=None)
_LOCK = threading.RLock()
_REGISTRY = AssetRegistry()
_APPROVALS = ApprovalStore()
_EVIDENCE = EvidenceLog()
_TOKEN: str | None = None
_KILL = None
_ENV_SETITEM = None
_ENV_DELITEM = None


def _decider(registry: AssetRegistry | None = None) -> Decider:
    return Decider(registry or current_registry(), _APPROVALS)


def current_registry() -> AssetRegistry:
    bound = _BOUND.get()
    return bound if bound is not None else _REGISTRY


def enabled() -> bool:
    try:
        return bool(current_registry().enabled)
    except Exception:
        return False


def section_hash(section: dict[str, Any]) -> str:
    payload = json.dumps(section, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def bind_registry(registry: AssetRegistry):
    return _BOUND.set(registry)


def reset_binding(token) -> None:
    _BOUND.reset(token)


def enable_monitoring_integrity(
    section: dict[str, Any],
    *,
    evidence_path: str | None = None,
    release_token: str | None = None,
) -> str:
    """Seal ``section`` into this process and return the operator release token.

    A second call without the current release token does not replace the seal.
    In-process code that can read this module can still reach the token; that
    is not an independent trust boundary.
    """
    global _TOKEN, _EVIDENCE
    token = secrets.token_hex(16)
    digest = section_hash(section)
    with _LOCK:
        if _REGISTRY._sealed and release_token != _REGISTRY._seal_token:
            raise RuntimeError("monitoring integrity is already sealed")
        if _REGISTRY._sealed:
            _restore_process_guards()
            _REGISTRY.__dict__.update(AssetRegistry().__dict__)
            _APPROVALS.reset()
        if evidence_path or section.get("evidence_path"):
            _EVIDENCE = EvidenceLog(evidence_path or section.get("evidence_path"))
        _REGISTRY.load_section(section, token=None, section_hash=digest)
        _REGISTRY.evidence_path = _EVIDENCE.path
        _REGISTRY.seal(token)
        _TOKEN = token
        invalidate_analysis()
        _install_process_guards()
    return token


def disable_monitoring_integrity(token: str | None = None) -> None:
    reset_monitoring_integrity(release_token=token or _TOKEN)


def reset_monitoring_integrity(*, release_token: str | None = None) -> None:
    """Drop sealed state. Refuses while sealed unless ``release_token`` matches."""
    global _TOKEN, _EVIDENCE
    with _LOCK:
        if _REGISTRY._sealed and release_token != _REGISTRY._seal_token:
            raise RuntimeError("monitoring integrity registry is sealed")
        _restore_process_guards()
        fresh = AssetRegistry()
        _REGISTRY.__dict__.update(fresh.__dict__)
        _APPROVALS.reset()
        _EVIDENCE = EvidenceLog()
        _TOKEN = None
        invalidate_analysis()


def registry_for_section(section: dict[str, Any]) -> AssetRegistry:
    digest = section_hash(section)
    with _LOCK:
        if _REGISTRY.enabled and _REGISTRY.section_hash == digest:
            return _REGISTRY
    registry = AssetRegistry()
    registry.load_section(section, section_hash=digest)
    if section.get("evidence_path"):
        registry.evidence_path = str(section["evidence_path"])
    return registry


def path_requires_mediation(path: Any) -> bool:
    if internal_io_active() or not enabled():
        return False
    if path is None or isinstance(path, int):
        return False
    try:
        text = os.fspath(path)
    except TypeError:
        return False
    try:
        matches = current_registry().match_path(str(text))
    except Exception:
        return True
    return any(match.asset.protected for match in matches)


def arm_approval(record: Any) -> None:
    """Present one operator approval to the next pre-execution check.

    The approval still has to match the asset, invariant, operation, and
    subject, and it is single-use. Arming is not itself authorisation.
    """
    _ARMED.set(approval_public(record) if hasattr(record, "digest") else dict(record))


def precheck_action(action: dict[str, Any]) -> IntegrityDecision | None:
    """Run before the original call. Raises nothing; the caller must honour ``prevents``."""
    from .io_guard import internal_io_active

    if internal_io_active():
        return None
    armed = _ARMED.get()
    if armed is not None:
        metadata = dict(action.get("metadata") or {})
        metadata.setdefault("mip_approval", armed)
        action = dict(action)
        action["metadata"] = metadata
        _ARMED.set(None)
    registry = current_registry()
    if not registry.enabled:
        return None
    try:
        decision = _decider(registry).evaluate(action, before_execution=True)
    except Exception as exc:
        if registry.fail_closed and registry.mode in {"guarded", "strict", "enforce"}:
            decision = IntegrityDecision(
                outcome=Outcome.UNKNOWN,
                reason=f"monitoring integrity evaluation failed: {exc.__class__.__name__}",
                invariant_id="INV-008",
                surface=str(action.get("type") or "unknown"),
                enforced_action="block",
                intercepted_before_execution=True,
                policy_version=registry.policy_version,
                coverage_status="UNKNOWN",
                limitations=["Evaluation failed closed. The side effect is prevented only if the caller does not run the original function."],
            )
        else:
            return None
    if decision is None:
        return None
    if decision.outcome != Outcome.ALLOW:
        _remember(decision)
    return decision


def apply_to_decision(action: Any, decision: Decision, policy_doc: dict | None) -> tuple[Decision, Any]:
    """Strengthen a control-plane decision. Returns ``(decision, context_token)``.

    The token is None when MIP is inactive. Callers reset it after Predictive
    Authority has read the bound registry. This does not by itself prevent a
    side effect; the intercepting client has to honour the returned action.
    """
    section = (policy_doc or {}).get("monitoring_integrity") if isinstance(policy_doc, dict) else None
    if not isinstance(section, dict) or not section.get("enabled"):
        return decision, None
    try:
        registry = registry_for_section(section)
    except Exception:
        if str(section.get("mode") or "") in {"guarded", "strict"} and section.get("fail_closed", True):
            blocked = Decision(
                action="block",
                reason="monitoring integrity policy failed to load",
                matched_rule={"type": "monitoring_integrity", "invariant": "INV-008"},
                effective_action="block",
            )
            return _merge(decision, blocked), None
        return decision, None
    token = bind_registry(registry)
    payload = _action_dict(action)
    try:
        mip = _decider(registry).evaluate(payload, before_execution=False)
    except Exception:
        mip = IntegrityDecision(
            outcome=Outcome.UNKNOWN,
            reason="monitoring integrity evaluation failed",
            invariant_id="INV-008",
            enforced_action="block" if registry.fail_closed else None,
            policy_version=registry.policy_version,
        )
    if mip is not None and mip.outcome != Outcome.ALLOW:
        _remember(mip, registry=registry)
    strengthened = strengthen(decision.action, mip)
    if mip is not None:
        metadata = dict(getattr(action, "metadata", None) or {})
        metadata["monitoring_integrity"] = mip.to_dict()
        try:
            action.metadata = metadata
        except Exception:
            pass
    if strengthened == decision.action:
        return decision, token
    merged = Decision(
        action=strengthened,
        reason=(mip.reason if mip else decision.reason),
        matched_rule={
            "type": "monitoring_integrity",
            "invariant": mip.invariant_id if mip else None,
            "asset_id": mip.asset_id if mip else None,
            "outcome": mip.outcome.value if mip else None,
        },
        effective_action=strengthened,
        route_target=decision.route_target,
    )
    return merged, token


def posture(policy_doc: dict | None = None) -> dict[str, Any]:
    registry = current_registry()
    if isinstance(policy_doc, dict) and isinstance(policy_doc.get("monitoring_integrity"), dict):
        try:
            registry = registry_for_section(policy_doc["monitoring_integrity"])
        except Exception as exc:
            return {
                "enabled": True,
                "posture": "unknown",
                "reason": f"policy_load_failed:{exc.__class__.__name__}",
                "os_isolation": False,
                "verified_protection": False,
            }
    if not registry.enabled:
        return {
            "enabled": False,
            "posture": "disabled",
            "verified_protection": False,
            "os_isolation": False,
            "independent_watchdog": False,
            "trust_boundary": "not_enabled",
            "limitations": [
                "Monitoring integrity is off. No protection is claimed.",
                "Platform cells are capability declarations. None of them is a live verified execution.",
            ],
            "platform_matrix": platform_matrix(),
            "protection_tier": "NOT_ENFORCEABLE",
            "boundary": {
                "tier": "NOT_ENFORCEABLE",
                "mechanism": "not_enabled",
                "verified": False,
                "os_isolation": False,
                "scope": "Monitoring integrity is off.",
            },
        }
    assets = []
    for asset in registry.assets():
        if asset.lexical_path:
            registry.refresh_verification(asset.id)
        assets.append(asset.to_dict())
    degraded = [row for row in assets if row["protected"] and row["verification"] not in {"verified", "unprotected"}]
    analysis = analyse(registry)
    return {
        "enabled": True,
        "mode": registry.mode,
        "posture": "degraded" if degraded else "verified_configuration",
        "verified_protection": False,
        "configuration_verified": not degraded,
        "os_isolation": False,
        "independent_watchdog": False,
        "trust_boundary": "python_interceptor_plus_optional_external_watchdog",
        "policy_version": registry.policy_version,
        "assets": assets,
        "invariants": invariant_catalog(registry.invariants),
        "grants": [grant.to_dict() for grant in registry.grants()],
        "analysis": analysis,
        "evidence_head": _EVIDENCE.head,
        "evidence_chain_ok": _EVIDENCE.verify_chain(),
        "limitations": [
            "Verified configuration means the sealed file digests still match. It does not mean every execution surface is enforced.",
            "Filesystem and subprocess coverage remain PARTIAL. OS isolation is not provided.",
            "An in-process caller is not an independent watchdog.",
            "Predictive paths are prevented only where an interruption is enforceable and intercepted before the side effect.",
            "This posture is not a live supervised execution. A boundary gauntlet on another process is not verification of this one.",
            "Linux and Windows adapters fail closed until a probe on that operating system succeeds. The matrix does not call them verified.",
        ],
        "platform_matrix": platform_matrix(),
        "surfaces": {
            "filesystem": "PARTIAL",
            "subprocess": "PARTIAL",
            "http": "PARTIAL",
            "mcp": "ENFORCED only when the gateway is the live route; otherwise NOT_ROUTED",
            "environment": "PARTIAL",
            "process_signal": "PARTIAL",
            "os_exec": "NOT_ENFORCEABLE",
        },
        "protection_tier": "INTERCEPTED",
        "boundary": {
            "tier": "INTERCEPTED",
            "mechanism": "python_interceptor",
            "verified": False,
            "os_isolation": False,
            "origin": "default",
            "scope": "In-process hooks can block a patched call. Equivalent-authority code can bypass them. This response did not run an OS probe.",
            "coverage_status": "PARTIAL",
        },
        "live_execution": None,
        "historical_gauntlet_is_not_live_posture": True,
    }


def issue_approval(**kwargs):
    return _APPROVALS.issue(**kwargs)


def approval_public(record) -> dict[str, Any]:
    data = record.to_dict()
    data["digest"] = record.digest
    return data


def _remember(decision: IntegrityDecision, registry: AssetRegistry | None = None) -> None:
    registry = registry or current_registry()
    event = decision.to_dict()
    event["note"] = "This record is the decision. Prevention is established only by the absence of the prohibited side effect."
    if registry is _REGISTRY or registry.evidence_path == _EVIDENCE.path:
        _EVIDENCE.append(event)


def _action_dict(action: Any) -> dict[str, Any]:
    if isinstance(action, dict):
        return action
    return {
        "type": getattr(action, "type", None),
        "tool": getattr(action, "tool", None),
        "method": getattr(action, "method", None),
        "url": getattr(action, "url", None),
        "args": dict(getattr(action, "args", None) or {}),
        "metadata": dict(getattr(action, "metadata", None) or {}),
        "agent_name": getattr(action, "agent_name", None),
    }


def _merge(existing: Decision, blocked: Decision) -> Decision:
    if strengthen(existing.action, IntegrityDecision(outcome=Outcome.DENY, reason="", enforced_action=blocked.action)) == blocked.action:
        return blocked
    return existing


def _install_process_guards() -> None:
    global _KILL, _ENV_SETITEM, _ENV_DELITEM
    if _KILL is None:
        _KILL = os.kill

        def _guarded_kill(pid, sig):
            try:
                number = int(sig)
            except (TypeError, ValueError):
                number = None
            if number in {15, 9, 19, 6, 3, 2} and enabled():
                decision = precheck_action({
                    "type": "tool_call",
                    "tool": "os.kill",
                    "args": {"pid": int(pid), "signal": number},
                    "metadata": {"execution_surface": "process", "runtime": {"surface": "process", "boundary": True}},
                    "agent_name": None,
                })
                if decision is not None and decision.prevents:
                    from varden_sdk.sdk import VardenBlockedError

                    raise VardenBlockedError(
                        f"os.kill blocked for protected monitoring pid {pid}",
                        decision.to_dict(),
                    )
            return _KILL(pid, sig)

        os.kill = _guarded_kill
    if _ENV_SETITEM is None:
        environ_type = type(os.environ)
        _ENV_SETITEM = environ_type.__setitem__
        _ENV_DELITEM = environ_type.__delitem__

        def _guarded_set(self, key, value):
            _guard_env(key, value, unset=False)
            return _ENV_SETITEM(self, key, value)

        def _guarded_del(self, key):
            _guard_env(key, None, unset=True)
            return _ENV_DELITEM(self, key)

        environ_type.__setitem__ = _guarded_set
        environ_type.__delitem__ = _guarded_del


def _guard_env(key, value, *, unset: bool) -> None:
    if not enabled() or internal_io_active():
        return
    decision = precheck_action({
        "type": "tool_call",
        "tool": "os.environ",
        "args": {"key": str(key), "value": value, "unset": unset},
        "metadata": {"execution_surface": "environment", "runtime": {"surface": "environment", "boundary": True}},
        "agent_name": None,
    })
    if decision is not None and decision.prevents:
        from varden_sdk.sdk import VardenBlockedError

        raise VardenBlockedError(f"protected environment key {key} cannot be changed", decision.to_dict())


def _restore_process_guards() -> None:
    global _KILL, _ENV_SETITEM, _ENV_DELITEM
    if _KILL is not None:
        os.kill = _KILL
        _KILL = None
    if _ENV_SETITEM is not None:
        environ_type = type(os.environ)
        environ_type.__setitem__ = _ENV_SETITEM
        environ_type.__delitem__ = _ENV_DELITEM
        _ENV_SETITEM = None
        _ENV_DELITEM = None


def validate_section(section: Any) -> list[str]:
    from .invariants import INVARIANTS

    if section is None:
        return []
    if not isinstance(section, dict):
        return ["monitoring_integrity must be an object"]
    errors: list[str] = []
    mode = str(section.get("mode") or "guarded")
    if mode not in {"off", "observe", "guarded", "strict"}:
        errors.append(f"monitoring_integrity.mode {mode!r} is not off|observe|guarded|strict")
    assets = section.get("assets", [])
    if not isinstance(assets, list):
        errors.append("monitoring_integrity.assets must be a list")
    else:
        seen = set()
        for index, asset in enumerate(assets):
            if not isinstance(asset, dict):
                errors.append(f"monitoring_integrity.assets[{index}] must be an object")
                continue
            asset_id = str(asset.get("id") or "")
            if not asset_id:
                errors.append(f"monitoring_integrity.assets[{index}] needs an id")
            elif asset_id in seen:
                errors.append(f"duplicate monitoring asset id {asset_id!r}")
            seen.add(asset_id)
            if asset.get("protected") and not any(asset.get(key) for key in ("path", "env_keys", "process_names", "endpoint", "protected_pids")):
                errors.append(f"protected asset {asset_id or index} needs a path, endpoint, process, or environment identity")
    requested = section.get("invariants")
    if requested is not None:
        if not isinstance(requested, list):
            errors.append("monitoring_integrity.invariants must be a list")
        else:
            for item in requested:
                if item not in INVARIANTS:
                    errors.append(f"unknown invariant {item!r}")
    return errors
