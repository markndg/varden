"""Pre-execution monitoring-integrity decisions.

``prevented`` stays false here. The interceptor proves prevention by not
calling the original function. A decision object alone is not that proof.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from varden.predictive_authority.policy import decision_rank
from varden.url_identity import DestinationRejected, canonicalize_destination

from .approvals import ApprovalStore
from .assets import (
    MUTATING_OPERATIONS,
    AssetMatch,
    AssetRegistry,
    MonitoringAsset,
    VerificationState,
)
from .child import (
    CONSEQUENTIAL_SIGNALS,
    classify_argv,
    extract_argv,
    paths_from_intent,
)
from .invariants import INVARIANTS

MODE_RANK = {"off": 0, "observe": 1, "guarded": 2, "enforce": 2, "strict": 3}
_WRITE_MODES = set("wa+")


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    UNKNOWN = "UNKNOWN"
    NOT_ENFORCEABLE = "NOT_ENFORCEABLE"


@dataclass
class IntegrityDecision:
    outcome: Outcome
    reason: str
    invariant_id: str | None = None
    asset_id: str | None = None
    surface: str | None = None
    enforced_action: str | None = None
    prevented: bool = False
    intercepted_before_execution: bool = False
    policy_version: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    authority_path: list[str] = field(default_factory=list)
    coverage_status: str = "UNKNOWN"
    limitations: list[str] = field(default_factory=list)
    applicable_invariants: list[str] = field(default_factory=list)
    os_isolation: bool = False

    @property
    def prevents(self) -> bool:
        return self.enforced_action in {"block", "require_approval"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "reason": self.reason,
            "invariant_id": self.invariant_id,
            "asset_id": self.asset_id,
            "surface": self.surface,
            "enforced_action": self.enforced_action,
            "prevents_execution": self.prevents,
            "prevented": self.prevented,
            "intercepted_before_execution": self.intercepted_before_execution,
            "policy_version": self.policy_version,
            "evidence": self.evidence,
            "authority_path": list(self.authority_path),
            "coverage_status": self.coverage_status,
            "limitations": list(self.limitations),
            "applicable_invariants": list(self.applicable_invariants),
            "os_isolation": False,
            "trust_boundary": "python_interceptor",
        }


def _surface(action: dict[str, Any]) -> str:
    metadata = action.get("metadata") or {}
    runtime = metadata.get("runtime") if isinstance(metadata, dict) else None
    if isinstance(runtime, dict) and runtime.get("surface"):
        return str(runtime["surface"])
    if isinstance(metadata, dict) and metadata.get("execution_surface"):
        return str(metadata["execution_surface"])
    action_type = str(action.get("type") or "")
    if action_type in {"filesystem", "http_request", "mcp_call"}:
        return {"filesystem": "filesystem", "http_request": "http", "mcp_call": "mcp"}[action_type]
    tool = str(action.get("tool") or "")
    if "subprocess" in tool or tool in {"os.system", "os.kill"}:
        return "subprocess" if tool != "os.kill" else "process"
    return action_type or "unknown"


def _filesystem_operation(mode: str, tool: str) -> str:
    name = tool.lower()
    if any(token in name for token in ("replace", "rename", "move")):
        return "replace" if "rename" not in name else "rename"
    if any(token in name for token in ("unlink", "remove", "rmdir")):
        return "unlink"
    if "symlink" in name:
        return "symlink"
    if "chmod" in name:
        return "chmod"
    text = str(mode or "r")
    if any(flag in text for flag in _WRITE_MODES) or "w" in text:
        if "a" in text and "w" not in text:
            return "append"
        return "write"
    return "read"


def _dig(document: Any, dotted: str) -> Any:
    current = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _body(action: dict[str, Any]) -> Any:
    args = action.get("args") or {}
    if not isinstance(args, dict):
        return None
    for key in ("content", "data", "body", "text"):
        if key in args:
            return args[key]
    return None


def _parse_document(body: Any) -> dict[str, Any] | None:
    if isinstance(body, dict):
        return body
    if isinstance(body, str):
        stripped = body.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, dict) else None
    return None


def _presented_approval(action: dict[str, Any]) -> dict[str, Any] | None:
    metadata = action.get("metadata") or {}
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get("mip_approval")
    return raw if isinstance(raw, dict) else None


def _agent(action: dict[str, Any], registry: AssetRegistry) -> str:
    name = str(action.get("agent_name") or "")
    if name:
        return name
    if len(registry.protected_agents) == 1:
        return next(iter(registry.protected_agents))
    return "agent"


def _is_protected_actor(agent: str, registry: AssetRegistry, *, trusted_operator: bool) -> bool:
    if trusted_operator:
        return False
    if not registry.protected_agents:
        return True
    return agent in registry.protected_agents


def _coverage_claim(action: dict[str, Any]) -> bool:
    metadata = action.get("metadata") or {}
    if not isinstance(metadata, dict):
        return False
    claim = metadata.get("coverage_claim")
    if isinstance(claim, dict):
        status = str(claim.get("status") or claim.get("coverage") or "").upper()
        return status in {"ENFORCED", "FULL", "COMPLETE"} or bool(claim.get("full_coverage"))
    return False


def _live_coverage_gaps(required: list[str]) -> list[str]:
    if not required:
        return []
    try:
        from varden.runtime.coverage import get_coverage_registry

        attestation = get_coverage_registry().attestation()
    except Exception:
        return list(required)
    surfaces = {item.get("name"): item for item in (attestation.get("surfaces") or []) if isinstance(item, dict)}
    gaps = []
    for name in required:
        row = surfaces.get(name)
        if row is None:
            gaps.append(name)
            continue
        if row.get("status") != "ENFORCED" or row.get("verified") is not True:
            gaps.append(name)
    return gaps


class Decider:
    def __init__(self, registry: AssetRegistry, approvals: ApprovalStore) -> None:
        self.registry = registry
        self.approvals = approvals

    def evaluate(self, action: dict[str, Any], *, trusted_operator: bool = False, before_execution: bool = False) -> IntegrityDecision | None:
        registry = self.registry
        if not registry.enabled:
            return None
        surface = _surface(action)
        agent = _agent(action, registry)
        protected_actor = _is_protected_actor(agent, registry, trusted_operator=trusted_operator)
        if not protected_actor:
            return None
        operation, matches, intent, extra = self._bind(action)
        considered = [match for match in matches if match.asset.protected]
        env_assets = extra.get("env_assets") or []
        process_assets = extra.get("process_assets") or []
        endpoint_assets = extra.get("endpoint_assets") or []
        if not considered and not env_assets and not process_assets and not endpoint_assets and not intent.activations:
            monitored_child = (
                registry.require_monitored_child
                and surface in {"subprocess", "process"}
                and intent.coverage in {"unknown", "absent", "partial"}
                and intent.reason in {"interpreter_launch", "unobservable_interpreter", "shell_parse_failed", "argv_missing", "unobservable_interpreter"}
            )
            if monitored_child or (
                operation in MUTATING_OPERATIONS
                and intent.coverage == "unknown"
                and registry.require_monitored_child
                and surface in {"subprocess", "process"}
            ):
                return self._finish(
                    Outcome.UNKNOWN,
                    "child launch has no verified enforcement boundary",
                    "INV-006",
                    None,
                    surface,
                    action,
                    before_execution,
                    evidence={"intent": intent.to_dict(), "coverage": intent.coverage},
                )
            return None
        primary = considered[0].asset if considered else (env_assets or process_assets or endpoint_assets or [None])[0]
        if isinstance(primary, AssetMatch):
            primary = primary.asset
        verdicts: list[tuple[Outcome, str, str, MonitoringAsset | None]] = []
        for match in considered:
            verdicts.extend(self._asset_verdicts(action, match.asset, operation, agent, intent))
        for asset in env_assets:
            verdicts.extend(self._env_verdicts(action, asset, operation, extra))
        for asset in process_assets:
            verdicts.extend(self._process_verdicts(asset, intent, extra))
        for asset in endpoint_assets:
            verdicts.extend(self._endpoint_verdicts(action, asset, operation))
        for asset_id in intent.activations:
            asset = registry.get(asset_id)
            if asset and asset.protected:
                verdicts.append((Outcome.DENY, "activation would apply a staged monitoring change", "INV-003", asset))
        if intent.service_tool and not intent.observable:
            protected_processes = [
                asset for asset in registry.assets() if asset.protected and (asset.process_names or asset.protected_pids)
            ]
            if protected_processes:
                verdicts.append((
                    Outcome.UNKNOWN,
                    "service-control command is not fully observable",
                    "INV-008",
                    protected_processes[0],
                ))
        if _coverage_claim(action):
            gaps = _live_coverage_gaps(list(extra.get("required_coverage") or []))
            if gaps or True:
                # Agent claims are never evidence. A claim of full coverage is denied
                # when it is attached to a mediated publish; otherwise it is stripped
                # by not being trusted. Here the action reached a protected asset.
                if gaps or primary is not None:
                    verdicts.append((
                        Outcome.DENY,
                        "agent coverage claim is not evidence of enforcement",
                        "INV-005",
                        primary if isinstance(primary, MonitoringAsset) else None,
                    ))
        if not verdicts:
            if operation not in MUTATING_OPERATIONS:
                return self._allow(surface, primary if isinstance(primary, MonitoringAsset) else None, "permitted read", before_execution)
            return self._allow(surface, primary if isinstance(primary, MonitoringAsset) else None, "no invariant fired", before_execution)
        outcome, reason, invariant_id, asset = _strongest(verdicts)
        asset = asset if isinstance(asset, MonitoringAsset) else (primary if isinstance(primary, MonitoringAsset) else None)
        if outcome in {Outcome.DENY, Outcome.REQUIRE_APPROVAL, Outcome.UNKNOWN} and asset is not None:
            ok, why = self._approval(action, asset, invariant_id or "INV-008", operation, agent)
            if ok:
                return self._allow(surface, asset, f"independent approval consumed ({why})", before_execution, invariant_id=invariant_id)
            if outcome == Outcome.REQUIRE_APPROVAL and why == "approval_missing":
                pass
            elif why not in {"approval_missing"} and outcome != Outcome.UNKNOWN:
                outcome = Outcome.DENY
                reason = f"{reason}; {why}"
        return self._finish(
            outcome,
            reason,
            invariant_id,
            asset.id if asset else None,
            surface,
            action,
            before_execution,
            evidence={
                "operation": operation,
                "via": [match.to_dict() for match in considered],
                "intent": intent.to_dict() if intent.argv else None,
                "verification": asset.verification.value if asset else None,
            },
        )

    def _approval(self, action: dict[str, Any], asset: MonitoringAsset, invariant_id: str, operation: str, agent: str) -> tuple[bool, str]:
        return self.approvals.consume(
            _presented_approval(action),
            asset_id=asset.id,
            invariant_id=invariant_id,
            operation=operation,
            subject_agent=agent,
        )

    def _asset_verdicts(self, action, asset: MonitoringAsset, operation: str, agent: str, intent):
        found: list[tuple[Outcome, str, str, MonitoringAsset]] = []
        active = set(self.registry.invariants)
        if operation not in MUTATING_OPERATIONS:
            return found
        if operation not in asset.permitted_operations and "INV-008" in active:
            state = asset.verification
            if state in {VerificationState.MISSING, VerificationState.STALE, VerificationState.MISMATCHED, VerificationState.UNOBSERVABLE, VerificationState.UNKNOWN}:
                found.append((Outcome.UNKNOWN, f"mandatory evidence is {state.value}: {asset.verification_detail}", "INV-008", asset))
        invariant = _invariant_for(asset, operation)
        if invariant and invariant in active and operation not in asset.permitted_operations:
            found.append((Outcome.DENY, f"{operation} is not a permitted operation on {asset.id}", invariant, asset))
        body = _parse_document(_body(action))
        if body is not None and asset.integrity_fields and operation in {"write", "append", "replace"}:
            found.extend(_field_weakening(asset, body, active))
        if asset.asset_type.value == "policy" and "INV-007" in active and operation in MUTATING_OPERATIONS:
            if operation not in asset.permitted_operations:
                found.append((Outcome.DENY, "protected agent cannot rewrite its own authorising policy", "INV-007", asset))
        if intent.activations and asset.id in intent.activations and "INV-009" not in active:
            found.append((Outcome.DENY, "child activation targets a protected monitoring asset", "INV-006", asset))
        for token in paths_from_intent(intent):
            if any(match.asset.id == asset.id for match in self.registry.match_path(token)):
                if operation in MUTATING_OPERATIONS or intent.reason in {"activation_boundary", "interpreter_launch", "unobservable_interpreter"}:
                    found.append((Outcome.DENY, "child arguments resolve to a protected monitoring asset", "INV-006", asset))
                    break
        return found

    def _env_verdicts(self, action, asset: MonitoringAsset, operation: str, extra: dict[str, Any]):
        if "INV-001" not in set(self.registry.invariants) and "INV-002" not in set(self.registry.invariants):
            return []
        key = str(extra.get("env_key") or "")
        value = extra.get("env_value")
        if operation == "env_unset":
            return [(Outcome.DENY, f"unsetting {key} removes a sealed security setting", "INV-001", asset)]
        if key in {"VARDEN_MODE", "VARDEN_FAIL_MODE"} or asset.asset_type.value == "enforcement_config":
            if _mode_downgrade(key, value, self.registry.mode):
                return [(Outcome.DENY, f"{key} would downgrade enforcement", "INV-001", asset)]
        if operation not in asset.permitted_operations:
            return [(Outcome.DENY, f"change to protected environment key {key}", "INV-001", asset)]
        return []

    def _process_verdicts(self, asset: MonitoringAsset, intent, extra: dict[str, Any]):
        if "INV-003" not in set(self.registry.invariants) and "INV-005" not in set(self.registry.invariants):
            active = set(self.registry.invariants)
        else:
            active = set(self.registry.invariants)
        signal = extra.get("signal")
        if signal is not None and int(signal) not in CONSEQUENTIAL_SIGNALS:
            return []
        if intent is not None and intent.service_tool and not intent.observable:
            return [(Outcome.UNKNOWN, "service-control command is not fully observable", "INV-008", asset)]
        if intent is not None and intent.service_targets:
            names = set(asset.process_names)
            pids = {str(pid) for pid in asset.protected_pids}
            for target in intent.service_targets:
                if target in names or os.path.basename(target) in names or target in pids:
                    return [(Outcome.DENY, "service control targets a protected monitoring process", "INV-003", asset)]
            if intent.service_tool in {"pkill", "killall"} and any(char in "".join(intent.service_targets) for char in "$`*[]"):
                return [(Outcome.UNKNOWN, "service-control pattern is not a concrete identity", "INV-008", asset)]
        if extra.get("pid") is not None and int(extra["pid"]) in asset.protected_pids:
            return [(Outcome.DENY, "signal targets a protected monitoring pid", "INV-003", asset)]
        if active:
            return []
        return []

    def _endpoint_verdicts(self, action, asset: MonitoringAsset, operation: str):
        if operation not in MUTATING_OPERATIONS:
            return []
        method = str(action.get("method") or "").upper()
        if method and method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return []
        return [(Outcome.DENY, f"{method or 'mutation'} targets a protected control-plane endpoint", "INV-004" if asset.asset_type.value == "notification_destination" else "INV-001", asset)]

    def _bind(self, action: dict[str, Any]):
        tool = str(action.get("tool") or "")
        args = action.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        surface = _surface(action)
        matches: list[AssetMatch] = []
        extra: dict[str, Any] = {"required_coverage": []}
        if surface == "filesystem" or str(action.get("type") or "") == "filesystem":
            path = args.get("path") or args.get("dst") or args.get("destination") or args.get("src")
            mode = str(args.get("mode") or "r")
            operation = _filesystem_operation(mode, tool)
            if path:
                matches = self.registry.match_path(str(path))
            dst = args.get("dst") or args.get("destination")
            if dst and str(dst) != str(path):
                matches.extend(self.registry.match_path(str(dst)))
            return operation, matches, classify_argv(None, registry=self.registry, mediated=True), extra
        if surface in {"subprocess", "process"} or "subprocess" in tool or tool in {"os.system", "os.kill"}:
            argv = extract_argv(action)
            intent = classify_argv(argv, registry=self.registry, mediated=True)
            for token in paths_from_intent(intent):
                matches.extend(self.registry.match_path(token))
            for name in intent.service_targets:
                extra.setdefault("process_assets", [])
                extra["process_assets"].extend(self.registry.match_process_name(name))
                if name.isdigit():
                    extra["process_assets"].extend(self.registry.match_pid(int(name)))
            if tool == "os.kill":
                extra["pid"] = args.get("pid")
                extra["signal"] = args.get("signal")
                if extra["pid"] is not None:
                    extra.setdefault("process_assets", [])
                    extra["process_assets"].extend(self.registry.match_pid(int(extra["pid"])))
            return "exec" if tool != "os.kill" else "signal", matches, intent, extra
        if surface == "environment" or tool == "os.environ":
            key = str(args.get("key") or "")
            extra["env_key"] = key
            extra["env_value"] = args.get("value")
            extra["env_assets"] = self.registry.match_env_key(key)
            operation = "env_unset" if args.get("unset") else "env_set"
            return operation, [], classify_argv(None, registry=self.registry, mediated=True), extra
        if surface == "http" or str(action.get("type") or "") == "http_request":
            url = str(action.get("url") or args.get("url") or "")
            operation = "http_mutation" if str(action.get("method") or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"} else "read"
            canonical = None
            try:
                if url:
                    dest = canonicalize_destination(url)
                    canonical = dest.canonical_url
                    extra["endpoint_assets"] = self.registry.match_endpoint(canonical, dest.host)
                    if dest.rejection and operation == "http_mutation":
                        extra["destination_rejected"] = dest.rejection
            except DestinationRejected as exc:
                extra["destination_rejected"] = exc.code
            return operation, matches, classify_argv(None, registry=self.registry, mediated=True), extra
        intent = classify_argv(extract_argv(action), registry=self.registry, mediated=surface == "mcp")
        return "mcp_call" if surface == "mcp" else "write", matches, intent, extra

    def _allow(self, surface, asset, reason, before_execution, invariant_id=None) -> IntegrityDecision:
        decision = IntegrityDecision(
            outcome=Outcome.ALLOW,
            reason=reason,
            invariant_id=invariant_id,
            asset_id=asset.id if asset else None,
            surface=surface,
            policy_version=self.registry.policy_version,
            coverage_status=_surface_coverage(surface),
            intercepted_before_execution=before_execution,
        )
        self._apply_mode(decision)
        return decision

    def _finish(self, outcome, reason, invariant_id, asset_id, surface, action, before_execution, evidence) -> IntegrityDecision:
        spec = INVARIANTS.get(invariant_id or "")
        decision = IntegrityDecision(
            outcome=outcome,
            reason=reason,
            invariant_id=invariant_id,
            asset_id=asset_id,
            surface=surface,
            policy_version=self.registry.policy_version,
            evidence=evidence,
            authority_path=[str(action.get("agent_name") or "agent"), surface, asset_id or ""],
            coverage_status=_surface_coverage(surface),
            limitations=list(spec.limitations) if spec else [],
            applicable_invariants=list(self.registry.invariants),
            intercepted_before_execution=before_execution,
        )
        if outcome == Outcome.NOT_ENFORCEABLE:
            decision.limitations.append("No interceptor is available for this operation. The side effect is not prevented by this decision.")
        self._apply_mode(decision)
        return decision

    def _apply_mode(self, decision: IntegrityDecision) -> None:
        mode = self.registry.mode
        if decision.outcome == Outcome.ALLOW:
            decision.enforced_action = "allow"
            return
        if decision.outcome == Outcome.NOT_ENFORCEABLE:
            decision.enforced_action = None
            return
        if mode == "observe":
            decision.enforced_action = None
            decision.limitations.append("MIP observe records the violation and does not prevent the side effect.")
            return
        if decision.outcome == Outcome.REQUIRE_APPROVAL:
            decision.enforced_action = "require_approval"
            return
        if decision.outcome == Outcome.UNKNOWN:
            if self.registry.fail_closed and mode in {"guarded", "strict", "enforce"}:
                decision.enforced_action = "block"
                decision.reason = "fail closed: " + decision.reason
            else:
                decision.enforced_action = None
            return
        decision.enforced_action = "block"


def _strongest(verdicts):
    rank = {Outcome.DENY: 4, Outcome.REQUIRE_APPROVAL: 3, Outcome.UNKNOWN: 2, Outcome.NOT_ENFORCEABLE: 1, Outcome.ALLOW: 0}
    return max(verdicts, key=lambda item: rank[item[0]])


def _invariant_for(asset: MonitoringAsset, operation: str) -> str | None:
    mapping = {
        "enforcement_config": "INV-001",
        "security_environment": "INV-001",
        "audit_storage": "INV-002",
        "logging_config": "INV-002",
        "monitoring_integration": "INV-003",
        "runtime_instrumentation": "INV-003",
        "protected_executable": "INV-003",
        "notification_destination": "INV-004",
        "coverage_declaration": "INV-005",
        "attestation_record": "INV-005",
        "policy": "INV-007",
        "control_plane_endpoint": "INV-001",
        "application": "INV-003",
    }
    return mapping.get(asset.asset_type.value)


def _mode_downgrade(key: str, value: Any, sealed_mode: str) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    if key == "VARDEN_FAIL_MODE":
        return text == "open"
    if key == "VARDEN_MODE":
        return MODE_RANK.get(text, 99) < MODE_RANK.get(sealed_mode, 2)
    return False


def _field_weakening(asset: MonitoringAsset, body: dict[str, Any], active: set[str]):
    found = []
    for item in asset.integrity_fields:
        proposed = _dig(body, item.path)
        if item.kind == "boolean_enabled" and proposed is False and "INV-002" in active:
            found.append((Outcome.DENY, f"{item.path} would disable a mandatory control", "INV-002", asset))
        elif item.kind == "enforcement_mode" and proposed is not None and "INV-001" in active:
            if MODE_RANK.get(str(proposed).lower(), 99) < MODE_RANK.get("guarded", 2):
                found.append((Outcome.DENY, f"{item.path} downgrades enforcement mode", "INV-001", asset))
        elif item.kind == "fail_mode" and str(proposed).lower() == "open" and "INV-001" in active:
            found.append((Outcome.DENY, f"{item.path} switches fail mode to open", "INV-001", asset))
        elif item.kind == "destination" and proposed is not None and "INV-004" in active:
            try:
                dest = canonicalize_destination(str(proposed))
            except DestinationRejected:
                found.append((Outcome.UNKNOWN, f"{item.path} is not a canonical destination", "INV-004", asset))
                continue
            allowed = {value.rstrip("/") for value in item.allow}
            if dest.rejection or not dest.canonical_url or dest.canonical_url.rstrip("/") not in allowed:
                found.append((Outcome.DENY, f"{item.path} is not an authorised notification destination", "INV-004", asset))
        elif item.kind == "equality" and proposed is None and "INV-008" in active:
            found.append((Outcome.UNKNOWN, f"{item.path} missing from proposed document", "INV-008", asset))
    return found


def _surface_coverage(surface: str) -> str:
    if surface in {"filesystem", "subprocess", "http", "process"}:
        return "PARTIAL"
    if surface == "mcp":
        return "NOT_ROUTED"
    if surface == "environment":
        return "PARTIAL"
    return "UNKNOWN"


def strengthen(existing_action: str, decision: IntegrityDecision | None):
    """Return the enforced action. Never weaker than ``existing_action``."""
    if decision is None or not decision.enforced_action:
        return existing_action
    if decision_rank(decision.enforced_action) > decision_rank(existing_action):
        return decision.enforced_action
    return existing_action
