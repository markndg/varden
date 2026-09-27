"""Predictive Authority configuration.

Default is fully off so existing Varden behaviour is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


VALID_MODES = frozenset({"off", "observe", "enforce"})
VALID_FAILURE_MODES = frozenset({"preserve_existing", "require_approval", "block", "closed", "open"})


@dataclass(frozen=True)
class PredictiveAuthorityConfig:
    """Feature configuration for Predictive Authority.

    ``enabled=False`` / ``mode="off"`` → no analysis.
    ``mode="observe"`` → analyse and record; never change enforcement.
    ``mode="enforce"`` → may strengthen existing decisions only.

    ``failure_mode`` (when PA itself fails or truncates in enforce):
      - preserve_existing: keep existing Varden decision
      - require_approval: strengthen to require_approval (default for enforce)
      - block: strengthen to block
    Legacy aliases: closed→preserve_existing, open→preserve_existing.
    """

    enabled: bool = False
    mode: str = "off"
    max_depth: int = 3
    max_authority_units: int | None = None
    max_nodes: int = 2048
    max_edges: int = 8192
    max_history: int = 256
    # Enforce default: incomplete/truncated analysis must not conclude SAFE/ALLOW.
    # Observe never changes decisions regardless; preserve_existing remains available explicitly.
    failure_mode: str = "require_approval"
    # Backward-compatible alias read by older code paths.
    fail_mode: str = "closed"
    audit: bool = True

    def is_active(self) -> bool:
        return bool(self.enabled) and self.mode in {"observe", "enforce"}

    def is_enforce(self) -> bool:
        return self.is_active() and self.mode == "enforce"

    def is_observe(self) -> bool:
        return self.is_active() and self.mode == "observe"

    def resolved_failure_mode(self) -> str:
        raw = str(self.failure_mode or self.fail_mode or "require_approval").strip().lower()
        if raw in {"closed", "open"}:
            # Legacy fail_mode aliases: treat as preserve_existing only when explicitly set
            # via fail_mode without a modern failure_mode override.
            if self.failure_mode in {"require_approval", "block", "preserve_existing"}:
                return "preserve_existing" if self.failure_mode == "preserve_existing" else self.failure_mode
            return "preserve_existing"
        if raw == "preserve_existing":
            return "preserve_existing"
        if raw in {"require_approval", "block"}:
            return raw
        # Unknown → fail closed for enforce, preserve for observe.
        return "require_approval" if self.mode == "enforce" else "preserve_existing"

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "max_depth": self.max_depth,
            "max_authority_units": self.max_authority_units,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "max_history": self.max_history,
            "failure_mode": self.resolved_failure_mode(),
            "fail_mode": self.fail_mode,
            "audit": self.audit,
        }


def _default_failure_for_mode(mode: str, explicit: str | None) -> str:
    if explicit:
        text = str(explicit).strip().lower()
        if text in {"closed", "open"}:
            return "preserve_existing"
        if text in VALID_FAILURE_MODES:
            return "preserve_existing" if text in {"closed", "open"} else text
    if mode == "enforce":
        return "require_approval"
    return "preserve_existing"


def parse_predictive_config(raw: Any = None, *, env: dict[str, str] | None = None) -> PredictiveAuthorityConfig:
    env = env or {}
    data: dict[str, Any] = {}

    env_enabled = env.get("VARDEN_PREDICTIVE_AUTHORITY") or env.get("VARDEN_PA_ENABLED")
    env_mode = env.get("VARDEN_PA_MODE")
    env_depth = env.get("VARDEN_PA_MAX_DEPTH")
    env_fail = env.get("VARDEN_PA_FAILURE_MODE")
    if env_enabled is not None:
        data["enabled"] = str(env_enabled).strip().lower() in {"1", "true", "yes", "on"}
        if data["enabled"] and "mode" not in data:
            data["mode"] = "observe"
    if env_mode:
        data["mode"] = str(env_mode).strip().lower()
        data.setdefault("enabled", data["mode"] != "off")
    if env_depth:
        try:
            data["max_depth"] = max(0, int(env_depth))
        except (TypeError, ValueError):
            pass
    if env_fail:
        data["failure_mode"] = env_fail

    if isinstance(raw, PredictiveAuthorityConfig):
        return raw
    if isinstance(raw, dict):
        nested = raw.get("predictive_authority") if "predictive_authority" in raw else raw
        if isinstance(nested, dict):
            for key in (
                "enabled",
                "mode",
                "max_depth",
                "max_authority_units",
                "max_nodes",
                "max_edges",
                "max_history",
                "failure_mode",
                "fail_mode",
                "audit",
            ):
                if key in nested and nested[key] is not None:
                    data[key] = nested[key]

    mode = str(data.get("mode", "off") or "off").strip().lower()
    if mode not in VALID_MODES:
        mode = "off"
    enabled = bool(data.get("enabled", False))
    if mode == "off":
        enabled = False
    elif enabled and mode == "off":
        mode = "observe"

    try:
        max_depth = max(0, int(data.get("max_depth", 3)))
    except (TypeError, ValueError):
        max_depth = 3

    max_units = data.get("max_authority_units")
    if max_units is not None:
        try:
            max_units = int(max_units)
        except (TypeError, ValueError):
            max_units = None

    explicit_fail = data.get("failure_mode") or data.get("fail_mode")
    failure_mode = _default_failure_for_mode(mode, explicit_fail if "failure_mode" in data or "fail_mode" in data else None)
    # If enforce and user didn't specify, default require_approval.
    if mode == "enforce" and "failure_mode" not in data and "fail_mode" not in data and env_fail is None:
        failure_mode = "require_approval"

    return PredictiveAuthorityConfig(
        enabled=enabled,
        mode=mode,
        max_depth=max_depth,
        max_authority_units=max_units,
        max_nodes=int(data.get("max_nodes", 2048) or 2048),
        max_edges=int(data.get("max_edges", 8192) or 8192),
        max_history=int(data.get("max_history", 256) or 256),
        failure_mode=failure_mode,
        fail_mode=str(data.get("fail_mode", "closed") or "closed"),
        audit=bool(data.get("audit", True)),
    )


DEFAULT_CONFIG = PredictiveAuthorityConfig()
