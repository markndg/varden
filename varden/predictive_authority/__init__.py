"""Varden Predictive Authority.

Evaluates not only whether an action is allowed, but what authority and
sensitive resources become *reachable* if that action is permitted.

This is deterministic reachability analysis over evidence-backed authority
state — not a prediction of future agent behaviour, and not an LLM risk
classifier. Disabled by default; observe mode never weakens existing Varden
decisions; enforce mode may only strengthen them.
"""

from __future__ import annotations

from .config import PredictiveAuthorityConfig, parse_predictive_config
from .deployment import pa_deployment_status
from .engine import PredictiveAuthorityEngine, apply_predictive_authority
from .registry import get_authority_registry, reset_authority_registry, configure_authority_registry

__all__ = [
    "PredictiveAuthorityConfig",
    "PredictiveAuthorityEngine",
    "apply_predictive_authority",
    "configure_authority_registry",
    "get_authority_registry",
    "pa_deployment_status",
    "parse_predictive_config",
    "reset_authority_registry",
]
