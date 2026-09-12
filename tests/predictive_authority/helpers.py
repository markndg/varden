"""Helpers shared by Predictive Authority tests."""

from __future__ import annotations

from varden.models import Action, Decision
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.registry import reset_authority_registry


def fresh_engine(mode: str = "enforce", max_depth: int = 4, **kwargs) -> PredictiveAuthorityEngine:
    reset_authority_registry()
    cfg = PredictiveAuthorityConfig(enabled=True, mode=mode, max_depth=max_depth, **kwargs)
    return PredictiveAuthorityEngine(cfg)


def allow_decision() -> Decision:
    return Decision(action="allow", reason="no matching rule", effective_action="allow")


def untrusted_meta(source_id: str = "issue-1", **extra) -> dict:
    meta = {
        "provenance_sources": [
            {"source_id": source_id, "type": "chat_message", "trust_level": "untrusted", **extra}
        ]
    }
    return meta


def run_step(engine: PredictiveAuthorityEngine, action: Action, existing: Decision | None = None):
    return engine.evaluate(action, existing or allow_decision(), policy={})
