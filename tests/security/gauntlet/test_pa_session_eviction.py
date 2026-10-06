"""Gauntlet Phase 2 — session eviction vs retained authority.

Security invariant: loss of monitoring state must not silently confer greater
effective authority.

BEFORE (unfixed 1.0.1): Scenario A prior steps accumulate untrusted→credential
authority. A subsequent ``shell`` tool_call escalates to require_approval. After
LRU-evicting that session and resuming the same session key, the same shell
call is analysed from a fresh state and returns allow — an exploitable weaken.

AFTER (continuity fail-safe): recreating a session key that was evicted while it
held accumulated authority marks continuity_broken; enforce mode applies the
configured failure_mode (default require_approval) so the shell hop cannot
regain a weaker effective decision.
"""

from __future__ import annotations

import time

import pytest

from varden.models import Action
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import AuthorityRegistry
from varden.predictive_authority.state import AuthorityTransitionRecord

from tests.predictive_authority.helpers import allow_decision, untrusted_meta

_PRIOR = [
    Action(
        type="tool_call",
        tool="ingest_issue",
        metadata=untrusted_meta("github.issue"),
        classifiers={"provenance_untrusted": True},
        trace_id="gauntlet-evict",
        tenant_id="t",
    ),
    Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata=untrusted_meta("github.issue"),
        trace_id="gauntlet-evict",
        tenant_id="t",
    ),
]


def _shell_hop(trace_id: str = "gauntlet-evict") -> Action:
    # State-dependent: allow on a fresh session; require_approval when prior
    # untrusted+credential authority is still in the live graph.
    return Action(
        type="tool_call",
        tool="shell",
        args={"command": "env"},
        trace_id=trace_id,
        tenant_id="t",
    )


def _force_lru_evict_target(reg: AuthorityRegistry, target_key: str) -> None:
    """Fill the registry with other accumulated-authority sessions until target is gone."""
    assert reg.get(target_key) is not None
    i = 0
    while reg.get(target_key) is not None and i < 500:
        key = f"t:noise-accum-{i}"
        state = reg.get_or_create(key, PredictiveAuthorityConfig(enabled=True, mode="enforce"))
        state.history.append(
            AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="noise",
                added_capabilities=["noise"],
                added_resources=[],
                added_sinks=[],
            )
        )
        i += 1
    assert reg.get(target_key) is None, "failed to force-evict target under LRU pressure"


def test_gauntlet_BEFORE_evidence_shell_weakens_after_eviction_without_continuity():
    """Characterization: without continuity tombstones, eviction weakens shell.

    This test deliberately uses a registry that does not record authority
    tombstones (pre-fix behaviour) so BEFORE evidence remains reproducible
    even after the production fix lands.
    """
    reg = AuthorityRegistry(max_sessions=8, idle_seconds=0)
    # Simulate pre-fix drop: clear tombstone bookkeeping if present.
    if hasattr(reg, "_authority_tombstones"):
        reg._record_authority_tombstone = lambda key, reason: None  # type: ignore[method-assign]

    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    engine = PredictiveAuthorityEngine(cfg, registry=reg)
    for action in _PRIOR:
        engine.evaluate(action, allow_decision(), policy={})

    key = reg.session_key(tenant_id="t", trace_id="gauntlet-evict")
    before, before_res = engine.evaluate(_shell_hop(), allow_decision(), policy={})
    assert decision_rank(before.action) >= decision_rank("require_approval"), (
        f"setup failed: expected escalation with live state, got {before.action!r}"
    )
    assert before_res.findings, "setup failed: expected hazardous findings with live state"

    _force_lru_evict_target(reg, key)
    after, after_res = engine.evaluate(_shell_hop(), allow_decision(), policy={})

    # BEFORE evidence: eviction conferred a weaker effective decision.
    assert decision_rank(after.action) < decision_rank(before.action), (
        "expected pre-fix weakening: "
        f"before={before.action!r} after={after.action!r} findings={len(after_res.findings)}"
    )
    assert after.action == "allow"


def test_gauntlet_AFTER_eviction_must_not_weaken_enforce_decision():
    """G-PA-EVICT-01: eviction of accumulated PA state must not allow a weaker hop."""
    reg = AuthorityRegistry(max_sessions=8, idle_seconds=0)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    engine = PredictiveAuthorityEngine(cfg, registry=reg)

    for action in _PRIOR:
        engine.evaluate(action, allow_decision(), policy={})

    key = reg.session_key(tenant_id="t", trace_id="gauntlet-evict")
    before, before_res = engine.evaluate(_shell_hop(), allow_decision(), policy={})
    assert decision_rank(before.action) >= decision_rank("require_approval")
    assert before_res.findings
    assert AuthorityRegistry._has_accumulated_authority(reg.get(key))

    _force_lru_evict_target(reg, key)
    assert reg.get(key) is None

    after, after_res = engine.evaluate(_shell_hop(), allow_decision(), policy={})
    state = reg.get(key)
    assert state is not None
    assert getattr(state, "continuity_broken", False) is True
    assert decision_rank(after.action) >= decision_rank(before.action), (
        f"AFTER eviction, shell decision={after.action!r} weakened vs pre-eviction "
        f"{before.action!r}; continuity loss conferred greater effective authority. "
        f"findings={len(after_res.findings)} status={after_res.analysis_status} "
        f"incomplete={after_res.analysis_incomplete_reason}"
    )


def test_gauntlet_idle_expiry_of_accumulated_authority_sets_continuity():
    """Idle-evicting an accumulated session must also trip continuity on resume."""
    reg = AuthorityRegistry(max_sessions=3, idle_seconds=0.05)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    engine = PredictiveAuthorityEngine(cfg, registry=reg)
    for action in _PRIOR:
        engine.evaluate(action, allow_decision(), policy={})
    key = reg.session_key(tenant_id="t", trace_id="gauntlet-evict")
    reg._last_access[key] = time.monotonic() - 10.0
    # Force make_room via new sessions.
    for i in range(5):
        reg.get_or_create(f"t:idle-fill-{i}", cfg)
    assert reg.get(key) is None
    assert key in getattr(reg, "_authority_tombstones", {})

    after, _ = engine.evaluate(_shell_hop(), allow_decision(), policy={})
    assert reg.get(key).continuity_broken is True
    assert decision_rank(after.action) >= decision_rank("require_approval")


def test_gauntlet_eviction_prefers_empty_before_valuable_still_holds():
    """Negative control: empty noise must not displace a valuable session first."""
    reg = AuthorityRegistry(max_sessions=5, idle_seconds=0)
    valuable = reg.get_or_create("t:valuable", PredictiveAuthorityConfig(enabled=True, mode="observe"))
    valuable.history.append(
        AuthorityTransitionRecord(
            timestamp=time.time(),
            action_summary="cred",
            added_capabilities=["aws"],
            added_resources=["~/.aws/credentials"],
            added_sinks=[],
        )
    )
    for i in range(30):
        reg.get_or_create(f"t:empty-{i}", PredictiveAuthorityConfig(enabled=True, mode="observe"))
    assert reg.get("t:valuable") is valuable


def test_gauntlet_benign_fresh_session_shell_still_allows():
    """Negative control: brand-new session without continuity break stays usable."""
    reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=3)
    engine = PredictiveAuthorityEngine(cfg, registry=reg)
    final, result = engine.evaluate(_shell_hop("benign-1"), allow_decision(), policy={})
    assert getattr(reg.get("t:benign-1"), "continuity_broken", False) is False
    assert final.action == "allow"
    assert result.analysis_incomplete_reason != "SESSION_CONTINUITY_BROKEN"


def test_gauntlet_observe_mode_reports_continuity_without_blocking():
    """Observe mode must surface continuity loss without claiming enforcement."""
    reg = AuthorityRegistry(max_sessions=8, idle_seconds=0)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="observe", max_depth=4)
    engine = PredictiveAuthorityEngine(cfg, registry=reg)
    for action in _PRIOR:
        engine.evaluate(action, allow_decision(), policy={})
    key = reg.session_key(tenant_id="t", trace_id="gauntlet-evict")
    _force_lru_evict_target(reg, key)
    final, result = engine.evaluate(_shell_hop(), allow_decision(), policy={})
    assert reg.get(key).continuity_broken is True
    assert final.action == "allow"  # observe does not strengthen
    assert result.analysis_incomplete_reason == "SESSION_CONTINUITY_BROKEN"
    assert result.to_metadata().get("safe_conclusion") is False
