"""Gauntlet continuity gate — tombstone exhaustion, restart, undeclared topology."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from varden.models import Action
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.deployment import pa_deployment_status
from varden.predictive_authority.engine import PredictiveAuthorityEngine
from varden.predictive_authority.policy import decision_rank
from varden.predictive_authority.registry import AuthorityRegistry
from varden.predictive_authority.state import AuthorityTransitionRecord

from tests.predictive_authority.helpers import allow_decision, untrusted_meta

_SINGLE = {"VARDEN_PA_DEPLOYMENT": "single_worker"}


def _prior(trace: str) -> list[Action]:
    return [
        Action(
            type="tool_call",
            tool="ingest_issue",
            metadata=untrusted_meta("github.issue"),
            classifiers={"provenance_untrusted": True},
            trace_id=trace,
            tenant_id="t",
        ),
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta("github.issue"),
            trace_id=trace,
            tenant_id="t",
        ),
    ]


def _shell(trace: str) -> Action:
    return Action(type="tool_call", tool="shell", args={"command": "env"}, trace_id=trace, tenant_id="t")


def _flood_tombstones(reg: AuthorityRegistry, cfg: PredictiveAuthorityConfig, n: int = 40) -> None:
    for j in range(n):
        k = f"t:flood-{j}"
        st = reg.get_or_create(k, cfg)
        st.history.append(
            AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="f",
                added_capabilities=["x"],
                added_resources=[],
                added_sinks=[],
            )
        )
        for m in range(reg.max_sessions + 2):
            st2 = reg.get_or_create(f"t:flood-{j}-n{m}", cfg)
            st2.history.append(
                AuthorityTransitionRecord(
                    timestamp=time.time(),
                    action_summary="f",
                    added_capabilities=["x"],
                    added_resources=[],
                    added_sinks=[],
                )
            )


def test_gauntlet_BEFORE_tombstone_exhaustion_without_degradation_flag():
    """Characterization: forgetting a tombstone without process degradation → allow."""
    reg = AuthorityRegistry(max_sessions=4, idle_seconds=0)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    # Disable degradation bookkeeping to reproduce pre-fix bypass.
    orig = reg._record_authority_tombstone

    def _tombstone_no_degrade(key: str, reason: str) -> None:
        reg._authority_tombstones.pop(key, None)
        reg._authority_tombstones[key] = reason
        while len(reg._authority_tombstones) > reg._tombstone_cap():
            reg._authority_tombstones.popitem(last=False)
            reg._tombstone_drops += 1
            # intentionally do NOT set continuity_degraded

    reg._record_authority_tombstone = _tombstone_no_degrade  # type: ignore[method-assign]
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    for action in _prior("victim"):
        eng.evaluate(action, allow_decision(), policy={})
    key = reg.session_key(tenant_id="t", trace_id="victim")
    before, _ = eng.evaluate(_shell("victim"), allow_decision(), policy={})
    assert decision_rank(before.action) >= decision_rank("require_approval")

    # Evict victim
    i = 0
    while reg.get(key) is not None and i < 50:
        st = reg.get_or_create(f"t:noise-{i}", cfg)
        st.history.append(
            AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="n",
                added_capabilities=["x"],
                added_resources=[],
                added_sinks=[],
            )
        )
        i += 1
    assert key in reg._authority_tombstones
    _flood_tombstones(reg, cfg)
    assert key not in reg._authority_tombstones
    assert reg.stats()["tombstone_drops"] > 0
    assert reg.continuity_degraded() is False  # pre-fix path

    after, res = eng.evaluate(_shell("victim"), allow_decision(), policy={})
    assert after.action == "allow"
    assert decision_rank(after.action) < decision_rank(before.action)
    reg._record_authority_tombstone = orig  # type: ignore[method-assign]


def test_gauntlet_AFTER_tombstone_exhaustion_degrades_process_failsafe():
    """G-PA-EVICT-02: forgotten tombstones must not restore trust."""
    reg = AuthorityRegistry(max_sessions=4, idle_seconds=0)
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    eng = PredictiveAuthorityEngine(cfg, registry=reg, env=_SINGLE)
    for action in _prior("victim"):
        eng.evaluate(action, allow_decision(), policy={})
    key = reg.session_key(tenant_id="t", trace_id="victim")
    before, _ = eng.evaluate(_shell("victim"), allow_decision(), policy={})
    assert decision_rank(before.action) >= decision_rank("require_approval")

    i = 0
    while reg.get(key) is not None and i < 50:
        st = reg.get_or_create(f"t:noise-{i}", cfg)
        st.history.append(
            AuthorityTransitionRecord(
                timestamp=time.time(),
                action_summary="n",
                added_capabilities=["x"],
                added_resources=[],
                added_sinks=[],
            )
        )
        i += 1
    _flood_tombstones(reg, cfg)
    assert reg.continuity_degraded() is True
    assert reg.stats()["tombstone_drops"] > 0

    after, res = eng.evaluate(_shell("victim"), allow_decision(), policy={})
    assert res.analysis_incomplete_reason == "TOMBSTONE_HISTORY_INCOMPLETE"
    assert res.to_metadata()["safe_conclusion"] is False
    assert decision_rank(after.action) >= decision_rank("require_approval")
    # Even a brand-new session identity fails safe once degraded.
    fresh, freshr = eng.evaluate(_shell("brand-new"), allow_decision(), policy={})
    assert freshr.analysis_incomplete_reason == "TOMBSTONE_HISTORY_INCOMPLETE"
    assert decision_rank(fresh.action) >= decision_rank("require_approval")


def test_gauntlet_impossibility_note_new_vs_forgotten(monkeypatch):
    """Bounded process-local state cannot tell new keys from forgotten tombstones."""
    status = pa_deployment_status(enforce=True, env=_SINGLE)
    assert status["cross_restart_continuity_verified"] is False
    assert status["continuity_scope"] == "process_lifetime_only"


def test_gauntlet_undeclared_deployment_failsafe(monkeypatch):
    """G-PA-MULTI-02: unknown topology must not claim complete enforce history."""
    monkeypatch.delenv("VARDEN_PA_DEPLOYMENT", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("VARDEN_WORKERS", raising=False)
    monkeypatch.delenv("VARDEN_UVICORN_WORKERS", raising=False)
    monkeypatch.delenv("VARDEN_PA_ALLOW_MULTI_WORKER", raising=False)

    assert pa_deployment_status(enforce=True, env={})["reason"] == "DEPLOYMENT_UNDECLARED"
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    eng = PredictiveAuthorityEngine(cfg, registry=AuthorityRegistry(max_sessions=50, idle_seconds=0), env={})
    final, res = eng.evaluate(_shell("undeclared"), allow_decision(), policy={})
    assert res.analysis_incomplete_reason == "DEPLOYMENT_UNDECLARED"
    assert decision_rank(final.action) >= decision_rank("require_approval")
    assert res.to_metadata()["safe_conclusion"] is False


def test_gauntlet_declared_single_worker_allows_benign_shell():
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
    eng = PredictiveAuthorityEngine(
        cfg,
        registry=AuthorityRegistry(max_sessions=50, idle_seconds=0),
        env=_SINGLE,
    )
    final, res = eng.evaluate(_shell("ok"), allow_decision(), policy={})
    assert res.analysis_incomplete_reason is None
    assert final.action == "allow"


def test_gauntlet_split_chain_across_declared_single_worker_processes(tmp_path: Path):
    """Two OS processes each declaring single_worker still miss cross-process chains.

    This is an architectural limit of in-process state — not fixed by env detection.
    Evidence: worker B allows shell that same-process would escalate.
    """
    script = tmp_path / "split_workers.py"
    script.write_text(
        textwrap.dedent(
            """
            import json, sys
            from varden.models import Action
            from varden.predictive_authority.config import PredictiveAuthorityConfig
            from varden.predictive_authority.engine import PredictiveAuthorityEngine
            from varden.predictive_authority.registry import AuthorityRegistry
            from tests.predictive_authority.helpers import allow_decision, untrusted_meta

            role = sys.argv[1]
            env = {"VARDEN_PA_DEPLOYMENT": "single_worker"}
            cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
            reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
            eng = PredictiveAuthorityEngine(cfg, registry=reg, env=env)
            tid = "split-proc"
            if role == "a":
                for a in [
                    Action(type="tool_call", tool="ingest", metadata=untrusted_meta("x"),
                           classifiers={"provenance_untrusted": True}, trace_id=tid, tenant_id="t"),
                    Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]},
                           metadata=untrusted_meta("x"), trace_id=tid, tenant_id="t"),
                ]:
                    eng.evaluate(a, allow_decision(), policy={})
                print(json.dumps({"role": "a", "ok": True}))
            else:
                final, res = eng.evaluate(
                    Action(type="tool_call", tool="shell", args={"command": "env"},
                           trace_id=tid, tenant_id="t"),
                    allow_decision(), policy={})
                print(json.dumps({
                    "role": "b",
                    "decision": final.action,
                    "incomplete": res.analysis_incomplete_reason,
                    "safe_conclusion": res.to_metadata().get("safe_conclusion"),
                }))
            """
        ),
        encoding="utf-8",
    )
    env = {**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": str(Path.cwd())}
    env["VARDEN_PA_DEPLOYMENT"] = "single_worker"
    a = subprocess.run([sys.executable, str(script), "a"], capture_output=True, text=True, env=env, cwd=str(Path.cwd()))
    assert a.returncode == 0, a.stderr
    b = subprocess.run([sys.executable, str(script), "b"], capture_output=True, text=True, env=env, cwd=str(Path.cwd()))
    assert b.returncode == 0, b.stderr
    payload = json.loads(b.stdout.strip().splitlines()[-1])
    # Worker B has empty local history → allow; cannot see worker A's authority.
    assert payload["decision"] == "allow"
    assert payload["safe_conclusion"] is True or payload["incomplete"] is None


def test_gauntlet_process_restart_loses_continuity(tmp_path: Path):
    """G-PA-RESTART-01: restart + same trace identity can allow previously escalated hop.

    Cross-restart continuity is unsupported with process-local state. Claims must
    not report cross_restart_continuity_verified.
    """
    script = tmp_path / "restart_continuity.py"
    script.write_text(
        textwrap.dedent(
            """
            import json, sys
            from varden.models import Action
            from varden.predictive_authority.config import PredictiveAuthorityConfig
            from varden.predictive_authority.deployment import pa_deployment_status
            from varden.predictive_authority.engine import PredictiveAuthorityEngine
            from varden.predictive_authority.policy import decision_rank
            from varden.predictive_authority.registry import AuthorityRegistry
            from tests.predictive_authority.helpers import allow_decision, untrusted_meta

            phase = sys.argv[1]
            env = {"VARDEN_PA_DEPLOYMENT": "single_worker"}
            cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce", max_depth=4)
            reg = AuthorityRegistry(max_sessions=100, idle_seconds=0)
            eng = PredictiveAuthorityEngine(cfg, registry=reg, env=env)
            tid = "restart-1"
            if phase == "before":
                for a in [
                    Action(type="tool_call", tool="ingest", metadata=untrusted_meta("x"),
                           classifiers={"provenance_untrusted": True}, trace_id=tid, tenant_id="t"),
                    Action(type="filesystem_read", tool="open", args={"args": ["~/.aws/credentials", "r"]},
                           metadata=untrusted_meta("x"), trace_id=tid, tenant_id="t"),
                ]:
                    eng.evaluate(a, allow_decision(), policy={})
                final, res = eng.evaluate(
                    Action(type="tool_call", tool="shell", args={"command": "env"},
                           trace_id=tid, tenant_id="t"),
                    allow_decision(), policy={})
                print(json.dumps({
                    "decision": final.action,
                    "rank": decision_rank(final.action),
                    "deployment": pa_deployment_status(enforce=True, env=env),
                }))
            else:
                final, res = eng.evaluate(
                    Action(type="tool_call", tool="shell", args={"command": "env"},
                           trace_id=tid, tenant_id="t"),
                    allow_decision(), policy={})
                print(json.dumps({
                    "decision": final.action,
                    "rank": decision_rank(final.action),
                    "incomplete": res.analysis_incomplete_reason,
                    "deployment": pa_deployment_status(enforce=True, env=env),
                    "safe_conclusion": res.to_metadata().get("safe_conclusion"),
                }))
            """
        ),
        encoding="utf-8",
    )
    env = {**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": str(Path.cwd())}
    env["VARDEN_PA_DEPLOYMENT"] = "single_worker"
    before = subprocess.run(
        [sys.executable, str(script), "before"], capture_output=True, text=True, env=env, cwd=str(Path.cwd())
    )
    assert before.returncode == 0, before.stderr
    before_payload = json.loads(before.stdout.strip().splitlines()[-1])
    assert before_payload["rank"] >= decision_rank("require_approval")
    assert before_payload["deployment"]["cross_restart_continuity_verified"] is False

    after = subprocess.run(
        [sys.executable, str(script), "after"], capture_output=True, text=True, env=env, cwd=str(Path.cwd())
    )
    assert after.returncode == 0, after.stderr
    after_payload = json.loads(after.stdout.strip().splitlines()[-1])
    # Fresh process without ContinuityStore: prior authority gone → weaker decision.
    # With ContinuityStore bound (create_app / configure_authority_registry), the
    # same reintroduction fails safe — see test_pa_durable_continuity.py.
    assert after_payload["decision"] == "allow"
    assert after_payload["rank"] < before_payload["rank"]
    assert after_payload["deployment"]["cross_restart_continuity_verified"] is False
    assert after_payload["deployment"]["continuity_scope"] == "process_lifetime_only"
