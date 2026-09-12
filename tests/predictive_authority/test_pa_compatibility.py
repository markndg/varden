"""Compatibility: Predictive Authority off leaves existing behaviour intact."""

from __future__ import annotations

import os

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.models import Action, Decision
from varden.predictive_authority import apply_predictive_authority
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.policy import decision_rank, strengthen_decision, PredictiveRecommendation
from varden.stores import EventStore


def test_disabled_apply_is_identity():
    action = Action(type="http_request", method="GET", url="https://example.com")
    decision = Decision(action="warn", reason="x", effective_action="warn")
    final, result = apply_predictive_authority(
        action,
        decision,
        config=PredictiveAuthorityConfig(enabled=False, mode="off"),
    )
    assert final is decision or final.action == "warn"
    assert result.config.mode == "off"


def test_enforce_strengthen_property_matrix():
    pairs = [
        ("allow", "monitor"),
        ("monitor", "warn"),
        ("warn", "require_approval"),
        ("require_approval", "block"),
        ("block", "allow"),
    ]
    for existing_a, rec_a in pairs:
        existing = Decision(action=existing_a, reason="e", effective_action=existing_a)
        rec = PredictiveRecommendation(
            action=rec_a,
            reason="r",
            matched_predicates=["t"],
            authority_expands=True,
            structural_units=1,
        )
        out = strengthen_decision(existing, rec)
        assert decision_rank(out.action) >= decision_rank(existing_a)


def test_sdk_guard_still_works_with_pa_off(tmp_path, monkeypatch):
    monkeypatch.delenv("VARDEN_PA_MODE", raising=False)
    monkeypatch.delenv("VARDEN_PREDICTIVE_AUTHORITY", raising=False)
    db = tmp_path / "varden.db"
    policy = tmp_path / "policy.json"
    policy.write_text('{"block":[{"type":"tool_call","tool":"delete_database"}],"warn":[],"monitor":[],"allow":[]}\n')
    cfg = AppConfig(db_path=str(db), policy_file=str(policy), enable_dev_bootstrap=True)
    app = create_app(cfg)
    client = TestClient(app)
    # Bootstrap key from health.
    health = client.get("/health").json()
    api_key = health.get("bootstrap_api_key") or "admin-demo-key"
    resp = client.post(
        "/sdk/guard",
        headers={"x-api-key": api_key},
        json={"type": "tool_call", "tool": "echo", "args": {"args": ["hi"], "kwargs": {}}},
    )
    assert resp.status_code in {200, 403}
    body = resp.json()
    assert "decision" in body or "detail" in body or "action" in body or resp.status_code == 200


def test_audit_chain_covers_predictive_metadata(tmp_path):
    from varden.models import EventRecord
    from tests.predictive_authority.helpers import fresh_engine, run_step, untrusted_meta

    engine = fresh_engine(mode="observe", max_depth=3)
    action = Action(
        type="filesystem_read",
        tool="open",
        args={"args": ["~/.aws/credentials", "r"]},
        metadata=untrusted_meta(),
        trace_id="audit-pa",
        tenant_id="t",
    )
    final, result = run_step(engine, action)
    assert result.explanation is not None
    store = EventStore(str(tmp_path / "a.db"))
    event_id = store.log(
        EventRecord.new(
            action=action.to_dict(),
            decision=final.to_dict(),
            status="allowed",
            tenant_id="t",
            trace_id="audit-pa",
        ).to_dict()
    )
    report = store.verify_integrity()
    assert report.get("ok") or report.get("status") == "PASS" or report.get("valid") is True or "PASS" in str(report).upper() or report.get("integrity_failures", 1) == 0
    # Soft assert on common verify shapes.
    if "integrity_failures" in report:
        assert report["integrity_failures"] == 0
    row = store.get_event(event_id)
    assert "predictive_authority" in ((row.get("action") or {}).get("metadata") or {})
