"""Demo + integration smoke for Predictive Authority."""

from __future__ import annotations

from varden.predictive_authority.demo import run_predictive_demo


def test_predictive_authority_demo_escalates_final_step(capsys):
    rc = run_predictive_demo(json_out=False)
    assert rc == 0
    out = capsys.readouterr().out
    assert "WITHOUT predictive reasoning" in out
    assert "WITH Predictive Authority" in out
    assert "REQUIRE_APPROVAL" in out or "BLOCK" in out
