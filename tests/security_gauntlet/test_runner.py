"""The gauntlet may not report prevention without an independent file check."""
# ruff: noqa: E402

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demos.security_gauntlet_loader import load_runner

runner = load_runner()


def test_missing_evidence_cannot_be_verified_prevented():
    verdict = runner.classify({
        "attempted": True,
        "completed": False,
        "decision": "block",
        "control_layer": "sdk_guard",
        "telemetry_present": True,
        "independent_check": False,
        "supported": True,
    })
    assert verdict == "INCONCLUSIVE"


def test_os_claim_is_unsupported_on_this_tree():
    verdict = runner.classify({
        "attempted": True,
        "completed": False,
        "decision": "block",
        "control_layer": "os_boundary",
        "telemetry_present": True,
        "independent_check": True,
        "supported": True,
    })
    assert verdict == "UNSUPPORTED"


def test_decision_without_a_stopped_side_effect_is_not_prevention():
    verdict = runner.classify({
        "attempted": True,
        "completed": True,
        "decision": "block",
        "control_layer": "sdk_guard",
        "telemetry_present": True,
        "independent_check": True,
        "supported": True,
    })
    assert verdict == "EXECUTION_ERROR"


def test_prompt_injection_prevents_only_the_guarded_export():
    record = runner.run_scenario("prompt-injection")
    export = next(leg for leg in record["legs"] if leg["name"] == "untrusted_export")
    summary = next(leg for leg in record["legs"] if leg["name"] == "legitimate_summary")
    baseline = record["comparison"][0]
    assert export["verdict"] == "VERIFIED_PREVENTED"
    assert export["completed"] is False
    assert export["after_sha256"] is None
    assert summary["verdict"] == "VERIFIED_ALLOWED"
    assert summary["completed"] is True
    assert baseline["completed"] is True
    assert baseline["control_layer"] == "none"
    assert record["verdict"] == "VERIFIED_PREVENTED"
    assert "http" not in record["enforcement_mode"]


def test_coverage_gap_does_not_report_prevention():
    record = runner.run_scenario("coverage-gap")
    assert record["verdict"] != "VERIFIED_PREVENTED"
    assert record["verdict"] == "UNSUPPORTED"
    assert record["side_effect_completed"] is True
    assert record["legs"][0]["completed"] is True


def test_mandatory_scenario_separates_sdk_and_os():
    record = runner.run_scenario("mandatory-enforcement")
    sdk = next(leg for leg in record["legs"] if leg["name"] == "sdk_guarded_write")
    raw = next(leg for leg in record["legs"] if leg["name"] == "unguarded_write")
    os_leg = next(leg for leg in record["legs"] if leg["name"] == "os_supervisor")
    assert sdk["verdict"] == "VERIFIED_PREVENTED"
    assert raw["completed"] is True
    assert raw["verdict"] == "OBSERVED_ONLY"
    assert os_leg["verdict"] == "UNSUPPORTED"
    assert record["verdict"] == "UNSUPPORTED"


def test_evidence_export_matches_the_run_and_does_not_upgrade_it():
    record = runner.run_scenario("auditable-evidence")
    html = runner.render_html(record)
    assert record["run_id"] in html
    assert record["verdict"] in html
    assert record["commit"]
    assert record["scenario_id"] == "auditable-evidence"
    assert "Exporting this record does not make the underlying verdict stronger." in record["coverage_limitations"]


def test_predictive_run_records_both_modes():
    record = runner.run_scenario("predictive-authority")
    assert record["predictive"]["default_product_state"] == "off"
    assert record["predictive"]["with_pa_external_post"] == record["verdict"]
    assert record["verdict"] in {
        "VERIFIED_PREVENTED",
        "VERIFIED_ALLOWED",
        "OBSERVED_ONLY",
        "INCONCLUSIVE",
        "UNSUPPORTED",
        "EXECUTION_ERROR",
    }
    post = next(leg for leg in record["legs"] if leg["name"].endswith("external_post"))
    if post["verdict"] == "VERIFIED_PREVENTED":
        assert post["completed"] is False
        assert post["decision"] in {"block", "require_approval"}
