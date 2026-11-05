"""The gauntlet may not report prevention without an independent file check."""
# ruff: noqa: E402

from __future__ import annotations

import json
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
    assert record["comparison"][0]["completed"] is True
    assert record["outcomes"]["protected"]["verdict"] == "INCONCLUSIVE"


def test_mandatory_scenario_separates_sdk_os_and_same_user(monkeypatch):
    monkeypatch.delenv("VARDEN_INTEGRITY_ROOT", raising=False)
    record = runner.run_scenario("mandatory-enforcement")
    sdk = next(leg for leg in record["legs"] if leg["name"] == "sdk_guarded_write")
    raw = next(leg for leg in record["comparison"] if leg["name"] == "unguarded_write")
    os_leg = next(leg for leg in record["legs"] if leg["name"] == "os_supervisor")
    html = runner.render_html(record)
    exported = json.loads(runner.render_json(record))
    assert sdk["verdict"] == "VERIFIED_PREVENTED"
    assert sdk["control_layer"] == "sdk_guard"
    assert raw["completed"] is True
    assert raw["verdict"] == "OBSERVED_ONLY"
    assert record["assurance"]["sdk"]["verdict"] == sdk["verdict"]
    assert record["assurance"]["os_supervised"]["verdict"] == os_leg["verdict"]
    assert exported["assurance"] == record["assurance"]
    for label, key in (
        ("SDK-mediated protection", "sdk"),
        ("OS-supervised process", "os_supervised"),
        ("Unsupervised same-user process", "unsupervised_same_user"),
    ):
        line = f"{label}: {record['assurance'][key]['verdict']}"
        assert line in html
    assert record["verdict"] != "VERIFIED_PREVENTED"
    if os_leg["verdict"] == "VERIFIED_PREVENTED":
        assert os_leg["before_sha256"] == os_leg["after_sha256"]
        assert os_leg["before_sha256"]
        assert os_leg["probe"]["returncode"] not in (0, None)
        assert os_leg["completed"] is False
        assert record["assurance"]["unsupervised_same_user"]["verdict"] == "OBSERVED_ONLY"
        assert record["outcomes"]["overall"]["verdict"] == "UNSUPPORTED"
        produced = {item["name"]: item for item in record["production_entry"]["cases"]}
        direct = produced["direct_write"]
        assert direct["outcome"] == "OS_DENIED"
        assert direct["command_returncode"] == 0
        assert direct["before_sha256"] == direct["after_sha256"]
        assert produced["hardlink_write"]["outcome"] == "FAIL_CLOSED"
        assert produced["hardlink_write"]["launched"] is False
        assert produced["hardlink_write"]["before_sha256"] == produced["hardlink_write"]["after_sha256"]
        assert "Production entry" in html
        assert "direct_write: OS_DENIED" in html
        assert "Isolated supervisor authority: unsupported" in html
        exported = json.loads(runner.render_json(record))
        exported_direct = next(item for item in exported["production_entry"]["cases"] if item["name"] == "direct_write")
        assert exported_direct["outcome"] == "OS_DENIED"
        assert exported_direct["before_sha256"] == exported_direct["after_sha256"]
        adapters = record["platform_status"]["adapters"]
        assert adapters[record["system"]]["verified"] is True
        for name, cap in adapters.items():
            if name != record["system"]:
                assert cap["verified"] is False
    else:
        assert os_leg["verdict"] in {"UNSUPPORTED", "INCONCLUSIVE", "EXECUTION_ERROR"}
        assert os_leg["observation"]["executed_on_host"] is False or os_leg["verdict"] == "EXECUTION_ERROR"


def test_supervisor_resolves_from_this_repository(monkeypatch):
    monkeypatch.delenv("VARDEN_INTEGRITY_ROOT", raising=False)
    found = runner.resolve_supervisor()
    assert found["available"] is True
    assert found["source"] == "repository"
    assert (found["root"] / "varden" / "monitoring_integrity" / "platforms.py").is_file()


def test_invalid_override_does_not_fall_back_to_the_repository(monkeypatch, tmp_path):
    monkeypatch.setenv("VARDEN_INTEGRITY_ROOT", str(tmp_path))
    found = runner.resolve_supervisor()
    assert found["available"] is False
    assert found["source"] == "VARDEN_INTEGRITY_ROOT"
    probe = runner.run_os_probe()
    assert probe["executed_on_host"] is False
    assert probe["supported"] is False
    assert "was not substituted" in probe["detail"]


def test_explicit_override_is_used_when_it_contains_the_supervisor(monkeypatch):
    monkeypatch.delenv("VARDEN_INTEGRITY_ROOT", raising=False)
    repo = runner.resolve_supervisor()["root"]
    monkeypatch.setenv("VARDEN_INTEGRITY_ROOT", str(repo))
    found = runner.resolve_supervisor()
    assert found["available"] is True
    assert found["source"] == "VARDEN_INTEGRITY_ROOT"
    assert found["root"] == repo


def test_other_platforms_stay_unverified_until_that_host_runs():
    caps = runner.enforcement_capabilities(system="Darwin", sandbox_exec=True, bwrap=True, windows=False)
    assert caps["Darwin"]["verified"] is False
    assert caps["Linux"]["verified"] is False
    assert caps["Windows"]["verified"] is False
    assert caps["Darwin"]["runnable_on_this_host"] is True
    assert caps["Linux"]["runnable_on_this_host"] is False
    assert caps["Windows"]["runnable_on_this_host"] is False


def test_failed_or_unproven_containment_is_not_prevention():
    prevented = runner.interpret_contained({
        "executed_on_host": True,
        "supported": True,
        "contained_completed": False,
        "before_sha256": "abc",
        "after_sha256": "abc",
        "returncode": 1,
    })
    assert prevented["decision"] == "block"
    assert prevented["completed"] is False
    changed = runner.interpret_contained({
        "executed_on_host": True,
        "supported": True,
        "contained_completed": True,
        "before_sha256": "abc",
        "after_sha256": "def",
        "returncode": 1,
    })
    assert changed["completed"] is True
    assert runner.classify({
        "attempted": True,
        "completed": True,
        "decision": "block",
        "control_layer": "os_boundary",
        "telemetry_present": True,
        "independent_check": True,
        "supported": True,
        "executed_on_host": True,
    }) == "EXECUTION_ERROR"
    quiet_exit = runner.interpret_contained({
        "executed_on_host": True,
        "supported": True,
        "contained_completed": False,
        "before_sha256": "abc",
        "after_sha256": "abc",
        "returncode": 0,
    })
    assert quiet_exit["decision"] == ""
    caught = runner.interpret_contained({
        "executed_on_host": True,
        "supported": True,
        "contained_completed": False,
        "before_sha256": "abc",
        "after_sha256": "abc",
        "returncode": 0,
        "denial_observed": True,
    })
    assert caught["decision"] == "block"
    assert caught["completed"] is False
    missing = runner.interpret_contained({"executed_on_host": False, "supported": False})
    assert missing["supported"] is False


def test_prompt_injection_scopes_agree_in_html_and_json():
    record = runner.run_scenario("prompt-injection")
    html = runner.render_html(record)
    exported = json.loads(runner.render_json(record))
    for scope, label in (
        ("baseline", "Baseline execution"),
        ("protected", "Protected execution"),
        ("overall", "Overall scenario outcome"),
    ):
        line = f"{label}: {record['outcomes'][scope]['verdict']}"
        if scope == "protected":
            line = f"Protected execution (untrusted_export): {record['outcomes'][scope]['verdict']}"
        assert line in html
        assert exported["outcomes"][scope]["verdict"] == record["outcomes"][scope]["verdict"]
    assert record["outcomes"]["baseline"]["verdict"] == "OBSERVED_ONLY"
    assert record["outcomes"]["protected"]["verdict"] == "VERIFIED_PREVENTED"
    assert record["outcomes"]["overall"]["verdict"] == "VERIFIED_PREVENTED"
    assert "legitimate_summary" in html
    assert "VERIFIED_ALLOWED" in html
    summary = next(leg for leg in record["legs"] if leg["name"] == "legitimate_summary")
    assert summary["scope"] == "protected"
    assert summary["verdict"] == "VERIFIED_ALLOWED"


def test_every_classify_path():
    base = {
        "attempted": True,
        "completed": False,
        "decision": "block",
        "control_layer": "sdk_guard",
        "telemetry_present": True,
        "independent_check": True,
        "supported": True,
    }
    cases = [
        ({"runner_error": "boom"}, "EXECUTION_ERROR"),
        ({"supported": False}, "UNSUPPORTED"),
        ({"telemetry_present": False}, "INCONCLUSIVE"),
        ({"independent_check": False}, "INCONCLUSIVE"),
        ({"attempted": False}, "INCONCLUSIVE"),
        ({"control_layer": "none", "completed": True, "decision": ""}, "OBSERVED_ONLY"),
        ({"control_layer": "none", "completed": False, "decision": ""}, "INCONCLUSIVE"),
        ({"control_layer": "os_boundary"}, "UNSUPPORTED"),
        ({"control_layer": "os_boundary", "executed_on_host": True}, "VERIFIED_PREVENTED"),
        ({"control_layer": "os_boundary", "executed_on_host": True, "completed": True}, "EXECUTION_ERROR"),
        ({"completed": True}, "EXECUTION_ERROR"),
        ({"decision": "allow", "completed": True}, "VERIFIED_ALLOWED"),
        ({"decision": "allow", "completed": False}, "INCONCLUSIVE"),
        ({"decision": "monitor", "completed": True}, "VERIFIED_ALLOWED"),
        ({"decision": "require_approval"}, "VERIFIED_PREVENTED"),
        ({"decision": "deny"}, "VERIFIED_PREVENTED"),
        ({"control_layer": "predictive_authority", "decision": "require_approval"}, "VERIFIED_PREVENTED"),
        ({"decision": "something-else"}, "INCONCLUSIVE"),
        ({"control_layer": "custom"}, "INCONCLUSIVE"),
    ]
    for patch, expected in cases:
        observation = {**base, **patch}
        assert runner.classify(observation) == expected, patch


def test_aggregate_uses_the_weakest_verdict_inside_one_scope():
    order = [
        "VERIFIED_PREVENTED",
        "VERIFIED_ALLOWED",
        "OBSERVED_ONLY",
        "INCONCLUSIVE",
        "UNSUPPORTED",
        "EXECUTION_ERROR",
    ]
    for verdict in order:
        assert runner.aggregate([verdict]) == verdict
    assert runner.aggregate([]) == "INCONCLUSIVE"
    assert runner.aggregate(["VERIFIED_PREVENTED", "VERIFIED_ALLOWED"]) == "VERIFIED_ALLOWED"
    assert runner.aggregate(["VERIFIED_ALLOWED", "EXECUTION_ERROR"]) == "EXECUTION_ERROR"
    assert runner.aggregate(["UNSUPPORTED", "OBSERVED_ONLY"]) == "UNSUPPORTED"


def test_contradictory_prevention_is_not_success():
    record = {
        "scenario_id": "prompt-injection",
        "legs": [{
            "name": "untrusted_export",
            "scope": "protected",
            "verdict": "VERIFIED_ALLOWED",
            "completed": True,
            "control_layer": "sdk_guard",
            "observation": {"independent_check": True},
        }],
        "comparison": [],
        "outcomes": runner.build_outcomes(
            baseline_legs=[{"name": "baseline", "verdict": "OBSERVED_ONLY"}],
            protected_legs=[{"name": "untrusted_export", "verdict": "VERIFIED_ALLOWED"}],
            claim_leg="untrusted_export",
            basis="protected",
            overall_verdict="VERIFIED_PREVENTED",
        ),
    }
    sealed = runner.seal(record)
    assert sealed["verdict"] == "INCONCLUSIVE"
    assert sealed["outcomes"]["overall"]["verdict"] == "INCONCLUSIVE"


def test_missing_outcomes_fail_closed():
    sealed = runner.seal({"legs": [], "comparison": []})
    assert sealed["verdict"] == "INCONCLUSIVE"


def test_sdk_prevention_cannot_become_an_os_claim():
    record = runner.run_scenario("prompt-injection")
    assert record["enforcement_mode"] == "sdk_guard"
    assert all(leg["control_layer"] != "os_boundary" for leg in record["legs"])
    forged = json.loads(runner.render_json(record))
    forged["outcomes"]["overall"]["verdict"] = "VERIFIED_PREVENTED"
    forged["legs"] = [{
        "name": "os_supervisor",
        "verdict": "VERIFIED_PREVENTED",
        "completed": False,
        "control_layer": "os_boundary",
        "before_sha256": None,
        "after_sha256": None,
        "observation": {"independent_check": True, "executed_on_host": False},
    }]
    forged["outcomes"]["protected"]["legs"] = ["os_supervisor"]
    forged["outcomes"]["overall"]["claim_leg"] = "os_supervisor"
    sealed = runner.seal(forged)
    assert sealed["verdict"] == "UNSUPPORTED"


def test_predictive_graph_comes_from_the_engine_and_is_not_the_baseline():
    record = runner.run_scenario("predictive-authority")
    graph = record["predictive"]["graph"]
    assert graph["present"] is True
    assert graph["trace_id"] == "gauntlet-pa-on"
    assert record["outcomes"]["baseline"]["verdict"] == "VERIFIED_ALLOWED"
    assert record["outcomes"]["protected"]["claim_leg"].endswith("external_post")
    assert record["outcomes"]["baseline"]["verdict"] != record["outcomes"]["protected"]["verdict"] or record["outcomes"]["protected"]["verdict"] != "VERIFIED_PREVENTED"
    html = runner.render_html(record)
    claim = record["outcomes"]["protected"]["claim_leg"]
    assert f"Baseline execution: {record['outcomes']['baseline']['verdict']}" in html
    assert f"Protected execution ({claim}): {record['outcomes']['protected']['verdict']}" in html
    assert record["predictive"]["intervention"]["decision"] in {"block", "require_approval", "allow", "monitor"}


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
