from __future__ import annotations

import json

from varden.monitoring_integrity.watchdog import evaluate_observation


def _base(**overrides):
    observation = {
        "process_alive": True,
        "heartbeat_age_s": 1,
        "heartbeat_limit_s": 30,
        "config_hashes": {"monitor.config": {"expected": "abc", "observed": "abc"}},
        "attestation_age_s": 1,
        "attestation_limit_s": 300,
        "audit_head": {"expected": "h", "observed": "h"},
        "control_plane_reachable": True,
    }
    observation.update(overrides)
    return observation


def test_matching_snapshot_is_ok_and_not_an_os_claim():
    verdict = evaluate_observation(_base())
    assert verdict["kind"] == "ok"
    assert verdict["confirmed_sabotage"] is False
    assert verdict["os_isolation"] is False
    assert verdict["independent_of_agent_process"] is True


def test_hash_mismatch_is_confirmed_tampering():
    verdict = evaluate_observation(_base(config_hashes={"monitor.config": {"expected": "abc", "observed": "def"}}))
    assert verdict["kind"] == "confirmed_tampering"
    assert verdict["confirmed_sabotage"] is True


def test_dead_process_is_not_called_sabotage():
    verdict = evaluate_observation(_base(process_alive=False, heartbeat_age_s=None))
    assert verdict["kind"] == "process_failure"
    assert verdict["confirmed_sabotage"] is False


def test_missed_heartbeat_with_unknown_process_is_not_sabotage():
    verdict = evaluate_observation(_base(process_alive=None, heartbeat_age_s=None, control_plane_reachable=None))
    assert verdict["kind"] == "heartbeat_missed"
    assert verdict["confirmed_sabotage"] is False
    assert verdict["heartbeat_is_not_proof_of_sabotage"] is True


def test_unreachable_control_plane_is_connectivity_loss():
    verdict = evaluate_observation(_base(process_alive=None, control_plane_reachable=False, heartbeat_age_s=1))
    assert verdict["kind"] == "connectivity_loss"
    assert verdict["confirmed_sabotage"] is False


def test_live_process_with_stale_heartbeat_is_degradation():
    verdict = evaluate_observation(_base(process_alive=True, heartbeat_age_s=500))
    assert verdict["kind"] == "monitoring_degradation"
    assert verdict["confirmed_sabotage"] is False


def test_manifest_file_round_trip(tmp_path):
    target = tmp_path / "monitoring.json"
    target.write_text("{}", encoding="utf-8")
    from varden.monitoring_integrity.watchdog import collect_observation

    digest = __import__("hashlib").sha256(target.read_bytes()).hexdigest()
    observation = collect_observation({"files": {"monitor.config": {"path": str(target), "sha256": digest}}, "pid": None})
    verdict = evaluate_observation(observation)
    assert verdict["kind"] == "ok"
    observation = collect_observation({"files": {"monitor.config": {"path": str(target), "sha256": "0" * 64}}})
    assert evaluate_observation(observation)["kind"] == "confirmed_tampering"
    assert json.loads(target.read_text(encoding="utf-8")) == {}
