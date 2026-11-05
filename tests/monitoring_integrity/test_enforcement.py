"""Real interception tests. Side effects are checked on temporary files."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import contextmanager

import pytest

from varden.models import Action, Decision
from varden.monitoring_integrity.demo import BoundaryGuard, run_multistep_demonstration
from varden.monitoring_integrity.service import (
    apply_to_decision,
    arm_approval,
    enable_monitoring_integrity,
    issue_approval,
    posture,
    reset_monitoring_integrity,
)
from varden.policy import PolicyEngine
from varden_sdk.patches import patch_filesystem, patch_subprocess_extended, restore_extended
from varden_sdk.sdk import VardenBlockedError, VardenGuard


def _section(path, **asset):
    body = {
        "id": "monitor.config",
        "type": "enforcement_config",
        "owner": "operator",
        "protected": True,
        "path": str(path),
        "permitted_operations": ["read"],
        "integrity_fields": [
            {"path": "audit.enabled", "kind": "boolean_enabled"},
            {"path": "mode", "kind": "enforcement_mode"},
        ],
    }
    body.update(asset)
    return {
        "enabled": True,
        "mode": "guarded",
        "fail_closed": True,
        "policy_version": "test",
        "protected_agents": ["agent"],
        "assets": [body],
    }


@contextmanager
def boundary(section):
    token = enable_monitoring_integrity(section)
    guard = BoundaryGuard()
    originals = {}
    from varden_sdk import sdk as sdk_mod

    context = sdk_mod._current_guard.set(guard)
    patch_filesystem(guard, originals)
    patch_subprocess_extended(guard, originals)
    try:
        yield guard
    finally:
        restore_extended(originals)
        sdk_mod._current_guard.reset(context)
        reset_monitoring_integrity(release_token=token)


def test_multistep_sabotage_changes_the_file_only_without_mip():
    result = run_multistep_demonstration()
    assert result["without_mip"]["live_monitoring_disabled"] is True
    assert result["without_mip"]["side_effect"] is True
    assert result["with_mip"]["live_monitoring_disabled"] is False
    assert result["with_mip"]["side_effect"] is False
    assert result["prevented"] is True
    assert result["with_mip"]["reload_blocked"]["outcome"] == "DENY"
    assert result["os_isolation"] is False


def test_direct_write_is_blocked_before_the_file_changes(tmp_path):
    live = tmp_path / "monitoring.json"
    original = json.dumps({"audit": {"enabled": True}, "mode": "strict"})
    live.write_text(original, encoding="utf-8")
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            live.write_text(json.dumps({"audit": {"enabled": False}, "mode": "observe"}), encoding="utf-8")
        assert live.read_text(encoding="utf-8") == original
        assert json.loads(live.read_text(encoding="utf-8"))["audit"]["enabled"] is True


def test_read_of_protected_config_still_works(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text('{"audit": {"enabled": true}}', encoding="utf-8")
    with boundary(_section(live)):
        assert "enabled" in live.read_text(encoding="utf-8")


def test_ordinary_workspace_write_is_not_blocked(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    other = tmp_path / "notes.txt"
    with boundary(_section(live)):
        other.write_text("hello", encoding="utf-8")
    assert other.read_text(encoding="utf-8") == "hello"


def test_symlink_substitution_does_not_write(tmp_path):
    live = tmp_path / "monitoring.json"
    original = '{"audit": {"enabled": true}}'
    live.write_text(original, encoding="utf-8")
    link = tmp_path / "alias.json"
    link.symlink_to(live)
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            link.write_text('{"audit": {"enabled": false}}', encoding="utf-8")
    assert live.read_text(encoding="utf-8") == original


def test_atomic_replace_does_not_install_the_new_file(tmp_path):
    live = tmp_path / "monitoring.json"
    original = '{"audit": {"enabled": true}}'
    live.write_text(original, encoding="utf-8")
    staged = tmp_path / "staged.json"
    staged.write_text('{"audit": {"enabled": false}}', encoding="utf-8")
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            os.replace(staged, live)
    assert live.read_text(encoding="utf-8") == original
    assert staged.exists()


def test_path_traversal_is_the_same_asset(tmp_path):
    live = tmp_path / "monitoring.json"
    original = "{}"
    live.write_text(original, encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    disguised = nested / ".." / "monitoring.json"
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            disguised.write_text('{"audit": {"enabled": false}}', encoding="utf-8")
    assert live.read_text(encoding="utf-8") == original


def test_environment_downgrade_is_blocked(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    os.environ["VARDEN_MIP_DEMO_MODE"] = "strict"
    section = _section(live)
    section["assets"].append(
        {
            "id": "mode.env",
            "type": "security_environment",
            "owner": "operator",
            "protected": True,
            "env_keys": ["VARDEN_MIP_DEMO_MODE"],
            "permitted_operations": [],
        }
    )
    try:
        with boundary(section):
            with pytest.raises(VardenBlockedError):
                os.environ["VARDEN_MIP_DEMO_MODE"] = "observe"
        assert os.environ["VARDEN_MIP_DEMO_MODE"] == "strict"
    finally:
        os.environ.pop("VARDEN_MIP_DEMO_MODE", None)


def test_signal_to_a_protected_pid_is_blocked():
    section = {
        "enabled": True,
        "mode": "guarded",
        "fail_closed": True,
        "protected_agents": ["agent"],
        "assets": [
            {
                "id": "control",
                "type": "runtime_instrumentation",
                "owner": "operator",
                "protected": True,
                "process_names": ["varden"],
                "protected_pids": [os.getpid()],
                "permitted_operations": [],
            }
        ],
    }
    token = enable_monitoring_integrity(section)
    try:
        with pytest.raises(VardenBlockedError):
            os.kill(os.getpid(), 15)
    finally:
        reset_monitoring_integrity(release_token=token)


def test_child_python_with_the_protected_path_does_not_run(tmp_path):
    live = tmp_path / "monitoring.json"
    original = '{"audit": {"enabled": true}}'
    live.write_text(original, encoding="utf-8")
    code = "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('disabled')"
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            subprocess.call([sys.executable, "-c", code, str(live)])
    assert live.read_text(encoding="utf-8") == original


def test_unrelated_child_still_runs(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    marker = tmp_path / "child.txt"
    with boundary(_section(live)):
        completed = subprocess.run([sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ok')", str(marker)], check=False)
    assert completed.returncode == 0
    assert marker.read_text(encoding="utf-8") == "ok"


def test_require_monitored_child_blocks_unverified_interpreter(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    section = _section(live)
    section["require_monitored_child"] = True
    marker = tmp_path / "child.txt"
    with boundary(section):
        with pytest.raises(VardenBlockedError):
            subprocess.call([sys.executable, "-c", "print(1)"])
    assert not marker.exists()


def test_approval_allows_one_write_and_replay_does_not(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text('{"audit": {"enabled": true}}', encoding="utf-8")
    with boundary(_section(live)):
        record = issue_approval(
            asset_id="monitor.config",
            invariant_id="INV-001",
            operation="write",
            subject_agent="agent",
            issuer="operator",
        )
        arm_approval(record)
        live.write_text('{"audit": {"enabled": true}, "note": "operator"}', encoding="utf-8")
        assert "operator" in live.read_text(encoding="utf-8")
        arm_approval(record)
        with pytest.raises(VardenBlockedError):
            live.write_text('{"audit": {"enabled": false}}', encoding="utf-8")
    assert "enabled" in live.read_text(encoding="utf-8")
    assert '"enabled": false' not in live.read_text(encoding="utf-8").replace(" ", "")


def test_agent_metadata_cannot_disable_mip(tmp_path):
    live = tmp_path / "monitoring.json"
    original = "{}"
    live.write_text(original, encoding="utf-8")
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            # The patch does not forward this metadata; the direct precheck path does.
            from varden.monitoring_integrity.service import precheck_action

            decision = precheck_action(
                {
                    "type": "filesystem",
                    "tool": "open",
                    "args": {"path": str(live), "mode": "w"},
                    "metadata": {"monitoring_integrity": {"enabled": False}, "runtime": {"surface": "filesystem"}},
                    "agent_name": "agent",
                }
            )
            assert decision is not None and decision.prevents
            raise VardenBlockedError("blocked", decision.to_dict())
    assert live.read_text(encoding="utf-8") == original


def test_fail_open_control_plane_does_not_run_a_protected_write(tmp_path):
    live = tmp_path / "monitoring.json"
    original = '{"audit": {"enabled": true}}'
    live.write_text(original, encoding="utf-8")
    token = enable_monitoring_integrity(_section(live))
    try:
        guard = VardenGuard(
            base_url="http://127.0.0.1:9",
            api_key="k",
            mode="guarded",
            fail_mode="open",
            auto_instrument=False,
            emit_attestation=False,
        )

        def boom(*args, **kwargs):
            raise ConnectionError("control plane down")

        guard.client._client.post = boom
        with pytest.raises(VardenBlockedError):
            guard.guarded_action(
                type="filesystem",
                tool="open",
                args={"path": str(live), "mode": "w"},
                metadata={"runtime": {"surface": "filesystem", "boundary": True}},
                agent_name="agent",
            )
        assert live.read_text(encoding="utf-8") == original
    finally:
        reset_monitoring_integrity(release_token=token)


def test_control_plane_decision_strengthens_and_does_not_claim_prevention(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    action = Action(
        type="filesystem",
        tool="open",
        args={"path": str(live), "mode": "w"},
        metadata={"runtime": {"surface": "filesystem", "boundary": True}},
        agent_name="agent",
    )
    policy = {"monitoring_integrity": _section(live), "allow": [{"type": "filesystem"}]}
    decision, token = apply_to_decision(action, Decision(action="allow", reason="rule"), policy)
    try:
        assert decision.action == "block"
        assert action.metadata["monitoring_integrity"]["prevented"] is False
        assert action.metadata["monitoring_integrity"]["intercepted_before_execution"] is False
        assert action.metadata["monitoring_integrity"]["os_isolation"] is False
    finally:
        from varden.monitoring_integrity.service import reset_binding

        if token is not None:
            reset_binding(token)


def test_policy_engine_accepts_the_monitoring_integrity_section(tmp_path):
    engine = PolicyEngine(str(tmp_path / "policy.db"))
    result = engine.validate({"monitoring_integrity": _section(tmp_path / "monitoring.json"), "allow": [{"type": "filesystem"}]})
    assert result["valid"] is True


def test_posture_does_not_call_partial_coverage_verified(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    token = enable_monitoring_integrity(_section(live))
    try:
        body = posture()
        assert body["verified_protection"] is False
        assert body["os_isolation"] is False
        assert body["surfaces"]["filesystem"] == "PARTIAL"
        assert body["surfaces"]["os_exec"] == "NOT_ENFORCEABLE"
    finally:
        reset_monitoring_integrity(release_token=token)


def test_os_exec_is_not_wrapped():
    assert os.execv.__name__ == "execv"


def test_stale_file_fails_closed(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text('{"audit": {"enabled": true}}', encoding="utf-8")
    token = enable_monitoring_integrity(_section(live))
    try:
        from varden.monitoring_integrity.io_guard import internal_io

        with internal_io():
            live.write_text('{"audit": {"enabled": false}}', encoding="utf-8")
        guard = BoundaryGuard()
        originals = {}
        from varden_sdk import sdk as sdk_mod

        context = sdk_mod._current_guard.set(guard)
        patch_filesystem(guard, originals)
        try:
            with pytest.raises(VardenBlockedError):
                live.write_text('{"audit": {"enabled": false}, "again": true}', encoding="utf-8")
        finally:
            restore_extended(originals)
            sdk_mod._current_guard.reset(context)
        text = live.read_text(encoding="utf-8")
        assert "again" not in text
    finally:
        reset_monitoring_integrity(release_token=token)


def test_indirect_shell_quoting_the_protected_path_is_blocked(tmp_path):
    live = tmp_path / "monitoring.json"
    original = "{}"
    live.write_text(original, encoding="utf-8")
    script = f"python3 -c 'open(\"{live}\", \"w\").write(\"disabled\")'"
    with boundary(_section(live)):
        with pytest.raises(VardenBlockedError):
            subprocess.call(["sh", "-c", script])
    assert live.read_text(encoding="utf-8") == original


def test_concatenated_shell_path_is_a_known_unobservable_bypass(tmp_path):
    """A path built by string concatenation has no discrete token to bind.

    This is a residual bypass on the default policy. The side effect happens.
    require_monitored_child is a separate, broader control and is not this test.
    """
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    text = str(live)
    half = len(text) // 2
    script = f"python3 -c 'open(\"{text[:half]}\" + \"{text[half:]}\", \"w\").write(\"disabled\")'"
    with boundary(_section(live)):
        subprocess.call(["sh", "-c", script])
    assert live.read_text(encoding="utf-8") == "disabled"


def test_service_control_argv_is_blocked(tmp_path):
    section = {
        "enabled": True,
        "mode": "guarded",
        "fail_closed": True,
        "protected_agents": ["agent"],
        "assets": [
            {
                "id": "control",
                "type": "runtime_instrumentation",
                "owner": "operator",
                "protected": True,
                "process_names": ["varden"],
                "permitted_operations": [],
            }
        ],
    }
    with boundary(section):
        with pytest.raises(VardenBlockedError):
            subprocess.call(["kill", "-TERM", "varden"])


def test_concurrent_match_and_verify_do_not_crash(tmp_path):
    import threading

    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    errors = []

    def work():
        try:
            from varden.monitoring_integrity.service import current_registry

            registry = current_registry()
            for _ in range(20):
                registry.match_path(str(live))
                registry.refresh_verification("monitor.config")
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    token = enable_monitoring_integrity(_section(live))
    try:
        threads = [threading.Thread(target=work) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        reset_monitoring_integrity(release_token=token)
    assert errors == []
