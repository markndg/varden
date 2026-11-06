"""Supervised launch. The command under test is the same function the CLI calls."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import uuid
from pathlib import Path

from varden.monitoring_integrity.analysis import analyse
from varden.monitoring_integrity.assets import AssetRegistry
from varden.monitoring_integrity.boundary import evaluate_attestation
from varden.monitoring_integrity.supervisor import STATE_TERMINATED, Supervisor

_ORIGINAL = '{"audit": {"enabled": true}, "mode": "strict"}\n'


def _layout():
    root = Path.home() / f".varden-mip-run-{uuid.uuid4().hex}"
    work = root / "work"
    protected_dir = root / "protected"
    state = root / "supervisor"
    work.mkdir(parents=True)
    protected_dir.mkdir()
    target = protected_dir / "monitoring.json"
    target.write_text(_ORIGINAL, encoding="utf-8")
    return root, work, target, state


def _registry():
    registry = AssetRegistry()
    registry.load_section(
        {
            "enabled": True,
            "mode": "guarded",
            "assets": [{"id": "monitor.config", "type": "enforcement_config", "protected": True, "path": "/var/lib/varden/monitoring.json", "permitted_operations": ["read"]}],
            "grants": [{"id": "reload", "operations": ["exec"], "assets": ["monitor.config"], "surface": "subprocess", "sequence": 1, "activation": True}],
        },
        section_hash="supervisor",
    )
    return registry


def test_probe_outcome_comes_from_the_supervisor_pipe(tmp_path):
    from varden.monitoring_integrity.supervisor import _is_denial, _run_probe

    class Adapter:
        def run_captured(self, prepared, argv, cwd):
            del prepared
            Path(cwd, "forged-denial.txt").write_text("PermissionError:13", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, stdout="wrote\n", stderr="PermissionError:1")

    text = _run_probe(Adapter(), None, ["probe"], tmp_path)
    assert text == "wrote"
    assert _is_denial(text) is False
    assert (tmp_path / "forged-denial.txt").read_text(encoding="utf-8") == "PermissionError:13"
    assert _is_denial("PermissionError:1") is True

    class Uncaptured:
        def run_captured(self, prepared, argv, cwd):
            del prepared, argv, cwd
            return 0

    assert _run_probe(Uncaptured(), None, ["probe"], tmp_path) == ""
    assert _is_denial("") is False


def test_linux_record_does_not_claim_seatbelt(tmp_path):
    from varden.monitoring_integrity.supervisor import _body, _claim_os_isolation, _claim_scope

    body = _body(
        execution_id="abc123",
        state="TERMINATED",
        established=True,
        verified=False,
        protected=tmp_path / "monitoring.json",
        before="a",
        after="a",
        policy_bytes=b"{}",
        argv=["/bin/true"],
        pid=None,
        started_at=None,
        reason=None,
        mechanism="linux_bubblewrap_unverified",
    )
    assert body["seatbelt_family"] is None
    assert body["network"] == "not_claimed"
    text = " ".join(body["limitations"])
    assert "Seatbelt" not in text
    assert "TCP allowlist" not in text
    assert "Network egress is not isolated." in body["limitations"]
    linux_scope = _claim_scope("linux_bubblewrap_unverified")
    assert "not a Seatbelt profile" in linux_scope
    assert "applies only to processes the supervisor launched under this profile" not in linux_scope
    assert _claim_os_isolation("linux_bubblewrap_unverified", ("filesystem",)) is True
    assert _claim_os_isolation("windows_restricted_token_unverified", ("filesystem",)) is False
    assert "Seatbelt" in _claim_scope("macos_seatbelt_experimental")


def test_protected_launch_refuses_when_the_asset_is_inside_the_workspace():
    root, work, target, state = _layout()
    try:
        inside = work / "monitoring.json"
        inside.write_text(_ORIGINAL, encoding="utf-8")
        marker = work / "ran.txt"
        result = Supervisor(state).launch(
            ["python3", "-c", f"open({str(marker)!r}, 'w').write('ran')"],
            workspace=work,
            protected=inside,
            mode="protected",
        )
        assert result["launched"] is False
        assert result["state"] == "FAILED"
        assert not marker.exists()
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_supervised_command_cannot_change_the_protected_file_and_can_write_workspace():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state)
        text = str(target)
        half = len(text) // 2
        child = work / "child_write.py"
        child.write_text("import pathlib, sys\npathlib.Path(sys.argv[1]).write_text('child')\n", encoding="utf-8")
        parent = work / "parent.py"
        parent.write_text(
            "import subprocess, sys\nraise SystemExit(subprocess.run([sys.executable, sys.argv[1], sys.argv[2]]).returncode)\n",
            encoding="utf-8",
        )
        attacks = [
            ["python3", "-c", f"open({text!r}, 'w').write('disabled')"],
            ["/bin/sh", "-c", f"python3 -c 'open(\"{text[:half]}\" + \"{text[half:]}\", \"w\").write(\"disabled\")'"],
            ["python3", "-c", f"import os; os.execv('/bin/sh', ['/bin/sh', '-c', 'printf disabled > {text}'])"],
            ["python3", str(parent), str(child), text],
        ]
        for argv in attacks:
            result = supervisor.launch(argv, workspace=work, protected=target, mode="protected")
            assert result["launched"] is True, result
            assert result["returncode"] not in (0, None), result
            assert result["protected_unchanged"] is True, result
            assert result["verified"] is False
            assert result["state"] == STATE_TERMINATED
            assert target.read_text(encoding="utf-8") == _ORIGINAL
            current = supervisor.verify(result["execution_id"])
            assert current["verified"] is False
            assert current["established"] is True
        note = work / "notes.txt"
        ok = supervisor.launch(
            ["python3", "-c", f"open({str(note)!r}, 'w').write('fine')"],
            workspace=work,
            protected=target,
            mode="protected",
        )
        assert ok["returncode"] == 0
        assert note.read_text(encoding="utf-8") == "fine"
        assert target.read_text(encoding="utf-8") == _ORIGINAL
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_running_execution_is_verified_only_while_identity_matches():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state, freshness_s=60)
        started = supervisor.launch(["/bin/sleep", "30"], workspace=work, protected=target, mode="protected", wait=False)
        assert started["verified"] is True
        assert started["pid"]
        current = supervisor.verify(started["execution_id"])
        assert current["verified"] is True
        assert current["state"] == "VERIFIED"
        from varden.monitoring_integrity.analysis import _protection
        claim = supervisor.claim(started["execution_id"])
        assert _protection("filesystem", claim)["protection_tier"] == "VERIFIED"
        assert _protection("network", claim)["protection_tier"] == "INTERCEPTED"
        assert _protection("mcp", claim)["protection_tier"] == "NOT_ENFORCEABLE"
        os.killpg(started["pid"], signal.SIGTERM)
        started["process"].wait(timeout=5)
        after = supervisor.verify(started["execution_id"])
        assert after["verified"] is False
        assert after["state"] == STATE_TERMINATED
        assert target.read_text(encoding="utf-8") == _ORIGINAL
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_forged_attestation_and_agent_origin_are_not_verified():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state)
        result = supervisor.launch(["/usr/bin/true"], workspace=work, protected=target, mode="protected")
        record_path = Path(result["attestation_path"])
        key = (record_path.parent / "authority.key").read_bytes()
        forged = json.loads(record_path.read_text(encoding="utf-8"))
        forged["verified"] = True
        forged["state"] = "VERIFIED"
        forged["mac"] = "0" * 64
        record_path.write_text(json.dumps(forged), encoding="utf-8")
        checked = supervisor.verify(result["execution_id"])
        assert checked["verified"] is False
        assert checked["reason"] == "mac_mismatch"
        claim = evaluate_attestation(
            {"origin": "agent", "tier": "VERIFIED", "verified": True, "observed_at": 1, "digest": "abc"},
            now=1,
            max_age_s=30,
            expected_digest="abc",
        )
        assert claim.verified is False
        report = analyse(_registry(), boundary=claim)
        assert report["interruption"]["protection_tier"] == "INTERCEPTED"
        assert key  # supervisor holds the key; the assertion above is the rejection
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_cli_protected_run_preserves_the_asset_and_the_exit_code():
    root, work, target, state = _layout()
    try:
        script = work / "agent.py"
        script.write_text(
            "import pathlib, sys\n"
            "target, note = sys.argv[1], sys.argv[2]\n"
            "try:\n"
            "    pathlib.Path(target).write_text('disabled')\n"
            "except OSError:\n"
            "    pathlib.Path(note).write_text('continued')\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
        note = work / "continued.txt"
        proc = subprocess.run(
            [
                "python3", "-m", "varden.cli", "run", "--protected",
                "--workspace", str(work),
                "--protected-path", str(target),
                "--state-dir", str(state),
                "--", "python3", str(script), str(target), str(note),
            ],
            cwd=str(Path(__file__).resolve().parents[2]),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert note.read_text(encoding="utf-8") == "continued"
        assert target.read_text(encoding="utf-8") == _ORIGINAL
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_a_later_supervised_command_cannot_read_an_earlier_authority_key():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state)
        first = supervisor.launch(["/usr/bin/true"], workspace=work, protected=target, mode="protected")
        key = Path(first["attestation_path"]).parent / "authority.key"
        result = supervisor.launch(
            ["python3", "-c", f"open({str(key)!r}, 'rb').read()"],
            workspace=work,
            protected=target,
            mode="protected",
        )
        assert result["returncode"] not in (0, None)
        assert target.read_text(encoding="utf-8") == _ORIGINAL
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_expiry_drops_verified_without_killing_under_continue_restricted():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state, freshness_s=60)
        started = supervisor.launch(["/bin/sleep", "30"], workspace=work, protected=target, mode="protected", wait=False)
        assert started["verified"] is True
        issued = json.loads(Path(started["attestation_path"]).read_text(encoding="utf-8"))["issued_at"]
        expired = supervisor.verify(started["execution_id"], now=issued + 120)
        assert expired["verified"] is False
        assert expired["state"] == "EXPIRED"
        assert expired["termination_confirmed"] is False
        assert supervisor.verify(started["execution_id"])["verified"] is True
        stopped = supervisor.terminate(started["execution_id"])
        assert stopped["termination_confirmed"] is True
        assert stopped["state"] == "TERMINATED"
        assert target.read_text(encoding="utf-8") == _ORIGINAL
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_terminate_lifecycle_confirms_the_process_is_gone_when_the_attestation_expires():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state, freshness_s=60)
        started = supervisor.launch(
            ["/bin/sleep", "30"],
            workspace=work,
            protected=target,
            mode="protected",
            wait=False,
            lifecycle="terminate",
        )
        issued = json.loads(Path(started["attestation_path"]).read_text(encoding="utf-8"))["issued_at"]
        expired = supervisor.verify(started["execution_id"], now=issued + 120)
        assert expired["verified"] is False
        assert expired["termination_confirmed"] is True
        assert expired["state"] == "TERMINATED"
        assert target.read_text(encoding="utf-8") == _ORIGINAL
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_renewal_keeps_the_same_process_identity_verified():
    root, work, target, state = _layout()
    try:
        supervisor = Supervisor(state, freshness_s=60)
        started = supervisor.launch(["/bin/sleep", "30"], workspace=work, protected=target, mode="protected", wait=False)
        before = json.loads(Path(started["attestation_path"]).read_text(encoding="utf-8"))["issued_at"]
        renewed = supervisor.renew(started["execution_id"])
        assert renewed["verified"] is True
        after = json.loads(Path(started["attestation_path"]).read_text(encoding="utf-8"))["issued_at"]
        assert after >= before
        supervisor.terminate(started["execution_id"])
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_missing_mode_does_not_launch():
    proc = subprocess.run(
        ["python3", "-m", "varden.cli", "run", "--", "python3", "-c", "print('no')"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "no" not in proc.stdout
