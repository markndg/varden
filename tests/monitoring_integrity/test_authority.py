"""Authority models. An unprovisioned host is not an isolated-authority pass."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

from varden.monitoring_integrity.authority import AGENT_USER, SUPERVISOR_USER, diagnose
from varden.monitoring_integrity.supervisor import Supervisor, _body, _seal, run_argv


def test_isolated_policy_rejects_a_symlink_or_an_agent_writable_file(tmp_path):
    from varden.monitoring_integrity.authority import read_isolated_policy

    workspace = tmp_path / "work"
    workspace.mkdir()
    policy = tmp_path / "policy.json"
    policy.write_text('{"assets": []}\n', encoding="utf-8")
    os.chmod(policy, 0o666)
    with pytest.raises(ValueError, match="not private"):
        read_isolated_policy(policy, workspace=workspace, supervisor_uid=os.getuid())
    os.chmod(policy, 0o600)
    assert read_isolated_policy(policy, workspace=workspace, supervisor_uid=os.getuid()) == b'{"assets": []}\n'
    inside = workspace / "policy.json"
    inside.write_text("{}\n", encoding="utf-8")
    os.chmod(inside, 0o600)
    with pytest.raises(ValueError, match="workspace"):
        read_isolated_policy(inside, workspace=workspace, supervisor_uid=os.getuid())
    link = tmp_path / "policy-link.json"
    link.symlink_to(policy)
    with pytest.raises(ValueError, match="symlink"):
        read_isolated_policy(link, workspace=workspace, supervisor_uid=os.getuid())


def test_sudoers_operator_rejects_injected_rules():
    from varden.monitoring_integrity.authority import sudoers_operator

    assert sudoers_operator("mark") == "mark"
    assert sudoers_operator(None) == "root"
    with pytest.raises(ValueError):
        sudoers_operator("mark\nmark ALL=(ALL) NOPASSWD: ALL")
    with pytest.raises(ValueError):
        sudoers_operator("varden-agent")
    with pytest.raises(ValueError):
        sudoers_operator("varden-supervisor")


def test_subordinate_id_ranges_must_not_overlap():
    from varden.monitoring_integrity.authority import subordinate_range_overlaps

    assert subordinate_range_overlaps("other:200000:65536\n", 200000, 65536) is True
    assert subordinate_range_overlaps("other:150000:100000\n", 200000, 65536) is True
    assert subordinate_range_overlaps("other:100000:65536\n", 200000, 65536) is False
    assert subordinate_range_overlaps("not-a-range\n", 200000, 65536) is False


def test_missing_key_is_not_regenerated(tmp_path):
    execution = "abc123"
    directory = tmp_path / execution
    directory.mkdir()
    result = Supervisor(tmp_path).verify(execution)
    assert result["reason"] == "attestation_missing"
    assert not (directory / "authority.key").exists()


def test_execution_id_mismatch_is_rejected(tmp_path):
    execution = "abc123"
    directory = tmp_path / execution
    directory.mkdir()
    key = b"k" * 32
    (directory / "authority.key").write_bytes(key)
    body = _body(
        execution_id="otherid",
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
    )
    (directory / "attestation.json").write_text(json.dumps(_seal(body, key)), encoding="utf-8")
    result = Supervisor(tmp_path).verify(execution)
    assert result["reason"] == "execution_id_mismatch"


def test_isolated_request_does_not_downgrade(tmp_path):
    report = diagnose()
    isolated = report["isolated"]
    assert isolated["verified_by_probe"] is False
    if platform.system() != "Linux":
        assert isolated["status"] == "unsupported"
    if isolated["status"] == "configured":
        return
    protected = tmp_path / "monitoring.json"
    protected.write_text('{"audit": true}\n', encoding="utf-8")
    code = run_argv([
        "--protected",
        "--authority",
        "isolated",
        "--json",
        "--workspace",
        str(tmp_path),
        "--protected-path",
        str(protected),
        "--",
        sys.executable,
        "-c",
        "print('should-not-run')",
    ])
    assert code == 1
    assert protected.read_text(encoding="utf-8") == '{"audit": true}\n'


def test_linux_agent_identity_cannot_touch_supervisor_state():
    if platform.system() != "Linux":
        pytest.skip("Linux isolated-authority identities are not this operating system. This skip is not a security verification.")
    report = diagnose()
    if report["isolated"]["status"] != "configured":
        assert report["isolated"]["status"] in {"available", "failed", "unsupported"}
        assert report["isolated"]["verified_by_probe"] is False
        return
    state = Path("/var/lib/varden/authority")
    work = Path("/var/lib/varden/work") / "mip007"
    subprocess.run(["sudo", "-n", "mkdir", "-p", str(work)], check=True)
    subprocess.run(["sudo", "-n", "chown", f"{AGENT_USER}:varden-monitor", str(work)], check=True)
    subprocess.run(["sudo", "-n", "chmod", "2770", str(work)], check=True)
    protected = Path("/var/lib/varden/authority-protected.json")
    subprocess.run(["sudo", "-n", "tee", str(protected)], input='{"audit": true}\n', text=True, check=True, capture_output=True)
    subprocess.run(["sudo", "-n", "chown", f"{SUPERVISOR_USER}:{SUPERVISOR_USER}", str(protected)], check=True)
    subprocess.run(["sudo", "-n", "chmod", "0640", str(protected)], check=True)
    before = subprocess.run(["sudo", "-n", "sha256sum", str(protected)], capture_output=True, text=True, check=True).stdout.split()[0]

    def as_agent(argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["sudo", "-n", "-u", AGENT_USER, "--", *argv], capture_output=True, text=True, check=False)

    identity = as_agent(["id", "-u"])
    assert identity.returncode == 0
    assert identity.stdout.strip() == str(pwd_uid(AGENT_USER))
    read_state = as_agent(["python3", "-c", "from pathlib import Path; list(Path('/var/lib/varden/authority').iterdir())"])
    assert read_state.returncode != 0
    link = as_agent(["ln", str(protected), str(work / "hard")])
    assert link.returncode != 0
    linked = subprocess.run(["sudo", "-n", "test", "-e", str(work / "hard")], check=False)
    assert linked.returncode != 0
    script = work / "attempt.py"
    script_text = (
        "import os, pathlib, sys\n"
        "target = pathlib.Path(sys.argv[1])\n"
        "note = pathlib.Path(sys.argv[2])\n"
        "fds = []\n"
        "for item in pathlib.Path('/proc/self/fd').iterdir():\n"
        "    try:\n"
        "        fds.append(os.readlink(item))\n"
        "    except OSError:\n"
        "        fds.append('unreadable')\n"
        "try:\n"
        "    target.write_text('disabled\\n', encoding='utf-8')\n"
        "    note.write_text('wrote ' + ' '.join(fds), encoding='utf-8')\n"
        "except OSError as exc:\n"
        "    note.write_text(type(exc).__name__ + ' ' + ' '.join(fds), encoding='utf-8')\n"
    )
    subprocess.run(["sudo", "-n", "tee", str(script)], input=script_text, text=True, check=True, capture_output=True)
    subprocess.run(["sudo", "-n", "chown", f"{AGENT_USER}:varden-monitor", str(script)], check=True)
    launched = subprocess.run(
        [sys.executable, "-m", "varden.cli", "run", "--protected", "--authority", "isolated", "--json",
         "--workspace", str(work), "--protected-path", str(protected), "--",
         "python3", str(script), str(protected), str(work / "note")],
        capture_output=True, text=True, check=False,
    )
    payload = json.loads(launched.stdout)
    after = subprocess.run(["sudo", "-n", "sha256sum", str(protected)], capture_output=True, text=True, check=True).stdout.split()[0]
    assert payload.get("launched") is True, launched.stderr + launched.stdout
    assert payload["authority_model"] == "isolated"
    assert payload["verified_by_probe"] is True
    assert before == after
    note = subprocess.run(["sudo", "-n", "cat", str(work / "note")], capture_output=True, text=True, check=True).stdout
    assert note.startswith("PermissionError") or note.startswith("OSError")
    assert "authority.key" not in note
    key_read = as_agent(["python3", "-c", "import pathlib; print(next(pathlib.Path('/var/lib/varden/authority').rglob('authority.key')).read_bytes())"])
    assert key_read.returncode != 0
    forged = as_agent(["python3", "-c", "from pathlib import Path; Path('/var/lib/varden/authority/forged.json').write_text('{}')"])
    assert forged.returncode != 0
    forged_present = subprocess.run(["sudo", "-n", "test", "-e", str(state / "forged.json")], check=False)
    assert forged_present.returncode != 0
    impersonate = as_agent(["sudo", "-n", "-u", SUPERVISOR_USER, "--", "true"])
    assert impersonate.returncode != 0
    replaced = as_agent(["python3", "-c", "open('/var/lib/varden/authority/authority.key','w').write('x')"])
    assert replaced.returncode != 0
    moved = as_agent(["mv", str(state), str(work / "stolen")])
    assert moved.returncode != 0
    symlink = as_agent(["ln", "-s", str(protected), str(work / "via")])
    assert symlink.returncode == 0
    through = as_agent(["python3", "-c", f"open({str(work / 'via')!r}).read()"])
    assert through.returncode != 0
    overwrite = as_agent(["python3", "-c", f"open({str(work / 'via')!r}, 'w').write('x')"])
    assert overwrite.returncode != 0
    child = work / "child.py"
    child_text = (
        "import os, pathlib, sys\n"
        "target, note = sys.argv[1], sys.argv[2]\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    try:\n"
        "        pathlib.Path(target).write_text('child\\n', encoding='utf-8')\n"
        "        pathlib.Path(note).write_text('child-wrote', encoding='utf-8')\n"
        "    except OSError as exc:\n"
        "        pathlib.Path(note).write_text(type(exc).__name__, encoding='utf-8')\n"
        "    os._exit(0)\n"
        "os.waitpid(pid, 0)\n"
    )
    subprocess.run(["sudo", "-n", "tee", str(child)], input=child_text, text=True, check=True, capture_output=True)
    subprocess.run(["sudo", "-n", "chown", f"{AGENT_USER}:varden-monitor", str(child)], check=True)
    child_run = subprocess.run(
        [sys.executable, "-m", "varden.cli", "run", "--protected", "--authority", "isolated", "--json",
         "--workspace", str(work), "--protected-path", str(protected), "--",
         "python3", str(child), str(protected), str(work / "child-note")],
        capture_output=True, text=True, check=False,
    )
    child_payload = json.loads(child_run.stdout)
    child_after = subprocess.run(["sudo", "-n", "sha256sum", str(protected)], capture_output=True, text=True, check=True).stdout.split()[0]
    assert child_payload.get("launched") is True, child_run.stderr + child_run.stdout
    assert child_payload["verified_by_probe"] is True
    assert child_after == before
    child_note = subprocess.run(["sudo", "-n", "cat", str(work / "child-note")], capture_output=True, text=True, check=True).stdout
    assert child_note.startswith("PermissionError") or child_note.startswith("OSError")


def pwd_uid(name: str) -> int:
    import pwd
    return pwd.getpwnam(name).pw_uid
