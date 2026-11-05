"""Adversarial checks through ``varden run --protected``.

A case is OS denial only when the command was launched, the attempt ran, and
the protected hash is unchanged. The exit code is recorded and is not itself
the proof. Linux and Windows stay unsupported on a host that did not run them.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_ORIGINAL = '{"audit": {"enabled": true}, "mode": "strict"}\n'


_REPO = Path(__file__).resolve().parents[3]


def _digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _layout(root: Path) -> dict[str, Path]:
    work = root / "work"
    protected = root / "protected"
    state = root / "supervisor"
    for path in (work, protected, state):
        path.mkdir(parents=True)
    target = protected / "monitoring.json"
    target.write_text(_ORIGINAL, encoding="utf-8")
    (protected / "policy.json").write_text('{"mode":"strict"}\n', encoding="utf-8")
    return {"root": root, "work": work, "protected": protected, "state": state, "target": target}


def _launch(layout: dict[str, Path], argv: list[str], *, protected: Path | None = None, workspace: Path | None = None) -> dict[str, Any]:
    command = [
        sys.executable, "-m", "varden.cli", "run", "--protected", "--json",
        "--workspace", str(workspace or layout["work"]),
        "--protected-path", str(protected or layout["target"]),
        "--state-dir", str(layout["state"]),
        "--",
        *argv,
    ]
    proc = subprocess.run(command, cwd=str(_REPO), capture_output=True, text=True, check=False)
    payload: dict[str, Any] = {}
    try:
        parsed = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, dict):
        payload = parsed
    return {
        "cli_returncode": proc.returncode,
        "stdout": (proc.stdout or "")[-800:],
        "stderr": (proc.stderr or "")[-400:],
        "result": payload,
    }


def _case(layout: dict[str, Path], name: str, capability: str, argv: list[str], *, protected: Path | None = None, workspace: Path | None = None) -> dict[str, Any]:
    target = protected or layout["target"]
    before = _digest(target)
    launched = _launch(layout, argv, protected=target, workspace=workspace)
    after = _digest(target)
    result = launched["result"]
    started = bool(result.get("launched"))
    unchanged = before is not None and before == after
    note = ""
    note_path = (workspace or layout["work"]) / f"{name}.note"
    if note_path.is_file():
        note = note_path.read_text(encoding="utf-8").strip()
    if not started:
        outcome = "FAIL_CLOSED" if "not started" in str(result.get("reason") or launched["stderr"]) or result.get("state") == "FAILED" else "UNSUPPORTED"
    elif not unchanged or note == "wrote":
        outcome = "NOT_PREVENTED"
    elif note in {"denied", "attempted"} or (isinstance(result.get("returncode"), int) and result.get("returncode") != 0 and note):
        outcome = "OS_DENIED"
    else:
        outcome = "INCONCLUSIVE"
    return {
        "name": name,
        "capability": capability,
        "outcome": outcome,
        "launched": started,
        "cli_returncode": launched["cli_returncode"],
        "command_returncode": result.get("returncode"),
        "mechanism": result.get("mechanism"),
        "state": result.get("state"),
        "before_sha256": before,
        "after_sha256": after,
        "attempt_note": note,
        "reason": result.get("reason") or result.get("state"),
        "attestation_path": result.get("attestation_path"),
        "execution_id": result.get("execution_id"),
    }


def run_production_boundary() -> dict[str, Any]:
    """Run the production entry point. Unsupported hosts do not become successes."""
    host = platform.system()
    root = Path.home() / f".varden-mip005-{uuid.uuid4().hex}"
    try:
        layout = _layout(root)
        if host not in {"Darwin", "Linux", "Windows"}:
            return {"executed": False, "host": host, "outcome": "UNSUPPORTED", "cases": [], "detail": "no adapter was executed"}
        work = layout["work"]
        target = layout["target"]
        policy = layout["protected"] / "policy.json"
        writer = (
            "import pathlib, sys\n"
            "target, note = sys.argv[1], sys.argv[2]\n"
            "path = pathlib.Path(target)\n"
            "try:\n"
            "    path.write_text('disabled\\n', encoding='utf-8')\n"
            "    pathlib.Path(note).write_text('wrote', encoding='utf-8')\n"
            "except OSError:\n"
            "    pathlib.Path(note).write_text('denied', encoding='utf-8')\n"
        )
        (work / "writer.py").write_text(writer, encoding="utf-8")
        (work / "child.py").write_text(
            "import subprocess, sys\n"
            "raise SystemExit(subprocess.run([sys.executable, 'writer.py', sys.argv[1], sys.argv[2]]).returncode)\n",
            encoding="utf-8",
        )
        cases = [
            _case(layout, "direct_write", "filesystem", [sys.executable, "writer.py", str(target), str(work / "direct_write.note")]),
            _case(layout, "child_write", "descendant", [sys.executable, "child.py", str(target), str(work / "child_write.note")]),
            _case(layout, "policy_write", "policy", [sys.executable, "writer.py", str(policy), str(work / "policy_write.note")], protected=policy),
        ]
        link = work / "via-link"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to(target)
            cases.append(_case(layout, "symlink_write", "filesystem", [sys.executable, "writer.py", str(link), str(work / "symlink_write.note")]))
        except OSError as exc:
            cases.append({"name": "symlink_write", "capability": "filesystem", "outcome": "INCONCLUSIVE", "detail": str(exc)})
        env_script = work / "envwrite.py"
        env_script.write_text(
            "import os, pathlib\n"
            "note = os.environ['NOTE']\n"
            "try:\n"
            "    pathlib.Path(os.environ['TARGET']).write_text('env\\n', encoding='utf-8')\n"
            "    pathlib.Path(note).write_text('wrote', encoding='utf-8')\n"
            "except OSError:\n"
            "    pathlib.Path(note).write_text('denied', encoding='utf-8')\n",
            encoding="utf-8",
        )
        cases.append(_case(
            layout,
            "env_write",
            "filesystem",
            ["/bin/sh", "-c", f'TARGET={target} NOTE={work / "env_write.note"} {sys.executable} envwrite.py'],
        ))
        key_script = work / "readkey.py"
        key_script.write_text(
            "import pathlib, sys\n"
            "state, note = sys.argv[1], sys.argv[2]\n"
            "try:\n"
            "    found = list(pathlib.Path(state).glob('*/authority.key'))\n"
            "    data = found[0].read_bytes() if found else b''\n"
            "    pathlib.Path(note).write_text('wrote' if data else 'denied', encoding='utf-8')\n"
            "except OSError:\n"
            "    pathlib.Path(note).write_text('denied', encoding='utf-8')\n",
            encoding="utf-8",
        )
        cases.append(_case(layout, "read_supervisor_key", "supervisor_state", [sys.executable, "readkey.py", str(layout["state"]), str(work / "read_supervisor_key.note")]))
        outside_before = _digest(target)
        try:
            target.write_text('{"written":"same-user"}\n', encoding="utf-8")
            outside_completed = _digest(target) != outside_before
        finally:
            target.write_text(_ORIGINAL, encoding="utf-8")
        cases.append({
            "name": "unsupervised_same_user",
            "capability": "same_user",
            "outcome": "OBSERVED_OUTSIDE_BOUNDARY" if outside_completed else "INCONCLUSIVE",
            "launched": False,
            "before_sha256": outside_before,
            "after_unchanged_after_restore": _digest(target) == outside_before,
            "detail": "The test process was not launched by the supervisor. A completed write is outside the containment claim.",
        })
        bad_work = root / "bad-work"
        bad_work.mkdir()
        bad_target = bad_work / "monitoring.json"
        bad_target.write_text(_ORIGINAL, encoding="utf-8")
        refused = _launch(layout, [sys.executable, "writer.py", str(bad_target), str(bad_work / "should-not-run.note")], protected=bad_target, workspace=bad_work)
        cases.append({
            "name": "containment_unavailable",
            "capability": "fail_closed",
            "outcome": "FAIL_CLOSED" if not refused["result"].get("launched") and not (bad_work / "should-not-run.note").exists() else "NOT_PREVENTED",
            "launched": bool(refused["result"].get("launched")),
            "reason": refused["result"].get("reason") or refused["stderr"][-200:],
            "before_sha256": _digest(bad_target),
            "after_sha256": _digest(bad_target),
        })
        attestation = next((case.get("attestation_path") for case in cases if case.get("attestation_path")), None)
        execution_id = next((case.get("execution_id") for case in cases if case.get("execution_id")), None)
        if attestation and execution_id:
            path = Path(str(attestation))
            original_record = path.read_text(encoding="utf-8")
            path.write_text(original_record.replace('"origin": "supervisor"', '"origin": "agent"', 1), encoding="utf-8")
            from varden.monitoring_integrity.supervisor import Supervisor
            checked = Supervisor(layout["state"]).verify(str(execution_id))
            path.write_text(original_record, encoding="utf-8")
            cases.append({
                "name": "tampered_attestation",
                "capability": "evidence",
                "outcome": "REJECTED" if checked.get("reason") in {"mac_mismatch", "origin_rejected"} else "NOT_PREVENTED",
                "reason": checked.get("reason"),
                "launched": False,
            })
        denied = [case["name"] for case in cases if case.get("outcome") == "OS_DENIED"]
        return {
            "executed": host in {"Darwin", "Linux", "Windows"},
            "host": host,
            "platform": platform.platform(),
            "entry_point": "varden run --protected",
            "cases": cases,
            "os_denied": denied,
            "same_user_outside": outside_completed,
            "detail": "Outcomes come from the production launcher and the protected file hash.",
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def _summary(samples: list[float]) -> dict[str, float | int]:
    return {"median_ms": statistics.median(samples), "p95_ms": _percentile(samples, 0.95), "p99_ms": _percentile(samples, 0.99), "count": len(samples)}


def benchmark_launches(count: int = 100) -> dict[str, Any]:
    """Time real launches. This does not change the enforcement decision."""
    from varden.monitoring_integrity.supervisor import Supervisor

    if count < 1:
        raise ValueError("count must be positive")
    root = Path.home() / f".varden-mip005-bench-{uuid.uuid4().hex}"
    layout = _layout(root)
    bare: list[float] = []
    protected: list[float] = []
    try:
        for _ in range(count):
            started = time.perf_counter()
            subprocess.run(["/usr/bin/true"], check=False)
            bare.append((time.perf_counter() - started) * 1000)
        supervisor = Supervisor(layout["state"])
        for _ in range(count):
            started = time.perf_counter()
            result = supervisor.launch(["/usr/bin/true"], workspace=layout["work"], protected=layout["target"], mode="protected")
            protected.append((time.perf_counter() - started) * 1000)
            if result.get("protected_unchanged") is not True:
                raise RuntimeError("benchmark launch changed the protected file")
        return {
            "host": platform.platform(),
            "count": count,
            "methodology": "Each sample is one process. Unsandboxed is /usr/bin/true. Protected is Supervisor.launch of the same command, which includes the pre-launch write probe, the secret probe, process wait, and attestation sealing. Phases inside launch are not split, because splitting them would be a different code path.",
            "unsandboxed_true": _summary(bare),
            "protected_launch": _summary(protected),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)
