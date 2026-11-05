"""Supervisor-owned launch for a mandatory monitoring boundary.

The agent does not establish, sign, or approve this boundary. The supervisor
process writes the profile and the HMAC key, probes the profile, and only
then starts the requested command. A configured flag is not an established
boundary, and an established launch is not a verified claim about a different
process.

On Darwin the mechanism is a custom Seatbelt profile via ``sandbox-exec -f``.
Named profiles are not used. Apple does not document ``sandbox-exec`` as a
stable application API, so the mechanism is experimental and every launch is
gated on a write probe against the protected file. If the probe does not
deny the write, the command is not started.

This module does not start containers or create Unix users.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .boundary import (
    MECHANISM_SEATBELT,
    SCOPE_SEATBELT,
    TIER_VERIFIED,
    BoundaryClaim,
    BoundaryLayoutError,
    assert_single_directory_entry,
    contained_environment,
    interceptor_claim,
)
from .contract import LIFECYCLE_CONTINUE, LIFECYCLE_TERMINATE
from .platforms import select_boundary

MECHANISM = "macos_seatbelt_experimental"
STATE_CONFIGURED = "CONFIGURED"
STATE_ESTABLISHING = "ESTABLISHING"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_VERIFIED = "VERIFIED"
STATE_DEGRADED = "DEGRADED"
STATE_EXPIRED = "EXPIRED"
STATE_TERMINATED = "TERMINATED"
STATE_FAILED = "FAILED"

_TRANSITIONS = {
    STATE_CONFIGURED: {"ESTABLISHING"},
    STATE_ESTABLISHING: {STATE_ESTABLISHED, STATE_FAILED},
    STATE_ESTABLISHED: {STATE_VERIFIED, STATE_FAILED, STATE_TERMINATED},
    STATE_VERIFIED: {STATE_DEGRADED, STATE_EXPIRED, STATE_TERMINATED, STATE_FAILED},
    STATE_DEGRADED: {STATE_VERIFIED, STATE_TERMINATED, STATE_FAILED, STATE_EXPIRED},
    STATE_EXPIRED: {STATE_TERMINATED, STATE_FAILED},
    STATE_TERMINATED: set(),
    STATE_FAILED: set(),
}

_LIMITATIONS = [
    "Seatbelt via sandbox-exec -f is an experimental compatibility mechanism, gated on a host write probe. It is not a documented stable Apple production API.",
    "The profile covers the launched process tree only. An unsandboxed process of the same user is outside it.",
    "Named sandbox-exec profiles are not used. On this OS they are not treated as available.",
    "system-socket remains allowed so the interpreter can start. Unix-domain sockets are not a fully closed egress boundary.",
    "The TCP allowlist is localhost on the configured gateway ports. Other TCP, including a non-listed port and typical external egress, is denied by the default. IPv6 is not separately allowlisted.",
    "A local profile does not protect files on a remote MCP server.",
    "A missed heartbeat is not sabotage.",
]


def transition(current: str, new: str) -> str:
    if new not in _TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid lifecycle transition {current} -> {new}")
    return new


def _canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _execution_id() -> str:
    return uuid.uuid4().hex


def process_identity(pid: int) -> dict[str, Any] | None:
    """PID plus start time. A reused PID has a different start time.

    A zombie is not a live process. ``ps`` can still print it until the parent reaps it.
    """
    try:
        waited, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        waited = 0
    if waited == pid:
        return None
    proc = subprocess.run(
        ["ps", "-o", "stat=,lstart=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    text = (proc.stdout or "").strip()
    if proc.returncode != 0 or not text:
        return None
    stat, _, started = text.partition(" ")
    if stat.startswith("Z") or not started.strip():
        return None
    return {"pid": pid, "started_at": started.strip()}


def _seal(body: dict[str, Any], key: bytes) -> dict[str, Any]:
    record = dict(body)
    record["mac"] = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    return record


def _check_mac(record: dict[str, Any], key: bytes) -> bool:
    presented = str(record.get("mac") or "")
    body = {key: value for key, value in record.items() if key != "mac"}
    expected = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(presented, expected)


class Supervisor:
    def __init__(self, state_dir: Path, *, freshness_s: float = 300.0) -> None:
        self.state_dir = Path(state_dir)
        self.freshness_s = freshness_s
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)

    def _dir(self, execution_id: str) -> Path:
        if not execution_id.isalnum() or len(execution_id) > 64:
            raise ValueError("execution id is not a supervisor identifier")
        path = self.state_dir / execution_id
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def launch(
        self,
        argv: list[str],
        *,
        workspace: Path,
        protected: Path,
        mode: str,
        policy_bytes: bytes | None = None,
        cwd: Path | None = None,
        gateway_ports: tuple[int, ...] = (),
        wait: bool = True,
        lifecycle: str = LIFECYCLE_CONTINUE,
    ) -> dict[str, Any]:
        if mode not in {"protected", "observe"}:
            return _failure(STATE_FAILED, "mode must be protected or observe")
        if not argv:
            return _failure(STATE_FAILED, "no command was provided")
        execution_id = _execution_id()
        directory = self._dir(execution_id)
        protected = Path(protected)
        workspace = Path(workspace)
        before = protected.read_text(encoding="utf-8") if protected.exists() else None
        if before is None:
            return _failure(STATE_FAILED, "protected asset is missing", execution_id=execution_id)
        if mode == "observe":
            return self._observe(execution_id, directory, argv, workspace, protected, before, policy_bytes, cwd)
        if lifecycle not in {LIFECYCLE_CONTINUE, LIFECYCLE_TERMINATE}:
            return _failure(STATE_FAILED, "lifecycle must be continue_restricted or terminate", execution_id=execution_id)
        adapter = select_boundary()
        prepared = adapter.prepare(
            workspace=workspace,
            protected=protected,
            state_dir=self.state_dir,
            directory=directory,
            gateway_ports=gateway_ports,
        )
        if not prepared.ok:
            return _failure(STATE_FAILED, prepared.reason, execution_id=execution_id, mechanism=prepared.mechanism)
        state = transition(STATE_CONFIGURED, STATE_ESTABLISHING)
        key = secrets.token_bytes(32)
        key_path = directory / "authority.key"
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
        write_result = workspace / f".varden-mip-probe-{execution_id}.txt"
        secret_result = workspace / f".varden-mip-secret-{execution_id}.txt"
        _run_probe(adapter, prepared, [sys.executable, "-c", _WRITE_PROBE, str(protected), str(write_result)], workspace)
        after_probe = protected.read_text(encoding="utf-8")
        write_text = _read_probe(write_result)
        _run_probe(adapter, prepared, [sys.executable, "-c", _SECRET_PROBE, str(key_path), str(secret_result)], workspace)
        secret_text = _read_probe(secret_result)
        probe_denied = after_probe == before and _is_denial(write_text)
        secret_denied = key_path.is_file() and _is_denial(secret_text)
        if not probe_denied or not secret_denied:
            state = transition(state, STATE_FAILED)
            reason = "pre-launch probe did not deny the protected write" if not probe_denied else "pre-launch probe could read the supervisor key"
            self._write(
                directory,
                _seal(_body(
                    execution_id=execution_id,
                    state=state,
                    established=False,
                    verified=False,
                    protected=protected,
                    before=before,
                    after=after_probe,
                    policy_bytes=policy_bytes,
                    argv=argv,
                    pid=None,
                    started_at=None,
                    reason=reason,
                    lifecycle=lifecycle,
                    mechanism=prepared.mechanism,
                ), key),
            )
            return _failure(
                STATE_FAILED,
                reason + "; the command was not started",
                execution_id=execution_id,
                launched=False,
                mechanism=prepared.mechanism,
            )
        try:
            assert_single_directory_entry(protected, label="protected file")
            assert_single_directory_entry(key_path, label="supervisor key")
        except BoundaryLayoutError as exc:
            return _failure(
                STATE_FAILED,
                f"{exc}; the command was not started",
                execution_id=execution_id,
                launched=False,
                mechanism=prepared.mechanism,
            )
        state = transition(state, STATE_ESTABLISHED)
        proc = adapter.spawn(prepared, argv, cwd=cwd or workspace, env=contained_environment())
        identity = process_identity(proc.pid)
        if wait:
            returncode = _wait(proc)
            after = protected.read_text(encoding="utf-8")
            tampered = after != before
            if tampered:
                state = transition(state, STATE_FAILED)
            else:
                state = transition(state, STATE_TERMINATED)
            record = _seal(_body(
                execution_id=execution_id,
                state=state,
                established=True,
                verified=False,
                protected=protected,
                before=before,
                after=after,
                policy_bytes=policy_bytes,
                argv=argv,
                pid=proc.pid,
                started_at=(identity or {}).get("started_at"),
                reason=None if not tampered else "protected bytes changed during the supervised command",
                returncode=returncode,
                lifecycle=lifecycle,
                mechanism=prepared.mechanism,
                covers=("filesystem", "secret"),
                termination_confirmed=not tampered,
            ), key)
            self._write(directory, record)
            return {
                "ok": not tampered,
                "launched": True,
                "execution_id": execution_id,
                "state": state,
                "returncode": returncode,
                "established": True,
                "verified": False,
                "current_tier": state,
                "mechanism": prepared.mechanism,
                "protected_unchanged": not tampered,
                "attestation_path": str(directory / "attestation.json"),
            }
        if identity is None:
            running_state = state
            running_verified = False
            reason = "process start time was not available; not claiming VERIFIED"
        else:
            running_state = transition(state, STATE_VERIFIED)
            running_verified = True
            reason = None
        record = _seal(_body(
            execution_id=execution_id,
            state=running_state,
            established=True,
            verified=running_verified,
            protected=protected,
            before=before,
            after=before,
            policy_bytes=policy_bytes,
            argv=argv,
            pid=proc.pid,
                started_at=identity.get("started_at") if identity else None,
                reason=reason,
                lifecycle=lifecycle,
                mechanism=prepared.mechanism,
                covers=("filesystem", "secret"),
            ), key)
        self._write(directory, record)
        return {
            "ok": True,
            "launched": True,
            "execution_id": execution_id,
            "state": running_state,
            "returncode": None,
            "established": True,
            "verified": running_verified,
            "current_tier": running_state,
            "mechanism": prepared.mechanism,
            "pid": proc.pid,
            "process": proc,
            "protected_unchanged": True,
            "attestation_path": str(directory / "attestation.json"),
        }

    def verify(self, execution_id: str, *, now: float | None = None) -> dict[str, Any]:
        directory = self.state_dir / execution_id
        record_path = directory / "attestation.json"
        key_path = directory / "authority.key"
        if not record_path.is_file() or not key_path.is_file():
            return {"ok": False, "state": STATE_FAILED, "verified": False, "reason": "attestation_missing"}
        record = json.loads(record_path.read_text(encoding="utf-8"))
        key = key_path.read_bytes()
        if not _check_mac(record, key):
            return {"ok": False, "state": STATE_FAILED, "verified": False, "reason": "mac_mismatch"}
        if record.get("origin") != "supervisor":
            return {"ok": False, "state": STATE_FAILED, "verified": False, "reason": "origin_rejected"}
        now = time.time() if now is None else now
        issued = float(record.get("issued_at") or 0)
        expired = now - issued > self.freshness_s or now < issued
        pid = record.get("pid")
        if not isinstance(pid, int):
            return {
                "ok": record.get("state") == STATE_TERMINATED and bool(record.get("established")),
                "state": record.get("state") or STATE_TERMINATED,
                "verified": False,
                "reason": "process_not_running",
                "execution_id": execution_id,
                "established": bool(record.get("established")),
                "protected_digest": record.get("protected_digest"),
            }
        identity = process_identity(pid)
        if identity is None:
            return {
                "ok": bool(record.get("established")),
                "state": STATE_TERMINATED,
                "verified": False,
                "reason": "process_exited",
                "execution_id": execution_id,
                "established": bool(record.get("established")),
            }
        if identity["started_at"] != record.get("started_at"):
            return {"ok": False, "state": STATE_FAILED, "verified": False, "reason": "pid_reused", "execution_id": execution_id, "termination_confirmed": False}
        if expired:
            confirmed = False
            if record.get("lifecycle") == LIFECYCLE_TERMINATE:
                _signal_tree(pid)
                confirmed = process_identity(pid) is None
                if confirmed:
                    self._reseal(directory, record, key, state=STATE_TERMINATED, verified=False, reason="expired_and_terminated", termination_confirmed=True)
                    return {
                        "ok": True,
                        "state": STATE_TERMINATED,
                        "verified": False,
                        "reason": "expired_and_terminated",
                        "termination_confirmed": True,
                        "execution_id": execution_id,
                        "established": True,
                    }
            return {
                "ok": False,
                "state": STATE_EXPIRED,
                "verified": False,
                "reason": "expired",
                "termination_confirmed": confirmed,
                "execution_id": execution_id,
                "established": bool(record.get("established")),
                "lifecycle": record.get("lifecycle") or LIFECYCLE_CONTINUE,
            }
        fresh = record.get("state") == STATE_VERIFIED and bool(record.get("verified"))
        return {
            "ok": fresh,
            "state": STATE_VERIFIED if fresh else STATE_DEGRADED,
            "verified": fresh,
            "reason": None if fresh else "not_a_current_verified_claim",
            "execution_id": execution_id,
            "mechanism": record.get("mechanism"),
            "established": bool(record.get("established")),
            "pid": pid,
            "covers": list(record.get("covers") or []),
            "lifecycle": record.get("lifecycle") or LIFECYCLE_CONTINUE,
        }

    def claim(self, execution_id: str) -> BoundaryClaim:
        """A Predictive Authority claim for this execution, or the interceptor default.

        Covers come from the probes stored in the sealed record. A filesystem
        probe does not add network or MCP to those covers.
        """
        current = self.verify(execution_id)
        covers = tuple(current.get("covers") or ())
        if not current.get("verified") or "filesystem" not in covers:
            return interceptor_claim()
        return BoundaryClaim(
            tier=TIER_VERIFIED,
            mechanism=str(current.get("mechanism") or MECHANISM),
            covers=covers,
            verified=True,
            origin="probe",
            scope=SCOPE_SEATBELT,
            os_isolation=True,
        )

    def renew(self, execution_id: str) -> dict[str, Any]:
        loaded = self._load(execution_id)
        if loaded[0] is None:
            return loaded[2]
        record, key, directory = loaded
        pid = record.get("pid")
        identity = process_identity(pid) if isinstance(pid, int) else None
        if identity is None or identity.get("started_at") != record.get("started_at"):
            return {"ok": False, "verified": False, "state": STATE_FAILED, "reason": "identity_mismatch", "termination_confirmed": False}
        path = record.get("protected_path")
        if not path or _digest(Path(path).read_bytes()) != record.get("protected_digest"):
            return {"ok": False, "verified": False, "state": STATE_FAILED, "reason": "protected_bytes_changed", "termination_confirmed": False}
        record["issued_at"] = time.time()
        record["state"] = STATE_VERIFIED
        record["verified"] = True
        record["reason"] = None
        self._write(directory, _seal({k: v for k, v in record.items() if k != "mac"}, key))
        return self.verify(execution_id)

    def terminate(self, execution_id: str) -> dict[str, Any]:
        loaded = self._load(execution_id)
        if loaded[0] is None:
            return loaded[2]
        record, key, directory = loaded
        pid = record.get("pid")
        if not isinstance(pid, int):
            return {"ok": False, "verified": False, "state": STATE_TERMINATED, "reason": "no_process", "termination_confirmed": False}
        identity = process_identity(pid)
        if identity is None:
            return {"ok": True, "verified": False, "state": STATE_TERMINATED, "reason": "already_absent", "process_absent": True, "termination_confirmed": False}
        if identity.get("started_at") != record.get("started_at"):
            return {"ok": False, "verified": False, "state": STATE_FAILED, "reason": "pid_reused", "termination_confirmed": False}
        _signal_tree(pid)
        if process_identity(pid) is not None:
            return {"ok": False, "verified": False, "state": STATE_DEGRADED, "reason": "termination_not_confirmed", "termination_confirmed": False}
        self._reseal(directory, record, key, state=STATE_TERMINATED, verified=False, reason="terminated_by_supervisor", termination_confirmed=True)
        return {"ok": True, "verified": False, "state": STATE_TERMINATED, "reason": "terminated_by_supervisor", "termination_confirmed": True}

    def _load(self, execution_id: str):
        directory = self.state_dir / execution_id
        record_path = directory / "attestation.json"
        key_path = directory / "authority.key"
        if not record_path.is_file() or not key_path.is_file():
            return None, None, {"ok": False, "state": STATE_FAILED, "verified": False, "reason": "attestation_missing"}
        record = json.loads(record_path.read_text(encoding="utf-8"))
        key = key_path.read_bytes()
        if not _check_mac(record, key) or record.get("origin") != "supervisor":
            return None, None, {"ok": False, "state": STATE_FAILED, "verified": False, "reason": "mac_mismatch"}
        return record, key, directory

    def _reseal(self, directory: Path, record: dict[str, Any], key: bytes, **updates: Any) -> None:
        body = {k: v for k, v in record.items() if k != "mac"}
        body.update(updates)
        self._write(directory, _seal(body, key))

    def _observe(self, execution_id, directory, argv, workspace, protected, before, policy_bytes, cwd) -> dict[str, Any]:
        proc = subprocess.run(argv, cwd=str(cwd or workspace), check=False)
        after = protected.read_text(encoding="utf-8") if protected.exists() else ""
        key = secrets.token_bytes(32)
        key_path = directory / "authority.key"
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
        record = _seal({
            "execution_id": execution_id,
            "origin": "supervisor",
            "state": STATE_TERMINATED,
            "established": False,
            "verified": False,
            "mechanism": "none",
            "tier": "INTERCEPTED",
            "issued_at": time.time(),
            "protected_digest": _digest(after.encode("utf-8")),
            "policy_digest": _digest(policy_bytes or b""),
            "returncode": proc.returncode,
            "pid": None,
            "started_at": None,
            "limitations": ["Observation-only launch. No OS boundary was applied."],
            "reason": None,
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "protected_path_digest": _digest(str(protected).encode("utf-8")),
            "protected_before_digest": _digest(before.encode("utf-8")),
            "argv0": argv[0],
            "supervisor_pid": os.getpid(),
            "network": "unrestricted",
            "remote_mcp": "NOT_ENFORCEABLE",
            "seatbelt_family": None,
        }, key)
        self._write(directory, record)
        return {
            "ok": True,
            "launched": True,
            "execution_id": execution_id,
            "state": STATE_TERMINATED,
            "returncode": proc.returncode,
            "established": False,
            "verified": False,
            "current_tier": "INTERCEPTED",
            "mechanism": "none",
            "protected_unchanged": after == before,
            "os_enforced": False,
        }

    def _write(self, directory: Path, record: dict[str, Any]) -> None:
        path = directory / "attestation.json"
        path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        os.chmod(path, 0o600)


def _body(
    *,
    execution_id: str,
    state: str,
    established: bool,
    verified: bool,
    protected: Path,
    before: str,
    after: str,
    policy_bytes: bytes | None,
    argv: list[str],
    pid: int | None,
    started_at: str | None,
    reason: str | None,
    returncode: int | None = None,
    lifecycle: str = LIFECYCLE_CONTINUE,
    mechanism: str = MECHANISM,
    covers: tuple[str, ...] = (),
    termination_confirmed: bool = False,
) -> dict[str, Any]:
    return {
        "execution_id": execution_id,
        "origin": "supervisor",
        "state": state,
        "established": established,
        "verified": verified and state == STATE_VERIFIED,
        "mechanism": mechanism,
        "lifecycle": lifecycle,
        "covers": list(covers),
        "termination_confirmed": termination_confirmed,
        "seatbelt_family": MECHANISM_SEATBELT,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "policy_digest": _digest(policy_bytes or b""),
        "protected_path_digest": _digest(str(protected).encode("utf-8")),
        "protected_digest": _digest(after.encode("utf-8")),
        "protected_before_digest": _digest(before.encode("utf-8")),
        "argv0": argv[0],
        "protected_path": str(protected),
        "pid": pid,
        "started_at": started_at,
        "supervisor_pid": os.getpid(),
        "issued_at": time.time(),
        "returncode": returncode,
        "reason": reason,
        "limitations": list(_LIMITATIONS),
        "network": "localhost_tcp_allowlist_only",
        "remote_mcp": "NOT_ENFORCEABLE",
    }


def _failure(state: str, reason: str, *, execution_id: str | None = None, launched: bool = False, mechanism: str | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "launched": launched,
        "execution_id": execution_id,
        "state": state,
        "returncode": None,
        "established": False,
        "verified": False,
        "current_tier": state,
        "mechanism": mechanism or ("unavailable" if platform.system() != "Darwin" else MECHANISM),
        "reason": reason,
        "protected_unchanged": None,
    }


def _run_probe(adapter: Any, prepared: Any, argv: list[str], cwd: Path) -> None:
    try:
        adapter.run_captured(prepared, argv, cwd=cwd)
    except OSError:
        return


def _read_probe(path: Path) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    path.unlink(missing_ok=True)
    return text


_WRITE_PROBE = (
    "import pathlib, sys\n"
    "protected, result = sys.argv[1], sys.argv[2]\n"
    "try:\n"
    "    pathlib.Path(protected).open('a').write('probe')\n"
    "    pathlib.Path(result).write_text('wrote')\n"
    "except OSError as exc:\n"
    "    pathlib.Path(result).write_text(type(exc).__name__ + ':' + str(getattr(exc, 'errno', None)))\n"
)
_SECRET_PROBE = (
    "import pathlib, sys\n"
    "key_path, result = sys.argv[1], sys.argv[2]\n"
    "try:\n"
    "    data = pathlib.Path(key_path).read_bytes()\n"
    "    pathlib.Path(result).write_text('read:' + str(len(data)))\n"
    "except OSError as exc:\n"
    "    pathlib.Path(result).write_text(type(exc).__name__ + ':' + str(getattr(exc, 'errno', None)))\n"
)


def _is_denial(text: str) -> bool:
    if text.startswith("read:"):
        return False
    if text.startswith("PermissionError") or text.startswith("FileNotFoundError"):
        return True
    if not text.startswith("OSError:"):
        return False
    return text.split(":", 1)[1].strip() in {"1", "13", "30"}


def _signal_tree(pid: int) -> None:
    """Ask the process group to exit. A later identity check decides if it is gone."""
    if os.name == "nt":
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if process_identity(pid) is None:
            return
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            return
        except PermissionError:
            if process_identity(pid) is None:
                return
        for _ in range(10):
            if process_identity(pid) is None:
                return
            time.sleep(0.05)


def _wait(proc: subprocess.Popen) -> int:
    if os.name == "nt":
        return proc.wait()

    def forward(signum, _frame):
        try:
            os.killpg(proc.pid, signum)
        except ProcessLookupError:
            pass

    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[sig] = signal.signal(sig, forward)
        except ValueError:
            continue
    try:
        return proc.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_argv(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="varden run", description="Launch a command under a supervisor-owned monitoring boundary")
    parser.add_argument("--protected", action="store_true", help="Require an OS boundary. Refuse to launch if it cannot be probed.")
    parser.add_argument("--observe", action="store_true", help="Explicit observation-only launch. Not OS enforcement.")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--workspace", default=None)
    parser.add_argument("--protected-path", default=None)
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--state-dir", default=None)
    parser.add_argument("--status", default=None, help="Verify an existing execution id and print its current state")
    parser.add_argument("--capabilities", action="store_true", help="Print platform assurance. This is not a live verification.")
    parser.add_argument("--lifecycle", default=LIFECYCLE_CONTINUE, choices=[LIFECYCLE_CONTINUE, LIFECYCLE_TERMINATE])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    state_dir = Path(args.state_dir) if args.state_dir else Path.home() / ".varden" / "mip-supervisor"
    supervisor = Supervisor(state_dir)
    if args.capabilities:
        from .contract import platform_matrix
        print(json.dumps(platform_matrix(), indent=2, sort_keys=True))
        return 0
    if args.status:
        body = supervisor.verify(args.status)
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0 if body.get("verified") else 1
    if args.protected and args.observe:
        print("choose either --protected or --observe", file=sys.stderr)
        return 2
    if not args.protected and not args.observe:
        print("refusing to launch: pass --protected or the explicit --observe opt-in", file=sys.stderr)
        return 2
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: varden run --protected -- COMMAND", file=sys.stderr)
        return 2
    workspace = Path(args.workspace or args.cwd or os.getcwd())
    protected = Path(args.protected_path) if args.protected_path else None
    policy_bytes = None
    if args.policy:
        policy_bytes = Path(args.policy).read_bytes()
        if protected is None:
            document = json.loads(policy_bytes)
            section = document.get("monitoring_integrity") or document
            for asset in section.get("assets") or []:
                if asset.get("protected") and asset.get("path"):
                    protected = Path(asset["path"])
                    break
    if protected is None:
        print("a --protected-path or a protected asset path in --policy is required", file=sys.stderr)
        return 2
    result = supervisor.launch(
        command,
        workspace=workspace,
        protected=protected,
        mode="protected" if args.protected else "observe",
        policy_bytes=policy_bytes,
        cwd=Path(args.cwd) if args.cwd else workspace,
        lifecycle=args.lifecycle,
    )
    if args.json or not result.get("launched"):
        print(json.dumps({key: value for key, value in result.items() if key != "process"}, indent=2, sort_keys=True, default=str))
    if not result.get("launched"):
        return 1
    if result.get("state") == STATE_FAILED:
        return 1
    code = result.get("returncode")
    return int(code) if isinstance(code, int) and code >= 0 else 1
