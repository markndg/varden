"""Two authority models for a protected launch.

Developer mode keeps today's behavior: the supervisor and the agent may share
a user account, and the OS boundary covers only the launched tree.

Isolated mode is a Linux identity split. The supervisor user owns keys,
policy state, and execution records. The agent user runs the command. There
is no silent fall back to developer mode. A host administrator is outside
both claims.
"""

from __future__ import annotations

import os
import platform
import pwd
import shutil
import stat
import subprocess
import sys
from pathlib import Path

SUPERVISOR_USER = "varden-supervisor"
AGENT_USER = "varden-agent"
MONITOR_GROUP = "varden-monitor"
STATE_DIR = Path("/var/lib/varden/authority")
WORK_ROOT = Path("/var/lib/varden/work")
LIBEXEC = Path("/usr/local/libexec/varden")
SUPERVISOR_EXEC = LIBEXEC / "supervisor-exec"
AGENT_EXEC = LIBEXEC / "agent-exec"
SUDOERS = Path("/etc/sudoers.d/varden-authority")
VENV = Path("/opt/varden-authority/venv")
REEXEC_ENV = "VARDEN_AUTHORITY_REEXEC"

DEVELOPER = "developer"
ISOLATED = "isolated"


def diagnose() -> dict[str, object]:
    """Report readiness. Configured is not a probe, and a probe is not implied."""
    system = platform.system()
    developer = {
        "model": DEVELOPER,
        "status": "available",
        "enforced": False,
        "verified_by_probe": False,
        "detail": "Developer mode is the default protected launch. It does not separate the agent user from the supervisor user.",
    }
    if system != "Linux":
        isolated = {
            "model": ISOLATED,
            "status": "unsupported",
            "enforced": False,
            "verified_by_probe": False,
            "detail": "Isolated authority is a Linux identity split. This host keeps developer mode and does not downgrade an isolated request into it.",
        }
        return {"developer": developer, "isolated": isolated, "system": system}
    supervisor = _user(SUPERVISOR_USER)
    agent = _user(AGENT_USER)
    bwrap = shutil.which("bwrap")
    problems: list[str] = []
    if not bwrap:
        problems.append("bubblewrap is not installed")
    if supervisor is None or agent is None:
        problems.append("supervisor and agent users are not provisioned")
    if not STATE_DIR.is_dir():
        problems.append("authority state directory is missing")
    elif supervisor is not None and STATE_DIR.stat().st_uid != supervisor.pw_uid:
        problems.append("authority state directory is not owned by the supervisor user")
    elif STATE_DIR.is_dir() and stat.S_IMODE(STATE_DIR.stat().st_mode) & 0o077:
        problems.append("authority state directory is group or world accessible")
    if not _readable_file(SUPERVISOR_EXEC) or not _readable_file(AGENT_EXEC):
        problems.append("authority helper commands are not installed")
    if _readable_file(SUDOERS) is False:
        problems.append("sudoers rule is not installed")
    if supervisor is not None and os.geteuid() not in {0, supervisor.pw_uid}:
        listed = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, check=False)
        if listed.returncode != 0 or str(SUPERVISOR_EXEC) not in (listed.stdout or ""):
            problems.append("the current user cannot start the supervisor identity")
    identities_ready = supervisor is not None and agent is not None and STATE_DIR.is_dir() and _readable_file(SUPERVISOR_EXEC) is True and _readable_file(AGENT_EXEC) is True and _readable_file(SUDOERS) is not False
    if identities_ready and not problems:
        status = "configured"
    elif bwrap and supervisor is None and agent is None:
        status = "available"
    else:
        status = "failed"
    return {
        "developer": developer,
        "isolated": {
            "model": ISOLATED,
            "status": status,
            "enforced": False,
            "verified_by_probe": False,
            "supervisor_user": SUPERVISOR_USER,
            "agent_user": AGENT_USER,
            "state_dir": str(STATE_DIR),
            "problems": problems,
            "detail": "Configured means the identities and ownership exist. Enforcement is a launch whose probe the agent identity fails.",
        },
        "system": system,
    }


def provision() -> int:
    """Create the two identities. This is root-only and does not start a daemon."""
    if os.geteuid() != 0:
        print("isolated authority provision must run as root. It was not started.", file=sys.stderr)
        return 1
    if platform.system() != "Linux":
        print("isolated authority provision is unsupported on this operating system.", file=sys.stderr)
        return 1
    _run(["groupadd", "--system", MONITOR_GROUP], accept_exists=True)
    _run(["useradd", "--system", "--create-home", "--shell", "/usr/sbin/nologin", SUPERVISOR_USER], accept_exists=True)
    _run(["useradd", "--system", "--create-home", "--shell", "/usr/sbin/nologin", AGENT_USER], accept_exists=True)
    _run(["usermod", "-aG", MONITOR_GROUP, SUPERVISOR_USER])
    _run(["usermod", "-aG", MONITOR_GROUP, AGENT_USER])
    supervisor = pwd.getpwnam(SUPERVISOR_USER)
    agent = pwd.getpwnam(AGENT_USER)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(STATE_DIR, supervisor.pw_uid, supervisor.pw_gid)
    os.chmod(STATE_DIR, 0o700)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    monitor = _group_gid(MONITOR_GROUP)
    os.chown(WORK_ROOT, agent.pw_uid, monitor)
    os.chmod(WORK_ROOT, 0o2770)
    _ensure_subordinate_ids(SUPERVISOR_USER)
    _ensure_subordinate_ids(AGENT_USER)
    python = _install_interpreter()
    (STATE_DIR / "python.path").write_text(python + "\n", encoding="utf-8")
    os.chown(STATE_DIR / "python.path", supervisor.pw_uid, supervisor.pw_gid)
    os.chmod(STATE_DIR / "python.path", 0o600)
    LIBEXEC.mkdir(parents=True, exist_ok=True)
    SUPERVISOR_EXEC.write_text(
        "#!/bin/sh\nset -eu\nexport VARDEN_AUTHORITY_REEXEC=1\npython=$(cat /var/lib/varden/authority/python.path)\nexec \"$python\" -m varden.cli \"$@\"\n",
        encoding="utf-8",
    )
    AGENT_EXEC.write_text("#!/bin/sh\nset -eu\nexec \"$@\"\n", encoding="utf-8")
    os.chmod(SUPERVISOR_EXEC, 0o755)
    os.chmod(AGENT_EXEC, 0o755)
    os.chown(SUPERVISOR_EXEC, 0, 0)
    os.chown(AGENT_EXEC, 0, 0)
    operator = os.environ.get("SUDO_USER") or "root"
    rules = (
        "Defaults:varden-supervisor !requiretty\n"
        "Defaults:varden-agent !requiretty\n"
        f"{operator} ALL=(varden-supervisor) NOPASSWD: {SUPERVISOR_EXEC}\n"
        f"{SUPERVISOR_USER} ALL=({AGENT_USER}) NOPASSWD: {AGENT_EXEC}\n"
    )
    temporary = Path("/tmp/varden-authority.sudoers")
    temporary.write_text(rules, encoding="utf-8")
    os.chmod(temporary, 0o440)
    checked = subprocess.run(["visudo", "-cf", str(temporary)], check=False)
    if checked.returncode != 0:
        temporary.unlink(missing_ok=True)
        print("sudoers rule was rejected. Nothing was installed.", file=sys.stderr)
        return 1
    SUDOERS.write_text(rules, encoding="utf-8")
    os.chmod(SUDOERS, 0o440)
    temporary.unlink(missing_ok=True)
    print(f"isolated authority provisioned for {operator}. No daemon was started.")
    return 0


def begin_isolated_launch(argv: list[str]) -> dict[str, object] | None:
    """Return None after replacing this process with the supervisor identity.

    A returned dict means the launch must stop. Developer mode is not used.
    """
    report = diagnose()
    isolated = report["isolated"]
    if not isinstance(isolated, dict):
        return {"ok": False, "launched": False, "state": "FAILED", "reason": "isolated authority diagnostic was unreadable", "authority_model": ISOLATED}
    if isolated.get("status") == "unsupported":
        return {
            "ok": False,
            "launched": False,
            "state": "FAILED",
            "authority_model": ISOLATED,
            "authority_status": "unsupported",
            "reason": isolated.get("detail"),
        }
    if isolated.get("status") != "configured":
        return {
            "ok": False,
            "launched": False,
            "state": "FAILED",
            "authority_model": ISOLATED,
            "authority_status": isolated.get("status"),
            "reason": "isolated authority is not configured; the command was not started. " + "; ".join(str(item) for item in isolated.get("problems") or []),
        }
    supervisor = pwd.getpwnam(SUPERVISOR_USER)
    if os.geteuid() == supervisor.pw_uid:
        if not _state_is_private(supervisor.pw_uid):
            return {
                "ok": False,
                "launched": False,
                "state": "FAILED",
                "authority_model": ISOLATED,
                "authority_status": "failed",
                "reason": "supervisor state is not private to the supervisor user; the command was not started",
            }
        return None
    if os.environ.get(REEXEC_ENV) == "1":
        return {
            "ok": False,
            "launched": False,
            "state": "FAILED",
            "authority_model": ISOLATED,
            "authority_status": "failed",
            "reason": "isolated authority re-exec did not land on the supervisor identity; developer mode was not used",
        }
    os.environ[REEXEC_ENV] = "1"
    os.execvpe(
        "sudo",
        ["sudo", "-n", "-u", SUPERVISOR_USER, "--", str(SUPERVISOR_EXEC), *argv],
        os.environ,
    )
    return {"ok": False, "launched": False, "state": "FAILED", "reason": "isolated authority re-exec returned", "authority_model": ISOLATED}


def agent_launch_prefix() -> tuple[str, ...]:
    return ("sudo", "-n", "-u", AGENT_USER, "--", str(AGENT_EXEC))


def identities() -> tuple[int, int]:
    supervisor = pwd.getpwnam(SUPERVISOR_USER)
    agent = pwd.getpwnam(AGENT_USER)
    return supervisor.pw_uid, agent.pw_uid


def _state_is_private(uid: int) -> bool:
    if not STATE_DIR.is_dir():
        return False
    info = STATE_DIR.stat()
    return info.st_uid == uid and stat.S_IMODE(info.st_mode) & 0o077 == 0


def _readable_file(path: Path) -> bool | None:
    """True or false when stat works. None when the directory is not searchable."""
    try:
        return path.is_file()
    except OSError:
        return None


def _user(name: str) -> pwd.struct_passwd | None:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def _group_gid(name: str) -> int:
    import grp
    return grp.getgrnam(name).gr_gid


def _run(argv: list[str], *, accept_exists: bool = False) -> None:
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    if completed.returncode == 0:
        return
    text = (completed.stderr or "") + (completed.stdout or "")
    if accept_exists and "already exists" in text:
        return
    raise OSError(text.strip() or f"{argv[0]} failed")


def _ensure_subordinate_ids(name: str) -> None:
    for path in (Path("/etc/subuid"), Path("/etc/subgid")):
        if not path.is_file():
            path.write_text("", encoding="utf-8")
        lines = path.read_text(encoding="utf-8").splitlines()
        if any(line.startswith(name + ":") for line in lines):
            continue
        start = 200000 + (100000 if name == AGENT_USER else 0)
        path.write_text("".join(line + "\n" for line in lines if line.strip()) + f"{name}:{start}:65536\n", encoding="utf-8")


def _install_interpreter() -> str:
    candidate = VENV / "bin" / "python"
    if candidate.is_file() and _imports_varden(candidate):
        return str(candidate)
    VENV.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    repo = Path(__file__).resolve().parents[2]
    subprocess.run([str(VENV / "bin" / "pip"), "install", "-q", "-e", str(repo)], check=True)
    if not _imports_varden(candidate):
        raise OSError("the authority interpreter cannot import varden")
    return str(candidate)


def _imports_varden(python: Path) -> bool:
    completed = subprocess.run([str(python), "-c", "import varden.monitoring_integrity.authority"], check=False)
    return completed.returncode == 0
