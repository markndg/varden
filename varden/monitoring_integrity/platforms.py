"""Native execution boundaries.

Each adapter reports only what it can apply on the machine that is running it.
A Linux or Windows class imported on macOS refuses to launch. Capability
declarations are not evidence that a probe has succeeded.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .boundary import BoundaryLayoutError, assert_layout, contained_environment, seatbelt_profile, write_profile

MECHANISM_DARWIN = "macos_seatbelt_experimental"
MECHANISM_LINUX = "linux_bubblewrap_unverified"
MECHANISM_WINDOWS = "windows_restricted_token_unverified"
MECHANISM_NONE = "unavailable"


@dataclass
class PreparedBoundary:
    ok: bool
    reason: str = ""
    mechanism: str = MECHANISM_NONE
    profile: Path | None = None
    prefix: tuple[str, ...] = ()
    experimental: bool = False
    limitations: tuple[str, ...] = ()


class DarwinSeatbelt:
    """Experimental Seatbelt profile. Named sandbox-exec profiles are not used."""

    mechanism = MECHANISM_DARWIN

    def prepare(self, *, workspace: Path, protected: Path, state_dir: Path, directory: Path, gateway_ports: tuple[int, ...]) -> PreparedBoundary:
        if platform.system() != "Darwin":
            return PreparedBoundary(ok=False, reason="Seatbelt is not this host; the command was not started")
        if not Path("/usr/bin/sandbox-exec").is_file():
            return PreparedBoundary(ok=False, reason="sandbox-exec is not available; the command was not started", mechanism=self.mechanism)
        try:
            text = seatbelt_profile(workspace=workspace, protected=protected, secret=state_dir, gateway_ports=gateway_ports)
        except BoundaryLayoutError as exc:
            return PreparedBoundary(ok=False, reason=str(exc), mechanism=self.mechanism)
        profile = write_profile(directory, text)
        return PreparedBoundary(
            ok=True,
            mechanism=self.mechanism,
            profile=profile,
            prefix=("/usr/bin/sandbox-exec", "-f", str(profile)),
            experimental=True,
            limitations=(
                "Seatbelt via sandbox-exec -f is experimental and probe-gated. It is not a stable Apple production API.",
                "The profile covers the launched process tree only. A same-user process started outside it is not covered.",
                "Unix-domain sockets remain available. TCP is a localhost allowlist. Remote MCP files are outside this profile.",
            ),
        )

    def spawn(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
        return subprocess.Popen(
            [*prepared.prefix, *argv],
            cwd=str(cwd),
            env=env if env is not None else contained_environment(),
            start_new_session=True,
        )

    def run_captured(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess:
        from .boundary import run_contained
        if prepared.profile is None:
            raise OSError("Seatbelt profile is missing")
        return run_contained(prepared.profile, argv, cwd=cwd)


class LinuxBubblewrap:
    """Bubblewrap namespaces when ``bwrap`` exists. Unverified until executed on Linux.

    This is not a container runtime. It is one OS tool, used only after a write
    probe fails closed. Absence of ``bwrap`` refuses the launch.
    """

    mechanism = MECHANISM_LINUX

    def prepare(self, *, workspace: Path, protected: Path, state_dir: Path, directory: Path, gateway_ports: tuple[int, ...]) -> PreparedBoundary:
        del directory, gateway_ports
        if platform.system() != "Linux":
            return PreparedBoundary(ok=False, reason="Linux boundary is not this host; the command was not started", mechanism=self.mechanism)
        bwrap = shutil.which("bwrap")
        if not bwrap:
            return PreparedBoundary(ok=False, reason="bubblewrap is not available; Linux protected execution was not started", mechanism=self.mechanism)
        try:
            assert_layout(workspace=workspace, protected=protected, secret=state_dir)
        except BoundaryLayoutError as exc:
            return PreparedBoundary(
                ok=False,
                reason=f"Linux layout refused before launch: {exc}",
                mechanism=self.mechanism,
            )
        prefix = (
            bwrap,
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--ro-bind", "/", "/",
            "--bind", str(workspace), str(workspace),
            "--tmpfs", str(state_dir),
            "--dev", "/dev",
            "--proc", "/proc",
            "--",
        )
        return PreparedBoundary(
            ok=True,
            mechanism=self.mechanism,
            prefix=prefix,
            experimental=True,
            limitations=(
                "Linux bubblewrap is implemented and unverified. A successful probe on a Linux host is required before any claim.",
                "User namespaces may be disabled. A failed probe does not launch the command.",
                "A protected path inside the writable workspace is refused. That check is not a substitute for a Linux execution.",
                "This adapter does not claim network, MCP, or same-user host isolation.",
            ),
        )

    def spawn(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
        return subprocess.Popen([*prepared.prefix, *argv], cwd=str(cwd), env=env, start_new_session=True)

    def run_captured(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess:
        return subprocess.run([*prepared.prefix, *argv], cwd=str(cwd), capture_output=True, text=True, check=False)


class WindowsRestrictedJob:
    """Restricted token plus a kill-on-close job. Unverified until executed on Windows.

    Importing this module on another operating system does not touch Win32.
    ``prepare`` refuses unless the host is Windows. The supervisor still requires
    a failed protected write and a successful workspace write before launch.
    """

    mechanism = MECHANISM_WINDOWS

    def prepare(self, *, workspace: Path, protected: Path, state_dir: Path, directory: Path, gateway_ports: tuple[int, ...]) -> PreparedBoundary:
        del workspace, protected, state_dir, directory, gateway_ports
        if sys.platform != "win32":
            return PreparedBoundary(ok=False, reason="Windows boundary is not this host; the command was not started", mechanism=self.mechanism)
        if not _windows_primitives_available():
            return PreparedBoundary(ok=False, reason="Win32 token or job APIs are not available; the command was not started", mechanism=self.mechanism)
        return PreparedBoundary(
            ok=True,
            mechanism=self.mechanism,
            experimental=True,
            limitations=(
                "Windows restricted-token enforcement is unverified until a Windows runner completes the probe.",
                "DISABLE_MAX_PRIVILEGE and a kill-on-close job are not a filesystem boundary.",
                "Launch stays fail-closed unless a pre-launch write to the protected file is denied and the file hash is unchanged.",
                "A job object controls process-tree lifetime. It is not a filesystem or network sandbox.",
            ),
        )

    def spawn(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
        del prepared
        if sys.platform != "win32":
            raise OSError("Windows spawn was called off Windows")
        return _spawn_windows(argv, cwd=cwd, env=env)

    def run_captured(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path):
        return self.spawn(prepared, argv, cwd=cwd).wait()


class UnsupportedUnix:
    mechanism = MECHANISM_NONE

    def prepare(self, *, workspace: Path, protected: Path, state_dir: Path, directory: Path, gateway_ports: tuple[int, ...]) -> PreparedBoundary:
        del workspace, protected, state_dir, directory, gateway_ports
        return PreparedBoundary(
            ok=False,
            reason=f"mandatory protection has no executed boundary on {platform.system()}; the command was not started",
            limitations=("SDK observation remains available through the explicit --observe opt-in.",),
        )

    def spawn(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
        del prepared, argv, cwd, env
        raise OSError("no execution boundary is available on this operating system")

    def run_captured(self, prepared: PreparedBoundary, argv: list[str], *, cwd: Path):
        del prepared, argv, cwd
        raise OSError("no execution boundary is available on this operating system")


def select_boundary():
    system = platform.system()
    if system == "Darwin":
        return DarwinSeatbelt()
    if system == "Linux":
        return LinuxBubblewrap()
    if system == "Windows":
        return WindowsRestrictedJob()
    return UnsupportedUnix()


def _windows_primitives_available() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes
    return hasattr(ctypes.windll, "kernel32") and hasattr(ctypes.windll, "advapi32")


def _spawn_windows(argv: list[str], *, cwd: Path, env: dict[str, str] | None) -> subprocess.Popen:
    """Launch under a restricted token and assign the process to a job.

    The caller must already have probed this same helper. This function is
    not evidence. A Windows test has to observe the protected file.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32
    CREATE_SUSPENDED = 0x00000004
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    TOKEN_DUPLICATE = 0x0002
    TOKEN_QUERY = 0x0008
    TOKEN_ASSIGN_PRIMARY = 0x0001
    DISABLE_MAX_PRIVILEGE = 0x1
    JobObjectExtendedLimitInformation = 9
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [("counters", ctypes.c_ulonglong * 6)]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    current = kernel32.GetCurrentProcess()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(current, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, ctypes.byref(token)):
        raise OSError("OpenProcessToken failed")
    restricted = wintypes.HANDLE()
    if not advapi32.CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, None, 0, None, 0, None, ctypes.byref(restricted)):
        kernel32.CloseHandle(token)
        raise OSError("CreateRestrictedToken failed")
    kernel32.CloseHandle(token)
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        kernel32.CloseHandle(restricted)
        raise OSError("CreateJobObjectW failed")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        kernel32.CloseHandle(restricted)
        raise OSError("SetInformationJobObject failed")
    command = subprocess.list2cmdline(argv)
    # CreateProcessAsUserW is resolved at runtime. The probe path uses the same
    # function, so a token that can still write the protected file fails closed
    # in the supervisor before this spawn is used for the agent.
    startup = wintypes.BYTE * 104
    si = startup()
    ctypes.memset(si, 0, ctypes.sizeof(si))
    ctypes.cast(si, ctypes.POINTER(wintypes.DWORD))[0] = ctypes.sizeof(si)
    pi = (wintypes.HANDLE * 6)()
    env_block = None
    flags = CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT
    if env:
        joined = "\0".join(f"{key}={value}" for key, value in env.items()) + "\0\0"
        env_block = ctypes.create_unicode_buffer(joined)
    created = advapi32.CreateProcessAsUserW(
        restricted, None, command, None, None, False, flags, ctypes.cast(env_block, wintypes.LPVOID) if env_block else None,
        str(cwd), si, pi,
    )
    kernel32.CloseHandle(restricted)
    if not created:
        kernel32.CloseHandle(job)
        raise OSError("CreateProcessAsUserW failed")
    process_handle = pi[0]
    thread_handle = pi[1]
    pid = int(pi[2])
    if not kernel32.AssignProcessToJobObject(job, process_handle):
        kernel32.TerminateProcess(process_handle, 1)
        kernel32.CloseHandle(thread_handle)
        kernel32.CloseHandle(process_handle)
        kernel32.CloseHandle(job)
        raise OSError("AssignProcessToJobObject failed; the process was terminated")
    kernel32.ResumeThread(thread_handle)
    kernel32.CloseHandle(thread_handle)
    return _WindowsProcess(pid=pid, process_handle=process_handle, job_handle=job, kernel32=kernel32)


class _WindowsProcess:
    """Enough of the Popen surface for the supervisor to wait and record a pid."""

    def __init__(self, *, pid: int, process_handle: int, job_handle: int, kernel32: object) -> None:
        self.pid = pid
        self._process = process_handle
        self._job = job_handle
        self._kernel32 = kernel32
        self.returncode: int | None = None

    def wait(self, timeout: float | None = None) -> int:
        kernel32 = self._kernel32
        millis = 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
        kernel32.WaitForSingleObject(self._process, millis)
        code = ctypes_dword()
        kernel32.GetExitCodeProcess(self._process, code)
        self.returncode = int(code.value)
        return self.returncode

    def poll(self) -> int | None:
        code = ctypes_dword()
        self._kernel32.GetExitCodeProcess(self._process, code)
        if int(code.value) == 259:
            return None
        self.returncode = int(code.value)
        return self.returncode


def ctypes_dword():
    from ctypes import wintypes
    return wintypes.DWORD()
