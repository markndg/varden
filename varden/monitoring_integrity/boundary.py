"""Independent enforcement boundary for monitoring integrity.

Python monkeypatches stay in place for semantic decisions. They are not this
boundary. A mandatory claim requires a deny-by-default OS policy applied by a
supervisor before the agent runs, plus a probe that shows the protected bytes
did not change.

On Darwin the tested mechanism is Seatbelt (``sandbox-exec``). It covers the
process tree the supervisor launches. It does not cover an unsandboxed process
of the same user. On Linux the reference mechanism is a separate Unix user and
directory permissions. That reference is not treated as tested on Darwin.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Coverage vocabulary already used by the runtime registry.
# These tiers are the assurance of a MIP claim. They do not replace a surface
# status, and INTERCEPTED is not coverage ENFORCED.
TIER_OBSERVED = "OBSERVED"
TIER_INTERCEPTED = "INTERCEPTED"
TIER_BOUNDARY = "BOUNDARY_ENFORCED"
TIER_VERIFIED = "VERIFIED"
TIER_UNKNOWN = "UNKNOWN"
TIER_NOT_ENFORCEABLE = "NOT_ENFORCEABLE"

COVERAGE_FOR_TIER = {
    TIER_OBSERVED: "OBSERVATIONAL",
    TIER_INTERCEPTED: "PARTIAL",
    TIER_BOUNDARY: "PARTIAL",
    TIER_VERIFIED: "PARTIAL",
    TIER_UNKNOWN: "UNCOVERED",
    TIER_NOT_ENFORCEABLE: "NOT_ROUTED",
}

MECHANISM_INTERCEPTOR = "python_interceptor"
MECHANISM_SEATBELT = "macos_seatbelt"
MECHANISM_POSIX = "linux_posix_dac"

# Writable locations a Darwin agent needs for a normal interpreter.
# A protected path inside one of these cannot be sealed by omitting it from
# the allow list, so the layout is rejected instead of claimed.
_DARWIN_WRITE_ROOTS = ("/dev", "/private/var/folders")
_UNSAFE_PROFILE_CHARS = set('"()\n\r')

SEATBELT_COVERS = ("filesystem", "subprocess", "process", "signal", "network", "secret")
SCOPE_SEATBELT = (
    "Seatbelt applies only to processes the supervisor launched under this profile, "
    "and to their descendants. An unsandboxed process running as the same user is outside it. "
    "A remote MCP server's files are outside it."
)


class BoundaryLayoutError(ValueError):
    """The protected path cannot be separated from a writable prefix."""


@dataclass(frozen=True)
class BoundaryClaim:
    tier: str
    mechanism: str
    covers: tuple[str, ...]
    verified: bool
    origin: str
    scope: str
    os_isolation: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "mechanism": self.mechanism,
            "covers": list(self.covers),
            "verified": self.verified,
            "origin": self.origin,
            "scope": self.scope,
            "os_isolation": self.os_isolation,
            "coverage_status": COVERAGE_FOR_TIER.get(self.tier, "UNCOVERED"),
        }


def interceptor_claim() -> BoundaryClaim:
    return BoundaryClaim(
        tier=TIER_INTERCEPTED,
        mechanism=MECHANISM_INTERCEPTOR,
        covers=(),
        verified=False,
        origin="default",
        scope="In-process hooks can block a patched call. Equivalent-authority code can bypass them.",
        os_isolation=False,
    )


def evaluate_attestation(
    record: dict[str, Any] | None,
    *,
    now: float,
    max_age_s: float,
    expected_digest: str | None,
) -> BoundaryClaim:
    """Accept a probe record only when it is fresh, matching, and probe-originated.

    A configuration flag, a stale file, or a record the agent could have written
    is not a verification. This function does not itself prove who wrote the record.
    """
    if not isinstance(record, dict) or record.get("origin") != "probe":
        return interceptor_claim()
    observed = record.get("observed_at")
    try:
        age = now - float(observed)
    except (TypeError, ValueError):
        return BoundaryClaim(
            tier=TIER_UNKNOWN,
            mechanism=str(record.get("mechanism") or "unknown"),
            covers=(),
            verified=False,
            origin="probe",
            scope="The attestation has no usable timestamp.",
            os_isolation=False,
        )
    if age < 0 or age > max_age_s:
        return BoundaryClaim(
            tier=TIER_UNKNOWN,
            mechanism=str(record.get("mechanism") or "unknown"),
            covers=(),
            verified=False,
            origin="probe",
            scope="The attestation is stale. Stale evidence is not verification.",
            os_isolation=False,
        )
    if expected_digest is not None and record.get("digest") != expected_digest:
        return BoundaryClaim(
            tier=TIER_UNKNOWN,
            mechanism=str(record.get("mechanism") or "unknown"),
            covers=(),
            verified=False,
            origin="probe",
            scope="The attestation digest does not match the protected file.",
            os_isolation=False,
        )
    if record.get("verified") is not True or record.get("tier") != TIER_VERIFIED:
        return BoundaryClaim(
            tier=TIER_BOUNDARY if record.get("tier") == TIER_BOUNDARY else TIER_UNKNOWN,
            mechanism=str(record.get("mechanism") or "unknown"),
            covers=tuple(record.get("covers") or ()),
            verified=False,
            origin="probe",
            scope=str(record.get("scope") or "The probe did not verify the boundary."),
            os_isolation=False,
        )
    return BoundaryClaim(
        tier=TIER_VERIFIED,
        mechanism=str(record.get("mechanism") or MECHANISM_SEATBELT),
        covers=tuple(record.get("covers") or SEATBELT_COVERS),
        verified=True,
        origin="probe",
        scope=str(record.get("scope") or SCOPE_SEATBELT),
        os_isolation=True,
    )


def assess_posix_separation(path: str | Path, agent_uid: int, watchdog_uid: int) -> dict[str, Any]:
    """Report whether Unix ownership would keep ``agent_uid`` from writing ``path``.

    This is a check of the inode, not a launch. On a host where the agent uid
    owns the file, the result is not a boundary.
    """
    st = os.stat(path)
    mode = stat_mode(st.st_mode)
    other_writable = bool(mode & 0o002)
    group_writable = bool(mode & 0o020)
    agent_owns = st.st_uid == agent_uid
    separated = (not agent_owns) and (not other_writable) and agent_uid != watchdog_uid
    # Group write is only safe when the agent is not in that group. We cannot
    # know the agent's groups from the inode, so group-writable is not separated.
    if group_writable:
        separated = False
    return {
        "mechanism": MECHANISM_POSIX,
        "separated": separated,
        "agent_owns_file": agent_owns,
        "other_writable": other_writable,
        "group_writable": group_writable,
        "watchdog_uid_distinct": agent_uid != watchdog_uid,
        "tier": TIER_BOUNDARY if separated else TIER_NOT_ENFORCEABLE,
        "verified": False,
        "scope": (
            "POSIX separation holds for every process of the agent uid, including processes "
            "this supervisor did not launch. It is not established when the agent owns the file."
        ),
    }


def stat_mode(mode: int) -> int:
    return mode & 0o777


def _realpath(path: str | Path) -> Path:
    return Path(path).resolve()


def _reject_profile_text(path: Path) -> None:
    text = str(path)
    if any(char in text for char in _UNSAFE_PROFILE_CHARS):
        raise BoundaryLayoutError(f"path cannot be embedded in a seatbelt profile: {path}")


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def assert_layout(*, workspace: Path, protected: Path, secret: Path) -> None:
    workspace = _realpath(workspace)
    protected = _realpath(protected)
    secret = _realpath(secret)
    for path in (workspace, protected, secret):
        _reject_profile_text(path)
    write_roots = [_realpath(item) for item in _DARWIN_WRITE_ROOTS if Path(item).exists()]
    write_roots.append(workspace)
    for label, path in (("protected", protected), ("secret", secret)):
        for root in write_roots:
            if path == root or _inside(path, root):
                raise BoundaryLayoutError(f"{label} path {path} is inside writable prefix {root}")
    if protected == secret or _inside(secret, protected) or _inside(protected, secret):
        raise BoundaryLayoutError("the approval secret must not share a directory with the protected asset")
    assert_single_directory_entry(protected, label="protected file")


def assert_single_directory_entry(path: Path, *, label: str) -> None:
    """Refuse a file that has another hard link.

    The macOS profile and the Linux mount rules name paths. A second directory
    entry is the same inode, so a writable path can change or reveal that file
    without matching the protected path. The supervisor does not start the
    command. This does not stop a same-user process that creates a link after
    the check.
    """
    if not path.is_file():
        return
    try:
        links = path.stat().st_nlink
    except OSError as exc:
        raise BoundaryLayoutError(f"{label} could not be inspected; the command was not started") from exc
    if links != 1:
        raise BoundaryLayoutError(f"{label} has {links} directory entries; the command was not started")


def seatbelt_profile(
    *,
    workspace: str | Path,
    protected: str | Path,
    secret: str | Path,
    gateway_ports: tuple[int, ...] = (),
) -> str:
    """Deny-by-default profile. ``(allow default)`` is intentionally absent.

    Explicit denies do not override ``(allow default)`` on this kernel, so
    protection is the absence of a write allow for the protected path.
    """
    workspace_p = _realpath(workspace)
    protected_p = _realpath(protected)
    secret_p = _realpath(secret)
    assert_layout(workspace=workspace_p, protected=protected_p, secret=secret_p)
    network = "\n".join(
        f'(allow network-outbound (remote tcp "localhost:{int(port)}"))' for port in gateway_ports
    )
    return f"""(version 1)
(deny default)
(allow file-read* (require-not (subpath "{secret_p}")))
(allow file-map-executable)
(allow file-ioctl)
(allow file-write* (subpath "{workspace_p}"))
(allow file-write* (subpath "/dev"))
(allow file-write* (subpath "/private/var/folders"))
(allow process*)
(allow signal (target self))
(allow signal (target children))
(allow sysctl-read)
(allow mach*)
(allow ipc*)
(allow system-socket)
{network}
"""


def write_profile(directory: Path, profile: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "agent.sb"
    path.write_text(profile, encoding="utf-8")
    return path


def contained_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    env.pop("VARDEN_MIP_APPROVAL_SECRET", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_contained(
    profile: Path,
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    if not Path("/usr/bin/sandbox-exec").exists():
        raise FileNotFoundError("sandbox-exec is not available")
    return subprocess.run(
        ["/usr/bin/sandbox-exec", "-f", str(profile), *argv],
        capture_output=True,
        text=True,
        env=contained_environment(env),
        cwd=str(cwd) if cwd else None,
        check=False,
    )


def denial_text(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stderr or ''}\n{result.stdout or ''}"


def classified_file_attempt(
    *,
    before: str,
    after: str,
    result: subprocess.CompletedProcess[str],
    launched_in_boundary: bool,
) -> str:
    """Map an attempt to an outcome. A crash or an unrelated error is not a block."""
    if not launched_in_boundary:
        return "NOT_ENFORCEABLE"
    if before != after:
        return "TEST_FAILED"
    if result.returncode < 0:
        return "TEST_FAILED"
    text = denial_text(result)
    if result.returncode != 0 and ("Operation not permitted" in text or "PermissionError" in text):
        return "BLOCKED_BY_BOUNDARY"
    return "TEST_FAILED"
