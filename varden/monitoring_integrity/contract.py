"""Platform-neutral supervision contract.

Assurance values describe evidence, not a platform's reputation. ``verified`` is
reserved for one live execution whose supervisor attestation still matches.
A platform row is not verified because another platform's tests passed.
"""

from __future__ import annotations

from typing import Any

# What an execution may do when the supervisor stops renewing attestation.
LIFECYCLE_CONTINUE = "continue_restricted"
LIFECYCLE_TERMINATE = "terminate"

ASSURANCE_UNSUPPORTED = "unsupported"
ASSURANCE_UNVERIFIED = "unverified"
ASSURANCE_EXPERIMENTAL = "experimental"
ASSURANCE_SCOPED = "scoped_to_launched_tree"

PROPERTIES: tuple[dict[str, Any], ...] = (
    {
        "id": "SEC-001",
        "title": "Protected asset integrity",
        "statement": "The supervised process tree cannot modify the protected monitoring file through a covered execution path.",
    },
    {
        "id": "SEC-002",
        "title": "Supervisor independence",
        "statement": "The supervised process tree cannot read the signing key or rewrite the supervisor state that hides that key.",
    },
    {
        "id": "SEC-003",
        "title": "Policy integrity",
        "statement": "The supervised process tree cannot rewrite the protected policy asset.",
    },
    {
        "id": "SEC-004",
        "title": "Approval isolation",
        "statement": "The supervised process tree cannot read the supervisor signing key.",
    },
    {
        "id": "SEC-005",
        "title": "Child containment",
        "statement": "A child created by a supported execution mechanism remains inside the same boundary.",
    },
    {
        "id": "SEC-006",
        "title": "Lifecycle enforcement",
        "statement": "Loss of a fresh attestation drops VERIFIED. Termination is claimed only after the process identity is confirmed absent.",
    },
    {
        "id": "SEC-007",
        "title": "Attestation integrity",
        "statement": "A sandboxed agent cannot mint a MAC the supervisor will accept.",
    },
    {
        "id": "SEC-008",
        "title": "Attestation freshness",
        "statement": "An expired record is not VERIFIED. Renewal is a supervisor action.",
    },
    {
        "id": "SEC-009",
        "title": "Network control",
        "statement": "Network enforcement is a separate capability from filesystem enforcement.",
    },
    {
        "id": "SEC-010",
        "title": "Honest coverage",
        "statement": "An unimplemented or unexecuted property stays unsupported or unverified.",
    },
)


def platform_matrix() -> dict[str, dict[str, str]]:
    """Static assurance for this build. No cell is ``verified``.

    macOS Seatbelt is experimental and applies to the launched tree only.
    Linux and Windows adapters exist and fail closed until a real probe on
    that operating system has succeeded. This table does not record such a probe.
    """
    return {
        "protected_filesystem": {
            "linux": ASSURANCE_UNVERIFIED,
            "macos": ASSURANCE_EXPERIMENTAL,
            "windows": ASSURANCE_UNVERIFIED,
            "other_unix": ASSURANCE_UNSUPPORTED,
        },
        "process_containment": {
            "linux": ASSURANCE_UNVERIFIED,
            "macos": ASSURANCE_EXPERIMENTAL,
            "windows": ASSURANCE_UNVERIFIED,
            "other_unix": ASSURANCE_UNSUPPORTED,
        },
        "supervisor_isolation": {
            "linux": ASSURANCE_UNVERIFIED,
            "macos": ASSURANCE_SCOPED,
            "windows": ASSURANCE_UNVERIFIED,
            "other_unix": ASSURANCE_UNSUPPORTED,
        },
        "network_egress": {
            "linux": ASSURANCE_UNSUPPORTED,
            "macos": "partial_tcp_allowlist_not_a_verified_firewall",
            "windows": ASSURANCE_UNSUPPORTED,
            "other_unix": ASSURANCE_UNSUPPORTED,
        },
        "attestation": {
            "linux": ASSURANCE_UNVERIFIED,
            "macos": ASSURANCE_SCOPED,
            "windows": ASSURANCE_UNVERIFIED,
            "other_unix": ASSURANCE_UNSUPPORTED,
        },
    }


# Attacks the production supervisor has demonstrated on this Darwin tree.
# Everything else stays NOT_EXECUTED. A later CI log may replace a cell;
# source inspection must not.
GAUNTLET_MATRIX: tuple[dict[str, str], ...] = (
    {"attack": "protected_file_write", "linux": "NOT_EXECUTED", "macos": "BLOCKED_BY_BOUNDARY", "windows": "NOT_EXECUTED"},
    {"attack": "shell_write", "linux": "NOT_EXECUTED", "macos": "BLOCKED_BY_BOUNDARY", "windows": "NOT_EXECUTED"},
    {"attack": "exec_write", "linux": "NOT_EXECUTED", "macos": "BLOCKED_BY_BOUNDARY", "windows": "NOT_EXECUTED"},
    {"attack": "child_process_write", "linux": "NOT_EXECUTED", "macos": "BLOCKED_BY_BOUNDARY", "windows": "NOT_EXECUTED"},
    {"attack": "approval_secret_read", "linux": "NOT_EXECUTED", "macos": "BLOCKED_BY_BOUNDARY", "windows": "NOT_EXECUTED"},
    {"attack": "forged_attestation", "linux": "NOT_EXECUTED", "macos": "REJECTED_BY_SUPERVISOR", "windows": "NOT_EXECUTED"},
    {"attack": "legitimate_workspace_write", "linux": "NOT_EXECUTED", "macos": "ALLOWED", "windows": "NOT_EXECUTED"},
    {"attack": "atomic_replace", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "symlink", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "native_executable", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "detached_child", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "supervisor_termination", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "network_egress_bypass", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "direct_mcp_bypass", "linux": "NOT_EXECUTED", "macos": "NOT_ENFORCEABLE", "windows": "NOT_EXECUTED"},
    {"attack": "powershell_write", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
    {"attack": "cmd_write", "linux": "NOT_EXECUTED", "macos": "NOT_EXECUTED", "windows": "NOT_EXECUTED"},
)
