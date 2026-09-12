"""Reversibility classification for actions and resources.

Does NOT implement rollback. Classifications are approximate and conservative:
unknown is preferred over false claims of reversibility.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class Reversibility(str, Enum):
    REVERSIBLE = "reversible"
    CONDITIONALLY_REVERSIBLE = "conditionally_reversible"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


_IRREVERSIBLE_CAPS = frozenset({
    "http.write.external",
    "cloud.destroy",
    "database.admin",
    "aws.iam.modify",
    "email.send",
    "payment.execute",
})

_CONDITIONAL_CAPS = frozenset({
    "git.push",
    "aws.s3.write",
    "aws.ec2.modify",
    "database.write",
    "filesystem.write.external",
    "cloud.deploy",
})

_REVERSIBLE_CAPS = frozenset({
    "filesystem.read.workspace",
    "filesystem.write.workspace",
    "git.read",
    "git.write",
    "http.read.external",
    "subprocess.execute.local",
})


def classify_capability_reversibility(capability_name: str) -> Reversibility:
    name = str(capability_name or "").strip().lower()
    if name in _IRREVERSIBLE_CAPS or name.endswith(".destroy") or name.endswith(".delete"):
        return Reversibility.IRREVERSIBLE
    if name in _CONDITIONAL_CAPS or name.endswith(".push") or name.endswith(".write"):
        return Reversibility.CONDITIONALLY_REVERSIBLE
    if name in _REVERSIBLE_CAPS or name.endswith(".read"):
        return Reversibility.REVERSIBLE
    return Reversibility.UNKNOWN


def classify_action_reversibility(action_type: str, *, tool: str | None = None, method: str | None = None) -> Reversibility:
    at = str(action_type or "").lower()
    tool_l = str(tool or "").lower()
    method_l = str(method or "").upper()

    if at in {"http_request", "network"} and method_l in {"POST", "PUT", "PATCH", "DELETE"}:
        return Reversibility.IRREVERSIBLE
    if at in {"http_request", "network"} and method_l in {"GET", "HEAD", "OPTIONS"}:
        return Reversibility.REVERSIBLE
    if "email" in tool_l or "sendgrid" in tool_l or "smtp" in tool_l:
        return Reversibility.IRREVERSIBLE
    if any(tok in tool_l for tok in ("destroy", "delete_database", "drop table", "rm -rf")):
        return Reversibility.IRREVERSIBLE
    if at in {"filesystem_write", "file_write"} or "write" in tool_l:
        return Reversibility.CONDITIONALLY_REVERSIBLE
    if at in {"filesystem_read", "file_read"} or tool_l.startswith("open") or "read" in tool_l:
        return Reversibility.REVERSIBLE
    if "git" in tool_l and "push" in tool_l:
        return Reversibility.CONDITIONALLY_REVERSIBLE
    if at == "subprocess" or "subprocess" in tool_l:
        return Reversibility.UNKNOWN
    return Reversibility.UNKNOWN


def is_irreversible(value: str | Reversibility | None) -> bool:
    return str(value or "") == Reversibility.IRREVERSIBLE.value or value == Reversibility.IRREVERSIBLE


def reversibility_to_dict(value: Reversibility) -> dict[str, Any]:
    return {
        "classification": value.value,
        "rollback_supported": False,
        "note": "Classification only; Varden does not roll back arbitrary external side effects.",
    }
