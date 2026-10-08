"""Human approval writes a candidate through Varden's normal policy path.

Approval validates the merged document, writes it with the same atomic helper
the control plane uses, and updates the live engine. A candidate cannot do
this by itself.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from varden.fsutil import atomic_write_json

from . import lifecycle

ENFORCING = frozenset({"block", "require_approval"})


class ApprovalError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def rule_present(policy: dict[str, Any], rule_id: str) -> str | None:
    for bucket in ("block", "require_approval", "sanitise", "warn", "monitor", "allow"):
        for rule in policy.get(bucket) or []:
            if isinstance(rule, dict) and rule.get("id") == rule_id:
                return bucket
    return None


def merge_rule(policy: dict[str, Any], rule: dict[str, Any], bucket: str) -> tuple[dict[str, Any], bool]:
    """Return (policy, already_present). Does not write."""
    if bucket not in {"block", "require_approval", "warn", "monitor"}:
        raise ApprovalError(f"refusing to place a threat-intelligence rule in {bucket}")
    merged = json.loads(json.dumps(policy))
    for name in ("block", "warn", "monitor", "allow"):
        if not isinstance(merged.get(name), list):
            merged[name] = []
    if not isinstance(merged.get(bucket), list):
        merged[bucket] = []
    existing = rule_present(merged, str(rule.get("id") or ""))
    if existing:
        return merged, True
    merged[bucket] = list(merged[bucket]) + [rule]
    return merged, False


def apply_approved_rule(
    *,
    policy_engine: Any,
    policy_file: str,
    rule: dict[str, Any],
    bucket: str,
    actor: str,
) -> dict[str, Any]:
    """Validate and publish one rule. Raises ApprovalError on refusal."""
    path = Path(policy_file)
    if not path.exists():
        raise ApprovalError(f"policy file {policy_file} does not exist; refusing to create one implicitly")
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApprovalError(f"policy file is not readable JSON: {exc}") from exc
    if not isinstance(current, dict):
        raise ApprovalError("policy file must contain an object")
    merged, already = merge_rule(current, rule, bucket)
    validation = policy_engine.validate(merged, for_publish=True)
    if not validation.get("valid"):
        raise ApprovalError("merged policy failed validation: " + "; ".join(validation.get("errors") or []))
    if not already:
        atomic_write_json(path, merged)
        policy_engine.update_policy(merged)
        snapshot_id = policy_engine.snapshot(
            f"threat-intelligence:{rule.get('id')}",
            created_by=actor or "threat-intelligence",
            status="published",
        )
    else:
        snapshot_id = None
        policy_engine.update_policy(merged)
    return {
        "rule_id": rule.get("id"),
        "bucket": bucket,
        "already_present": already,
        "snapshot_id": snapshot_id,
        "policy_file": str(path),
        "written_at": time.time(),
        "enforcing": bucket in ENFORCING,
    }


def next_states_after_approval(bucket: str) -> list[str]:
    if bucket in ENFORCING:
        return [lifecycle.APPROVED, lifecycle.ENFORCED]
    return [lifecycle.APPROVED, lifecycle.OBSERVE]
