"""Out-of-process monitoring integrity checks.

A caller in the agent interpreter is not an independent watchdog. This module
is meant to run as its own process, preferably as a different OS user. A
missed heartbeat is not, by itself, proof of sabotage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any


def _hash_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def evaluate_observation(observation: dict[str, Any]) -> dict[str, Any]:
    """Classify one snapshot. Does not repair anything."""
    hashes = observation.get("config_hashes") or {}
    mismatches = []
    unreadable = []
    for asset_id, row in hashes.items():
        expected = (row or {}).get("expected")
        observed = (row or {}).get("observed")
        if observed is None:
            unreadable.append(asset_id)
        elif expected and observed != expected:
            mismatches.append(asset_id)
    process_alive = observation.get("process_alive")
    heartbeat_age = observation.get("heartbeat_age_s") if "heartbeat_age_s" in observation else None
    heartbeat_limit = float(observation.get("heartbeat_limit_s") or 30)
    heartbeat_stale = "heartbeat_age_s" in observation and (heartbeat_age is None or float(heartbeat_age) > heartbeat_limit)
    attestation_age = observation.get("attestation_age_s") if "attestation_age_s" in observation else None
    attestation_limit = float(observation.get("attestation_limit_s") or 300)
    attestation_stale = "attestation_age_s" in observation and (attestation_age is None or float(attestation_age) > attestation_limit)
    reachable = observation.get("control_plane_reachable")
    audit_expected = (observation.get("audit_head") or {}).get("expected") if isinstance(observation.get("audit_head"), dict) else None
    audit_observed = (observation.get("audit_head") or {}).get("observed") if isinstance(observation.get("audit_head"), dict) else None
    audit_break = bool(audit_expected and audit_observed and audit_expected != audit_observed)

    if mismatches or audit_break:
        kind = "confirmed_tampering"
        sabotage = True
    elif process_alive is False:
        kind = "process_failure"
        sabotage = False
    elif reachable is False and process_alive is None:
        kind = "connectivity_loss"
        sabotage = False
    elif process_alive is True and heartbeat_stale:
        kind = "monitoring_degradation"
        sabotage = False
    elif heartbeat_stale and process_alive is None:
        kind = "heartbeat_missed"
        sabotage = False
    elif attestation_stale or unreadable:
        kind = "monitoring_degradation"
        sabotage = False
    else:
        kind = "ok"
        sabotage = False
    return {
        "kind": kind,
        "confirmed_sabotage": sabotage,
        "heartbeat_missed": heartbeat_stale,
        "heartbeat_is_not_proof_of_sabotage": True,
        "process_alive": process_alive,
        "config_mismatches": mismatches,
        "unreadable": unreadable,
        "attestation_stale": attestation_stale,
        "audit_break": audit_break,
        "control_plane_reachable": reachable,
        "os_isolation": False,
        "trust_boundary": "separate_process",
        "independent_of_agent_process": True,
        "limitations": [
            "This process is independent of the agent interpreter only when it is actually a different process.",
            "The same OS user can still stop this process unless the deployment uses a separate user or service manager.",
            "A missed heartbeat distinguishes neither sabotage from a crash nor a network partition.",
        ],
    }


def collect_observation(manifest: dict[str, Any]) -> dict[str, Any]:
    hashes = {}
    for asset_id, row in (manifest.get("files") or {}).items():
        path = row.get("path")
        hashes[asset_id] = {"expected": row.get("sha256"), "observed": _hash_file(path) if path else None}
    pid = manifest.get("pid")
    alive = None
    if pid:
        try:
            os.kill(int(pid), 0)
            alive = True
        except ProcessLookupError:
            alive = False
        except PermissionError:
            alive = None
        except OSError:
            alive = None
    heartbeat_path = manifest.get("heartbeat_path")
    heartbeat_age = None
    if heartbeat_path and os.path.exists(heartbeat_path):
        heartbeat_age = max(0.0, __import__("time").time() - os.path.getmtime(heartbeat_path))
    observation: dict[str, Any] = {"config_hashes": hashes}
    if manifest.get("pid"):
        observation["process_alive"] = alive
    if heartbeat_path:
        observation["heartbeat_age_s"] = heartbeat_age
        observation["heartbeat_limit_s"] = manifest.get("heartbeat_limit_s", 30)
    if "attestation_age_s" in manifest:
        observation["attestation_age_s"] = manifest.get("attestation_age_s")
        observation["attestation_limit_s"] = manifest.get("attestation_limit_s", 300)
    if manifest.get("audit_head") is not None:
        observation["audit_head"] = manifest.get("audit_head")
    if "control_plane_reachable" in manifest:
        observation["control_plane_reachable"] = manifest.get("control_plane_reachable")
    return observation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a monitoring-integrity manifest from outside the agent process")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    with open(args.manifest, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    verdict = evaluate_observation(collect_observation(manifest))
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if verdict["kind"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
