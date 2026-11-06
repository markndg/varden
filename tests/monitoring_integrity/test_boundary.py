"""OS-boundary gauntlet. Attacks run in a disposable home directory."""

from __future__ import annotations

import os
import platform
import time
import uuid
from pathlib import Path

import pytest

from varden.monitoring_integrity.analysis import analyse
from varden.monitoring_integrity.approvals import ApprovalStore
from varden.monitoring_integrity.assets import AssetRegistry
from varden.monitoring_integrity.boundary import (
    BoundaryLayoutError,
    assess_posix_separation,
    evaluate_attestation,
    interceptor_claim,
    seatbelt_profile,
)
from varden.monitoring_integrity.gauntlet import _ORIGINAL, run_gauntlet


def _registry():
    registry = AssetRegistry()
    registry.load_section(
        {
            "enabled": True,
            "mode": "guarded",
            "assets": [{"id": "monitor.config", "type": "enforcement_config", "protected": True, "path": "/var/lib/varden/monitoring.json", "permitted_operations": ["read"]}],
            "grants": [
                {"id": "read_config", "operations": ["read"], "assets": ["monitor.config"], "surface": "filesystem", "sequence": 1, "authority_neutral": True},
                {"id": "reload", "operations": ["exec"], "assets": ["monitor.config"], "surface": "subprocess", "sequence": 2, "activation": True},
            ],
        },
        section_hash="boundary",
    )
    return registry


def test_linux_reference_script_does_not_apply_without_root():
    import subprocess
    script = Path(__file__).resolve().parents[2] / "deploy" / "monitoring-integrity" / "linux" / "setup-boundary.sh"
    result = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "Reference only" in result.stderr


def test_layout_rejects_a_protected_path_inside_the_workspace(tmp_path):
    with pytest.raises(BoundaryLayoutError):
        seatbelt_profile(workspace=tmp_path, protected=tmp_path / "nested", secret=tmp_path.parent / "authority")


def test_same_uid_is_not_a_posix_boundary(tmp_path):
    path = tmp_path / "monitoring.json"
    path.write_text("{}", encoding="utf-8")
    report = assess_posix_separation(path, os.getuid(), os.getuid())
    assert report["separated"] is False
    assert report["tier"] == "NOT_ENFORCEABLE"
    assert report["verified"] is False


def test_stale_or_flag_attestation_is_not_verified():
    flag = evaluate_attestation({"enabled": True, "tier": "VERIFIED"}, now=100, max_age_s=30, expected_digest="abc")
    assert flag.verified is False
    assert flag.tier == "INTERCEPTED"
    stale = evaluate_attestation(
        {"origin": "probe", "observed_at": 0, "tier": "VERIFIED", "verified": True, "digest": "abc", "mechanism": "macos_seatbelt"},
        now=100,
        max_age_s=30,
        expected_digest="abc",
    )
    assert stale.verified is False
    assert stale.tier == "UNKNOWN"
    fresh = evaluate_attestation(
        {
            "origin": "probe",
            "observed_at": time.time(),
            "tier": "VERIFIED",
            "verified": True,
            "digest": "abc",
            "mechanism": "macos_seatbelt",
            "covers": ["filesystem"],
            "scope": "scoped",
        },
        now=time.time(),
        max_age_s=30,
        expected_digest="abc",
    )
    assert fresh.verified is True
    assert fresh.os_isolation is True


def test_probe_claim_is_not_the_same_tier_as_an_interceptor(tmp_path):
    registry = _registry()
    plain = analyse(registry)
    assert plain["interruption"]["protection_tier"] == "INTERCEPTED"
    assert plain["interruption"]["protection_mechanism"] == "python_interceptor"
    claim = evaluate_attestation(
        {
            "origin": "probe",
            "observed_at": time.time(),
            "tier": "VERIFIED",
            "verified": True,
            "digest": None,
            "mechanism": "macos_seatbelt",
            "covers": ["subprocess", "filesystem", "process"],
            "scope": "scoped",
        },
        now=time.time(),
        max_age_s=30,
        expected_digest=None,
    )
    upgraded = analyse(registry, boundary=claim)
    assert upgraded["interruption"]["protection_tier"] == "VERIFIED"
    assert upgraded["interruption"]["protection_mechanism"] == "macos_seatbelt"
    assert interceptor_claim().os_isolation is False


def test_process_local_approval_secret_is_not_an_independent_authority():
    local = ApprovalStore()
    assert local.independent_authority is False
    external = ApprovalStore(b"from-supervisor", authority="external_file")
    assert external.independent_authority is True
    issued = external.issue(asset_id="monitor.config", invariant_id="INV-001", operation="write", subject_agent="agent", issuer="operator")
    ok, reason = external.consume(issued.to_dict() | {"digest": issued.digest}, asset_id="monitor.config", invariant_id="INV-001", operation="write", subject_agent="agent")
    assert ok is True and reason == "approval_consumed"
    again, replay = external.consume(issued.to_dict() | {"digest": issued.digest}, asset_id="monitor.config", invariant_id="INV-001", operation="write", subject_agent="agent")
    assert again is False and replay == "approval_replay"


def _seatbelt_host() -> bool:
    return platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").is_file()


@pytest.mark.skipif(
    not _seatbelt_host(),
    reason="macOS Seatbelt via /usr/bin/sandbox-exec is not available on this host. This skip is not a security verification.",
)
def test_seatbelt_gauntlet_blocks_native_shell_and_child_writes():
    root = Path.home() / f".varden-mip-gauntlet-{uuid.uuid4().hex}"
    try:
        report = run_gauntlet(root, launch_samples=20)
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
    by_name = {item["name"]: item for item in report["scenarios"]}
    failures = {name: item for name, item in by_name.items() if item["outcome"] == "TEST_FAILED"}
    assert not failures, failures
    for name in (
        "direct_write",
        "shell_concatenation",
        "saved_open",
        "ctypes",
        "os_exec",
        "os_spawn",
        "child_python",
        "native_executable",
        "atomic_replace",
        "symlink",
        "watchdog_termination",
        "watchdog_config",
        "policy_downgrade",
        "audit_disable",
        "notification_redirect",
        "approval_secret_unreadable",
        "control_plane_unavailable",
        "mcp_direct_connect",
        "multistep",
        "env_expansion",
        "command_substitution",
        "shell_function",
        "indirect_script",
        "relative_path",
        "encoded_exec",
        "approval_material_cannot_write",
    ):
        assert by_name[name]["outcome"] == "BLOCKED_BY_BOUNDARY", by_name[name]
        assert by_name[name]["side_effect"] is False
    assert by_name["concatenation_without_boundary"]["side_effect"] is True
    assert by_name["concatenation_without_boundary"]["outcome"] == "NOT_ENFORCEABLE"
    assert by_name["mcp_remote_files"]["outcome"] == "NOT_ENFORCEABLE"
    assert by_name["stale_attestation"]["outcome"] == "DETECTED_ONLY"
    assert report["protected_after"] == _ORIGINAL
    assert report["verified"] is True
    assert report["tier"] == "VERIFIED"
    assert all(item["ok"] for item in report["positive"])
    perf = report["performance"]
    assert perf["plain_ms"]["count"] == 20
    assert perf["seatbelt_ms"]["count"] == 20
    assert perf["seatbelt_ms"]["p99"] >= perf["seatbelt_ms"]["median"]
    print("MIP_BOUNDARY_BENCH", perf)
