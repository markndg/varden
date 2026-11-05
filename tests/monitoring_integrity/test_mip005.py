"""Production-entry boundary evidence. A skipped or unsupported host is not a pass of OS denial."""

from __future__ import annotations

import importlib.util
import platform
import shutil
from pathlib import Path

from varden.monitoring_integrity.boundary import BoundaryLayoutError, assert_layout

ROOT = Path(__file__).resolve().parents[2]


def _production():
    path = ROOT / "demos" / "security-gauntlet" / "runner" / "production.py"
    spec = importlib.util.spec_from_file_location("gauntlet_production", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_overlapping_protected_path_is_refused_before_any_launch(tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    protected = workspace / "monitoring.json"
    protected.write_text("{}\n", encoding="utf-8")
    secret = tmp_path / "state"
    secret.mkdir()
    try:
        assert_layout(workspace=workspace, protected=protected, secret=secret)
    except BoundaryLayoutError as exc:
        assert "writable" in str(exc)
    else:
        raise AssertionError("a protected file inside the writable workspace was accepted")


def test_read_only_filesystem_errno_counts_as_denial():
    from varden.monitoring_integrity.supervisor import _is_denial

    assert _is_denial("OSError:30")
    assert _is_denial("PermissionError:1")
    assert _is_denial("FileNotFoundError:2")
    assert _is_denial("OSError") is False
    assert _is_denial("wrote") is False
    assert _is_denial("read:32") is False


def test_production_entry_records_real_outcomes_without_promoting_other_platforms():
    report = _production().run_production_boundary()
    by_name = {case["name"]: case for case in report["cases"]}
    assert report["entry_point"] == "varden run --protected"
    if platform.system() == "Darwin":
        for name in ("direct_write", "child_write", "policy_write", "symlink_write", "env_write", "read_supervisor_key"):
            case = by_name[name]
            assert case["outcome"] == "OS_DENIED", case
            assert case["launched"] is True
            assert case["before_sha256"]
            assert case["before_sha256"] == case["after_sha256"]
            assert case["attempt_note"] == "denied"
        hard = by_name["hardlink_write"]
        assert hard["outcome"] == "FAIL_CLOSED", hard
        assert hard["launched"] is False
        assert hard["before_sha256"] == hard["after_sha256"]
        assert by_name["unsupervised_same_user"]["outcome"] == "OBSERVED_OUTSIDE_BOUNDARY"
        assert by_name["containment_unavailable"]["outcome"] == "FAIL_CLOSED"
        assert by_name["containment_unavailable"]["launched"] is False
        assert by_name["tampered_attestation"]["outcome"] == "REJECTED"
        assert by_name["network_connect"]["outcome"] == "OS_DENIED"
        assert by_name["network_connect"]["capability"] == "network"
        assert ":open" not in str(by_name["network_connect"].get("attempt_note"))
        assert report["same_user_outside"] is True
    elif platform.system() == "Linux":
        for name in ("direct_write", "child_write", "policy_write", "symlink_write", "env_write", "read_supervisor_key"):
            case = by_name[name]
            assert case["before_sha256"] == case["after_sha256"], case
            assert case["outcome"] in {"OS_DENIED", "FAIL_CLOSED", "UNSUPPORTED"}, case
            if case["outcome"] == "OS_DENIED":
                assert case["launched"] is True
                assert case["attempt_note"] == "denied"
        if shutil.which("bwrap"):
            assert by_name["direct_write"]["outcome"] == "OS_DENIED", by_name["direct_write"]
            assert by_name["child_write"]["outcome"] == "OS_DENIED", by_name["child_write"]
            assert by_name["symlink_write"]["outcome"] == "OS_DENIED", by_name["symlink_write"]
            assert by_name["read_supervisor_key"]["outcome"] == "OS_DENIED", by_name["read_supervisor_key"]
            assert by_name["hardlink_write"]["outcome"] == "FAIL_CLOSED"
            assert by_name["hardlink_write"]["before_sha256"] == by_name["hardlink_write"]["after_sha256"]
            assert by_name["containment_unavailable"]["launched"] is False
            assert by_name["unsupervised_same_user"]["outcome"] == "OBSERVED_OUTSIDE_BOUNDARY"
            assert by_name["tampered_attestation"]["outcome"] == "REJECTED"
            assert by_name["network_connect"]["capability"] == "network"
    else:
        for case in report["cases"]:
            assert case.get("outcome") != "OS_DENIED" or case.get("launched") is True
            if case.get("outcome") == "OS_DENIED":
                assert case["before_sha256"] == case["after_sha256"]
