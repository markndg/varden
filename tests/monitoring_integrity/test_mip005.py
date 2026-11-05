"""Production-entry boundary evidence. A skipped or unsupported host is not a pass of OS denial."""

from __future__ import annotations

import importlib.util
import platform
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
        assert by_name["unsupervised_same_user"]["outcome"] == "OBSERVED_OUTSIDE_BOUNDARY"
        assert by_name["containment_unavailable"]["outcome"] == "FAIL_CLOSED"
        assert by_name["containment_unavailable"]["launched"] is False
        assert by_name["tampered_attestation"]["outcome"] == "REJECTED"
        assert report["same_user_outside"] is True
    else:
        for case in report["cases"]:
            assert case.get("outcome") != "OS_DENIED" or case.get("launched") is True
            if case.get("outcome") == "OS_DENIED":
                assert case["before_sha256"] == case["after_sha256"]
