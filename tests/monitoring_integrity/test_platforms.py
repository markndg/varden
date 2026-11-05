"""Cross-platform assurance stays honest on a machine that has not run the other OS."""

from __future__ import annotations

import platform

from varden.monitoring_integrity.contract import GAUNTLET_MATRIX, platform_matrix
from varden.monitoring_integrity.platforms import LinuxBubblewrap, UnsupportedUnix, WindowsRestrictedJob, select_boundary


def test_matrix_does_not_call_any_platform_verified():
    matrix = platform_matrix()
    assert matrix["protected_filesystem"]["linux"] == "unverified"
    assert matrix["protected_filesystem"]["windows"] == "unverified"
    assert matrix["protected_filesystem"]["macos"] == "experimental"
    assert matrix["supervisor_isolation"]["macos"] == "scoped_to_launched_tree"
    assert matrix["network_egress"]["macos"] != "verified"
    assert "verified" not in {value for row in matrix.values() for value in row.values()}


def test_linux_and_windows_rows_are_not_executed_from_this_tree():
    for row in GAUNTLET_MATRIX:
        assert row["linux"] == "NOT_EXECUTED"
        assert row["windows"] == "NOT_EXECUTED"


def test_off_host_adapters_refuse_to_prepare(tmp_path):
    kwargs = dict(workspace=tmp_path, protected=tmp_path / "asset.json", state_dir=tmp_path / "state", directory=tmp_path / "exec", gateway_ports=())
    if platform.system() != "Linux":
        refused = LinuxBubblewrap().prepare(**kwargs)
        assert refused.ok is False
        assert refused.mechanism.startswith("linux_")
    if platform.system() != "Windows":
        refused = WindowsRestrictedJob().prepare(**kwargs)
        assert refused.ok is False
    if platform.system() == "Darwin":
        assert select_boundary().__class__.__name__ == "DarwinSeatbelt"
    else:
        assert UnsupportedUnix().prepare(**kwargs).ok is False
