"""Gauntlet Phase 5 — filesystem containment characterization (synthetic temps)."""

from __future__ import annotations

from pathlib import Path

from varden.runtime.filesystem import is_path_contained, resolve_filesystem_target


def test_gauntlet_symlink_escape_detected(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("x", encoding="utf-8")
    link = ws / "out"
    link.symlink_to(outside)
    target = resolve_filesystem_target(ws / "out" / "secret", workspace=str(ws), operation="open")
    assert target.symlink_involved is True
    assert target.inside_workspace is False


def test_gauntlet_prefix_false_friend_rejected():
    assert is_path_contained("/workspace/file", "/workspace")
    assert not is_path_contained("/workspace-safe/file", "/workspace")


def test_gauntlet_relative_traversal_effective_target(tmp_path: Path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    secret = tmp_path / "secret_root"
    secret.mkdir()
    (secret / "passwd").write_text("x", encoding="utf-8")
    lexical = ws / "subdir" / ".." / ".." / "secret_root" / "passwd"
    target = resolve_filesystem_target(lexical, workspace=str(ws), operation="open")
    assert target.inside_workspace is False
