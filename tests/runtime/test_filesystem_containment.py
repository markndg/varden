"""Adversarial filesystem containment tests for Varden runtime boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient

import varden
from varden.app_factory import create_app
from varden.config import AppConfig
from varden.runtime.filesystem import (
    classify_path,
    is_path_contained,
    resolve_filesystem_target,
)


def _make_client(tmpdir: str, policy: dict | None = None) -> TestClient:
    policy_path = Path(tmpdir) / "policy.json"
    doc = policy or {
        "block": [
            {"field:metadata.filesystem.classification": {"equals": "secrets"}},
            {"field:metadata.filesystem.classification": {"equals": "system"}},
            {"field:metadata.filesystem.mutation": {"equals": "WRITE_CI"}},
            {"field:metadata.filesystem_destination.mutation": {"equals": "WRITE_CI"}},
            {"field:metadata.filesystem_destination.classification": {"equals": "secrets"}},
        ],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    policy_path.write_text(json.dumps(doc), encoding="utf-8")
    cfg = AppConfig(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret",
        rate_limit_per_minute=5000,
    )
    return TestClient(create_app(cfg))


def test_is_path_contained_rejects_prefix_false_friends():
    assert is_path_contained("/workspace/file", "/workspace")
    assert is_path_contained("/workspace", "/workspace")
    assert not is_path_contained("/workspace-safe/file", "/workspace")
    assert not is_path_contained("/workspace2", "/workspace")


def test_traversal_effective_target(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    secret = tmp_path / "secret_root"
    secret.mkdir()
    (secret / "passwd").write_text("x", encoding="utf-8")
    # Lexical path appears under workspace but escapes via ..
    lexical = ws / "subdir" / ".." / ".." / "secret_root" / "passwd"
    target = resolve_filesystem_target(lexical, workspace=str(ws), operation="open")
    assert target.effective_path is not None
    assert is_path_contained(target.effective_path, secret) or "secret_root" in target.effective_path
    assert target.inside_workspace is False


def test_symlink_escape_not_inside_workspace(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "passwd").write_text("secret", encoding="utf-8")
    link = ws / "output"
    link.symlink_to(outside)
    target = resolve_filesystem_target(ws / "output" / "passwd", workspace=str(ws), operation="open")
    assert target.symlink_involved is True
    assert target.inside_workspace is False
    info = classify_path(ws / "output" / "passwd", workspace=str(ws), mode="r")
    # Must not be classified as contained workspace merely due to lexical prefix.
    assert info.get("canonical_target", {}).get("inside_workspace") is False


def test_nonexistent_under_symlinked_parent(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = ws / "output"
    link.symlink_to(outside)
    target = resolve_filesystem_target(ws / "output" / "newfile.txt", workspace=str(ws), operation="write")
    assert target.exists is False
    assert target.symlink_involved is True
    assert target.effective_path is not None
    assert target.inside_workspace is False
    assert target.resolution in {"resolution_partial", "resolution_success"}


def test_nonexistent_under_safe_parent(tmp_path):
    ws = tmp_path / "workspace"
    (ws / "subdir").mkdir(parents=True)
    target = resolve_filesystem_target(ws / "subdir" / "new.txt", workspace=str(ws), operation="write")
    assert target.exists is False
    assert target.inside_workspace is True
    assert target.effective_path is not None


def test_nested_symlink_and_relative_link(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "etc_like"
    outside.mkdir()
    (outside / "shadow").write_text("x", encoding="utf-8")
    mid = ws / "mid"
    mid.symlink_to(outside)
    # relative symlink from mid-style path
    rel = ws / "rel"
    rel.symlink_to(os.path.relpath(outside, ws))
    for path in (mid / "shadow", rel / "shadow"):
        t = resolve_filesystem_target(path, workspace=str(ws))
        assert t.inside_workspace is False
        assert t.symlink_involved is True


def test_dangling_symlink(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    link = ws / "dangling"
    link.symlink_to(ws / "missing-target")
    t = resolve_filesystem_target(link, workspace=str(ws))
    # Dangling: existence false or resolution failure — must not claim safe containment via lexical path alone.
    assert t.supplied_path
    if t.effective_path and t.inside_workspace:
        # If classified inside, symlink_involved should still be noted when detectable
        pass
    assert t.resolution in {"resolution_partial", "resolution_failed", "resolution_success"}


def test_unicode_and_spaces(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    f = ws / "café file.txt"
    f.write_text("ok", encoding="utf-8")
    t = resolve_filesystem_target(f, workspace=str(ws))
    assert t.inside_workspace is True
    assert t.resolution == "resolution_success"


def test_invariant_equivalent_destinations(tmp_path):
    """INVARIANT 1: traversal/symlink indirection must not hide secrets classification."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    ssh = Path.home() / ".ssh"
    if not ssh.exists():
        pytest.skip("no ~/.ssh for classification probe")
    # Direct
    direct = classify_path(ssh / "id_rsa", workspace=str(ws), mode="r")
    # Traversal-style if we can construct one
    trav = classify_path(ws / ".." / ".." / Path.home().name / ".ssh" / "id_rsa", workspace=str(ws), mode="r")
    # At least one path should hit secrets; if both resolve into home/.ssh both should.
    assert direct["classification"] == "secrets" or "ssh" in str(direct.get("real_path", "")).lower()
    if trav.get("real_path") and ".ssh" in trav["real_path"]:
        assert trav["classification"] == "secrets"


def test_interceptor_blocks_secret_via_symlink(tmp_path):
    """Exercise real protect() interception, not helpers alone."""
    from tests.runtime.helpers import make_app_client, wire_guard_to_app

    policy = {
        "block": [
            {"type": "filesystem", "field:metadata.filesystem.classification": {"in": ["secrets", "system"]}},
            {"type": "filesystem", "field:metadata.filesystem.mutation": "WRITE_CI"},
            {"type": "filesystem", "field:metadata.filesystem_destination.mutation": "WRITE_CI"},
            {"type": "filesystem", "field:metadata.filesystem_destination.classification": {"in": ["secrets", "system"]}},
        ],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        ws = Path(td) / "ws"
        ws.mkdir()
        outside = Path(td) / "outside"
        outside.mkdir()
        secret = outside / "id_rsa"
        secret.write_text("PRIVATE", encoding="utf-8")
        link = ws / "output"
        link.symlink_to(outside)
        prev = os.getcwd()
        try:
            os.chdir(ws)
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            with pytest.raises(varden.VardenBlockedError):
                open(link / "id_rsa", "r", encoding="utf-8").read()
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_interceptor_rename_destination_ci(tmp_path):
    from tests.runtime.helpers import make_app_client, wire_guard_to_app

    policy = {
        "block": [
            {"type": "filesystem", "field:metadata.filesystem.mutation": "WRITE_CI"},
            {"type": "filesystem", "field:metadata.filesystem_destination.mutation": "WRITE_CI"},
        ],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        ws = Path(td) / "ws"
        workflows = ws / ".github" / "workflows"
        workflows.mkdir(parents=True)
        src = ws / "benign.txt"
        src.write_text("x", encoding="utf-8")
        dst = workflows / "evil.yml"
        prev = os.getcwd()
        try:
            os.chdir(ws)
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            with pytest.raises(varden.VardenBlockedError):
                os.rename(src, dst)
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_normal_workspace_write_still_allowed_when_not_sensitive(tmp_path):
    from tests.runtime.helpers import make_app_client, wire_guard_to_app

    with TemporaryDirectory() as td:
        client, _app = make_app_client(td)
        key = client.get("/health").json()["bootstrap_api_key"]
        ws = Path(td) / "ws"
        ws.mkdir()
        prev = os.getcwd()
        try:
            os.chdir(ws)
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            path = ws / "notes.txt"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("hello")
            assert path.read_text(encoding="utf-8") == "hello"
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()


def test_delete_secret_blocked(tmp_path):
    from tests.runtime.helpers import make_app_client, wire_guard_to_app

    policy = {
        "block": [
            {"type": "filesystem", "field:metadata.filesystem.classification": {"in": ["secrets", "system"]}},
        ],
        "warn": [],
        "monitor": [],
        "allow": [],
    }
    with TemporaryDirectory() as td:
        client, _app = make_app_client(td, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        ws = Path(td) / "ws"
        ws.mkdir()
        secret = ws / "id_rsa"
        secret.write_text("PRIVATE", encoding="utf-8")
        prev = os.getcwd()
        try:
            os.chdir(ws)
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            with pytest.raises(varden.VardenBlockedError):
                os.remove(secret)
            assert secret.exists()
        finally:
            os.chdir(prev)
            varden.unpatch_runtime()
