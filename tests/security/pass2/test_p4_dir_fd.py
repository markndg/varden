"""Directory-descriptor checks for patched ``os.open``.

A relative ``dir_fd`` is classified only when the descriptor is a directory
and its path names that same directory. Policy denial, an unsafe descriptor,
and a native open error are different results.
"""

from __future__ import annotations

import errno
import os
import socket
import sys

import pytest

import varden
from tests.security.pass2.test_p4_boundary_integrity import (
    _allow,
    _block,
    _guard,
    _install,
)
from varden.runtime.filesystem import directory_fd_path
from varden_sdk.sdk import _ORIGINALS, VardenBlockedError


@pytest.fixture(autouse=True)
def _reset_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()


def _open_text(path: str, dir_fd: int) -> bytes:
    opened = os.open(path, os.O_RDONLY, dir_fd=dir_fd)
    try:
        return os.read(opened, 64)
    finally:
        os.close(opened)


def test_valid_directory_descriptor_reads_the_file(tmp_path):
    folder = tmp_path / "allowed"
    folder.mkdir()
    target = folder / "notes.txt"
    target.write_text("visible")
    fd = os.open(folder, os.O_RDONLY)
    _install(_guard(), lambda action: _allow())
    try:
        assert directory_fd_path(fd) == os.path.realpath(folder)
        assert _open_text("notes.txt", fd) == b"visible"
    finally:
        os.close(fd)
    assert target.read_text() == "visible"


def test_missing_file_on_a_valid_directory_is_a_native_error(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY)
    _install(_guard(), lambda action: _allow())
    try:
        with pytest.raises(FileNotFoundError) as caught:
            os.open("no-such-notes.txt", os.O_RDONLY, dir_fd=fd)
    finally:
        os.close(fd)
    assert caught.value.errno == errno.ENOENT
    assert not isinstance(caught.value, VardenBlockedError)


def test_pipe_descriptor_is_refused_before_the_syscall(tmp_path):
    read_fd, write_fd = os.pipe()
    _install(_guard(), lambda action: _allow())
    try:
        assert directory_fd_path(read_fd) is None
        with pytest.raises(VardenBlockedError) as caught:
            os.open("notes.txt", os.O_RDONLY, dir_fd=read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)
    assert caught.value.decision.get("reason") == "filesystem_dir_fd_unresolved"
    assert not (tmp_path / "notes.txt").exists()


def test_observe_pipe_descriptor_reaches_the_native_error():
    read_fd, write_fd = os.pipe()
    varden.protect(
        base_url="http://testserver",
        api_key="k",
        emit_attestation=False,
        mode="observe",
        fail_mode="open",
    )
    try:
        with pytest.raises(OSError) as caught:
            os.open("notes.txt", os.O_RDONLY, dir_fd=read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)
    assert not isinstance(caught.value, VardenBlockedError)
    # macOS openat on a pipe returns ENOTSUP. Linux returns ENOTDIR.
    expected = errno.ENOTSUP if sys.platform == "darwin" else errno.ENOTDIR
    assert caught.value.errno == expected


def test_socket_descriptor_is_refused(tmp_path):
    sock = socket.socket()
    _install(_guard(), lambda action: _allow())
    try:
        assert directory_fd_path(sock.fileno()) is None
        with pytest.raises(VardenBlockedError) as caught:
            os.open("notes.txt", os.O_RDONLY, dir_fd=sock.fileno())
    finally:
        sock.close()
    assert caught.value.decision.get("reason") == "filesystem_dir_fd_unresolved"
    assert not (tmp_path / "notes.txt").exists()


def test_closed_descriptor_is_refused(tmp_path):
    import fcntl

    held = os.open(tmp_path, os.O_RDONLY)
    closed = fcntl.fcntl(held, fcntl.F_DUPFD, 1000)
    os.close(held)
    os.close(closed)
    _install(_guard(), lambda action: _allow())
    with pytest.raises(VardenBlockedError) as caught:
        os.open("notes.txt", os.O_RDONLY, dir_fd=closed)
    assert caught.value.decision.get("reason") == "filesystem_dir_fd_unresolved"


def test_invalid_descriptor_is_refused():
    _install(_guard(), lambda action: _allow())
    with pytest.raises(VardenBlockedError) as caught:
        os.open("notes.txt", os.O_RDONLY, dir_fd=-1)
    assert caught.value.decision.get("reason") == "filesystem_dir_fd_unresolved"
    with pytest.raises(VardenBlockedError) as caught:
        os.open("notes.txt", os.O_RDONLY, dir_fd=2**20)
    assert caught.value.decision.get("reason") == "filesystem_dir_fd_unresolved"


def test_renamed_directory_still_names_the_same_descriptor(tmp_path):
    source = tmp_path / "before"
    source.mkdir()
    target = source / "notes.txt"
    target.write_text("kept")
    fd = os.open(source, os.O_RDONLY)
    renamed = tmp_path / "after"
    os.rename(source, renamed)
    _install(_guard(), lambda action: _allow())
    try:
        named = directory_fd_path(fd)
        assert named is not None
        assert os.path.realpath(renamed) == named
        assert _open_text("notes.txt", fd) == b"kept"
    finally:
        os.close(fd)
    assert target.exists() is False
    assert (renamed / "notes.txt").read_text() == "kept"


def test_secret_directory_outside_the_workspace_is_denied(tmp_path):
    """A benign relative name must not hide a directory outside the workspace.

    Reads are enforced for secret and system paths. A directory that is merely
    outside the workspace is not a default deny; filesystem coverage stays partial.
    """
    secret_dir = tmp_path / ".ssh"
    secret_dir.mkdir()
    hidden = secret_dir / "notes.txt"
    hidden.write_text("secret-body")
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    (ordinary / "notes.txt").write_text("plain")

    def decide(action):
        info = ((action.get("metadata") or {}).get("filesystem") or {})
        if info.get("classification") == "secrets":
            return _block()
        return _allow()

    secret_fd = os.open(secret_dir, os.O_RDONLY)
    ordinary_fd = os.open(ordinary, os.O_RDONLY)
    seen = _install(_guard(), decide)
    try:
        assert _open_text("notes.txt", ordinary_fd) == b"plain"
        with pytest.raises(VardenBlockedError) as caught:
            os.open("notes.txt", os.O_RDONLY, dir_fd=secret_fd)
    finally:
        os.close(secret_fd)
        os.close(ordinary_fd)
    body = caught.value.decision
    assert body.get("reason") != "filesystem_dir_fd_unresolved"
    assert body["decision"]["action"] == "block"
    assert body["decision"]["reason"] == "no"
    with _ORIGINALS["builtins.open"](hidden, "r", encoding="utf-8") as handle:
        assert handle.read() == "secret-body"
    rendered = " ".join(str(item) for item in seen)
    assert ".ssh" in rendered
    assert "notes.txt" in rendered
