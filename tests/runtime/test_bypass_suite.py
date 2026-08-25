"""Adversarial / bypass classification suite for the runtime boundary."""

from __future__ import annotations

import socket
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

import varden
from varden.runtime.coverage import UNCOVERED, get_coverage_registry
from tests.runtime.helpers import make_app_client, wire_guard_to_app


def test_saved_subprocess_reference_bypass_is_documented():
    """Saved pre-protect Popen references can bypass monkeypatching — uncovered limitation."""
    from subprocess import Popen as saved_popen

    with TemporaryDirectory() as tmpdir:
        client, app = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            # Original Popen class reference bypasses GuardedPopen wrapper.
            proc = saved_popen(["/usr/bin/true"], stdout=-1, stderr=-1)
            proc.wait()
            assert proc.returncode == 0
            att = get_coverage_registry().attestation()
            sub = next(s for s in att["surfaces"] if s["name"] == "subprocess")
            assert any("pre-patch" in lim.lower() or "Saved" in lim for lim in sub["limitations"])
        finally:
            varden.unpatch_runtime()


def test_raw_socket_reported_uncovered():
    with TemporaryDirectory() as tmpdir:
        client, app = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            s = socket.socket()
            s.close()
            surf = get_coverage_registry().get("http.raw_sockets")
            assert surf is not None
            assert surf.status == UNCOVERED
        finally:
            varden.unpatch_runtime()


def test_import_before_and_after_protect():
    import requests  # noqa: F401 — import before

    with TemporaryDirectory() as tmpdir:
        policy = {
            "block": [{"type": "http_request", "field:url": {"contains": "evil.example"}}],
            "warn": [],
            "monitor": [],
            "allow": [],
        }
        client, app = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
            wire_guard_to_app(guard, client)
            import requests as req2

            with pytest.raises(varden.VardenBlockedError):
                req2.get("https://evil.example/x", timeout=1)
        finally:
            varden.unpatch_runtime()


def test_observe_mode_does_not_raise_from_guarded_action():
    with TemporaryDirectory() as tmpdir:
        policy = {
            "block": [{"type": "http_request", "field:url": {"contains": "evil.example"}}],
            "warn": [],
            "monitor": [],
            "allow": [],
        }
        client, app = make_app_client(tmpdir, policy=policy)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = varden.protect(
                base_url="http://testserver",
                api_key=key,
                mode="observe",
                emit_attestation=False,
            )
            wire_guard_to_app(guard, client)
            result = guard.guarded_action(
                type="http_request",
                tool="requests",
                url="https://evil.example/x",
                method="GET",
                args={},
                payload={},
            )
            assert result is not None
            assert result.blocked
            assert guard.product_mode == "observe"
        finally:
            varden.unpatch_runtime()
