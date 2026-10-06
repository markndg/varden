"""G-COV-ATTEST-01 / G-PATCH-LIFE-01 — coverage attestation & monkeypatch lifecycle."""

from __future__ import annotations

from tempfile import TemporaryDirectory

import pytest
import requests

import varden
from varden.runtime.coverage import ENFORCED, UNCOVERED, get_coverage_registry
from varden_sdk import sdk as sdk_mod
from varden_sdk.sdk import VardenBlockedError

from tests.runtime.helpers import make_app_client, wire_guard_to_app

_ALLOW = ["mcp", "http.raw_sockets", "http.aiohttp", "http.urllib3"]


def _protect(client, key):
    guard = varden.protect(
        mode="guarded",
        fail_mode="closed",
        base_url="http://testserver",
        api_key=key,
        emit_attestation=False,
        allow_uncovered=_ALLOW,
    )
    wire_guard_to_app(guard, client)
    return guard


def test_gauntlet_BEFORE_false_enforced_via_mark_and_poisoned_probe_is_blocked():
    """Pre-fix characterization retained: poison path must not yield ENFORCED."""
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            _protect(client, key)
            reg = get_coverage_registry()
            orig = sdk_mod._ORIGINALS["requests.sessions.Session.request"]
            requests.sessions.Session.request = orig
            # Honest verify drops ENFORCED
            v1 = reg.verify()
            assert v1["ok"] is False
            surf = reg.get("http.requests")
            assert surf is not None and surf.status == UNCOVERED
            # Poison attempts
            with pytest.raises(RuntimeError, match="sealed interceptor probe|live sealed"):
                reg.register_interceptor_check("http.requests", lambda: True)
            with pytest.raises(RuntimeError, match="ENFORCED|sealed|probe"):
                reg.mark("http.requests", status=ENFORCED, active=True, interceptor="fake")
            att = reg.attestation()
            surf2 = next(s for s in att["surfaces"] if s["name"] == "http.requests")
            assert surf2["status"] != ENFORCED
            assert surf2.get("verified") is not True
        finally:
            varden.unpatch_runtime()


def test_gauntlet_restore_original_clears_enforced_attestation_and_readiness():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = _protect(client, key)
            reg = get_coverage_registry()
            assert reg.get("http.requests").status == ENFORCED
            assert reg.get("http.requests").verified is True
            # Denied side effect still blocked while patched
            with pytest.raises(VardenBlockedError):
                guard.guarded_action(type="tool_call", tool="delete_database", args={"target": "prod"})
            # Third-party style restore
            requests.sessions.Session.request = sdk_mod._ORIGINALS["requests.sessions.Session.request"]
            att = reg.attestation()
            surf = next(s for s in att["surfaces"] if s["name"] == "http.requests")
            assert surf["status"] == UNCOVERED
            assert surf["verified"] is False
            assert surf["installed"] is True
            # Tool-path deny still uses locked contract (not http wrapper)
            with pytest.raises(VardenBlockedError):
                guard.guarded_action(type="tool_call", tool="delete_database", args={"target": "prod"})
        finally:
            varden.unpatch_runtime()


def test_gauntlet_reconcile_rewraps_restored_original_once():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            _protect(client, key)
            orig = sdk_mod._ORIGINALS["requests.sessions.Session.request"]
            wrapper = sdk_mod._WRAPPERS["requests.sessions.Session.request"]
            requests.sessions.Session.request = orig
            assert requests.sessions.Session.request is orig
            # Same-contract re-entry triggers reconcile
            varden.protect(
                mode="guarded",
                fail_mode="closed",
                base_url="http://testserver",
                api_key=key,
                emit_attestation=False,
                allow_uncovered=_ALLOW,
            )
            assert requests.sessions.Session.request is wrapper
            reg = get_coverage_registry()
            att = reg.attestation()
            surf = next(s for s in att["surfaces"] if s["name"] == "http.requests")
            assert surf["status"] == ENFORCED
            assert surf["verified"] is True
        finally:
            varden.unpatch_runtime()


def test_gauntlet_foreign_wrapper_does_not_repatch_loop():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            _protect(client, key)
            orig = sdk_mod._ORIGINALS["requests.sessions.Session.request"]

            def foreign(self, method, url, *args, **kwargs):
                return orig(self, method, url, *args, **kwargs)

            requests.sessions.Session.request = foreign
            before = requests.sessions.Session.request
            varden.protect(
                mode="guarded",
                fail_mode="closed",
                base_url="http://testserver",
                api_key=key,
                emit_attestation=False,
                allow_uncovered=_ALLOW,
            )
            # Must not fight foreign wrapper (no repatch loop)
            assert requests.sessions.Session.request is before
            att = get_coverage_registry().attestation()
            surf = next(s for s in att["surfaces"] if s["name"] == "http.requests")
            assert surf["status"] != ENFORCED
        finally:
            varden.unpatch_runtime()
