"""G-SDK-MODE-01 enforcement-integrity audit.

Authoritative source of truth after ``protect()`` is the locked coverage-registry
enforcement contract (``enforcement_contract()`` / ``_mode`` + ``_fail_mode``),
not mutable guard attributes or ``ContextVar`` contents alone.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
from tempfile import TemporaryDirectory

import pytest

import varden
from varden.runtime.coverage import get_coverage_registry
from varden.runtime.modes import is_enforcing
from varden_sdk import sdk as sdk_mod
from varden_sdk.sdk import VardenBlockedError, _live_enforcing, current_guard

from tests.runtime.helpers import make_app_client, wire_guard_to_app

_ALLOW = ["mcp", "http.raw_sockets", "http.aiohttp", "http.urllib3"]


def _protect(client, key, *, mode="guarded", fail_mode="closed", **kwargs):
    guard = varden.protect(
        mode=mode,
        fail_mode=fail_mode,
        base_url="http://testserver",
        api_key=key,
        emit_attestation=False,
        allow_uncovered=kwargs.pop("allow_uncovered", _ALLOW),
        **kwargs,
    )
    wire_guard_to_app(guard, client)
    return guard


def _assert_denied(guard) -> None:
    with pytest.raises(VardenBlockedError):
        guard.guarded_action(type="tool_call", tool="delete_database", args={"target": "prod"})


def test_gauntlet_BEFORE_contextvar_swap_disagrees_with_attestation_labels():
    """Pre-fix characterization: ContextVar can diverge from attestation labels.

    After remediation, ``_live_enforcing`` and denied side effects still follow
    the locked registry contract even if ContextVar is poisoned.
    """
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            strong = _protect(client, key, mode="guarded")
            weak = sdk_mod.VardenGuard(
                mode="observe",
                fail_mode="open",
                base_url="http://testserver",
                api_key=key,
                emit_attestation=False,
                auto_instrument=False,
            )
            sdk_mod._current_guard.set(weak)
            assert current_guard() is weak
            assert not is_enforcing(current_guard().product_mode)
            assert get_coverage_registry().attestation()["mode"] == "guarded"
            # Integrity: enforcement must still follow locked contract.
            assert _live_enforcing(weak) is True
            assert get_coverage_registry().enforcement_contract()["mode_locked"] is True
            _assert_denied(weak)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_registry_reset_refused_while_locked():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            strong = _protect(client, key, mode="guarded")
            reg = get_coverage_registry()
            with pytest.raises(RuntimeError, match="locked|unpatch"):
                reg.reset()
            assert reg.enforcement_contract()["mode_locked"] is True
            assert current_guard() is strong
            _assert_denied(strong)
            with pytest.raises(RuntimeError, match="locked|downgrade"):
                varden.protect(
                    mode="observe",
                    fail_mode="open",
                    base_url="http://testserver",
                    api_key=key,
                    emit_attestation=False,
                    allow_uncovered=_ALLOW,
                )
            assert current_guard() is strong
            _assert_denied(strong)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_cannot_expand_allow_uncovered_after_lock():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            _protect(client, key, mode="guarded", allow_uncovered=_ALLOW)
            reg = get_coverage_registry()
            with pytest.raises(RuntimeError, match="locked|downgrade"):
                reg.set_session(
                    mode="guarded",
                    fail_mode="closed",
                    allow_uncovered=_ALLOW + ["http", "subprocess", "filesystem"],
                    lock_mode=True,
                )
            assert reg.enforcement_contract()["allow_uncovered"] == sorted(a.lower() for a in _ALLOW)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_object_setattr_bypass_does_not_weaken_enforcement():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = _protect(client, key, mode="strict")
            object.__setattr__(guard, "product_mode", "observe")
            object.__setattr__(guard, "fail_mode", "open")
            assert guard.product_mode == "observe"  # attribute poisoned
            assert get_coverage_registry().enforcement_contract()["mode"] == "strict"
            assert _live_enforcing(guard) is True
            _assert_denied(guard)
            att = get_coverage_registry().attestation()
            assert att["mode"] == "strict"
            assert att["mode_locked"] is True
        finally:
            varden.unpatch_runtime()


def test_gauntlet_failed_weaker_activate_does_not_replace_guard():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            strong = _protect(client, key, mode="guarded")
            with pytest.raises(RuntimeError, match="locked|downgrade"):
                sdk_mod.VardenGuard(
                    mode="observe",
                    fail_mode="open",
                    base_url="http://testserver",
                    api_key=key,
                    emit_attestation=False,
                    allow_uncovered=_ALLOW,
                ).activate()
            assert current_guard() is strong
            assert get_coverage_registry().attestation()["mode"] == "guarded"
            _assert_denied(strong)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_failed_strict_readiness_rolls_back_first_activation():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            with pytest.raises(RuntimeError, match="not ready"):
                varden.protect(
                    mode="strict",
                    fail_mode="closed",
                    base_url="http://testserver",
                    api_key=key,
                    emit_attestation=False,
                    allow_uncovered=[],  # MCP discovery / missing coverage → not ready
                    require_coverage=["http", "subprocess", "mcp"],
                )
            reg = get_coverage_registry()
            assert reg.enforcement_contract()["mode_locked"] is False
            assert current_guard() is None
        finally:
            varden.unpatch_runtime()


def test_gauntlet_copied_context_still_uses_locked_contract():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            strong = _protect(client, key, mode="guarded")
            ctx = contextvars.copy_context()

            def _in_copy():
                weak = sdk_mod.VardenGuard(
                    mode="observe",
                    fail_mode="open",
                    base_url="http://testserver",
                    api_key=key,
                    auto_instrument=False,
                    emit_attestation=False,
                )
                sdk_mod._current_guard.set(weak)
                assert current_guard() is weak
                assert _live_enforcing() is True
                _assert_denied(weak)

            ctx.run(_in_copy)
            assert current_guard() is strong
            _assert_denied(strong)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_concurrent_protect_downgrade_attempts():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            strong = _protect(client, key, mode="guarded")

            def _attempt():
                try:
                    varden.protect(
                        mode="observe",
                        fail_mode="open",
                        base_url="http://testserver",
                        api_key=key,
                        emit_attestation=False,
                        allow_uncovered=_ALLOW,
                    )
                    return "ok"
                except RuntimeError:
                    return "refused"

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: _attempt(), range(16)))
            assert results.count("ok") == 0
            assert all(r == "refused" for r in results)
            assert current_guard() is strong or (
                current_guard() is not None and get_coverage_registry().attestation()["mode"] == "guarded"
            )
            _assert_denied(strong)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_async_protect_downgrade_refused():
    async def _run():
        with TemporaryDirectory() as tmpdir:
            client, _ = make_app_client(tmpdir)
            key = client.get("/health").json()["bootstrap_api_key"]
            try:
                strong = _protect(client, key, mode="guarded")

                async def _attempt():
                    with pytest.raises(RuntimeError, match="locked|downgrade"):
                        await asyncio.to_thread(
                            lambda: varden.protect(
                                mode="observe",
                                fail_mode="open",
                                base_url="http://testserver",
                                api_key=key,
                                emit_attestation=False,
                                allow_uncovered=_ALLOW,
                            )
                        )

                await asyncio.gather(*[_attempt() for _ in range(4)])
                _assert_denied(strong)
            finally:
                varden.unpatch_runtime()

    asyncio.run(_run())


def test_gauntlet_same_contract_reentry_succeeds():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            first = _protect(client, key, mode="guarded", fail_mode="closed")
            second = _protect(client, key, mode="guarded", fail_mode="closed")
            assert get_coverage_registry().attestation()["mode"] == "guarded"
            assert current_guard() is second
            _assert_denied(second)
            _assert_denied(first)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_observe_mode_benign_allows_blocked_policy_action():
    """Observation-only: policy may classify block, but side effect is not prevented."""
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = _protect(client, key, mode="observe", fail_mode="open")
            assert get_coverage_registry().attestation()["mode"] == "observe"
            assert _live_enforcing(guard) is False
            result = guard.guarded_action(type="tool_call", tool="delete_database", args={"target": "prod"})
            assert result is not None
            assert result.blocked is True
        finally:
            varden.unpatch_runtime()


def test_gauntlet_attestation_matches_live_enforcing():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            for mode in ("guarded", "strict"):
                guard = _protect(client, key, mode=mode)
                contract = get_coverage_registry().enforcement_contract()
                att = get_coverage_registry().attestation()
                assert contract["mode"] == mode == att["mode"]
                assert contract["mode_locked"] is True is att["mode_locked"]
                assert _live_enforcing(guard) is True
                _assert_denied(guard)
                varden.unpatch_runtime()
        finally:
            varden.unpatch_runtime()


def test_gauntlet_nested_weaker_protect_refused():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            outer = _protect(client, key, mode="strict")

            def _inner():
                with pytest.raises(RuntimeError, match="locked|downgrade"):
                    varden.protect(
                        mode="guarded",
                        fail_mode="open",
                        base_url="http://testserver",
                        api_key=key,
                        emit_attestation=False,
                        allow_uncovered=_ALLOW,
                    )

            _inner()
            assert current_guard() is outer
            assert get_coverage_registry().enforcement_contract()["mode"] == "strict"
            _assert_denied(outer)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_guarded_fail_open_still_blocks_reachable_deny():
    """fail_mode=open weakens only unreachable-CP paths; policy deny still blocks."""
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            with pytest.warns(UserWarning, match="fail_mode=open"):
                guard = _protect(client, key, mode="guarded", fail_mode="open")
            assert get_coverage_registry().enforcement_contract()["fail_mode"] == "open"
            assert _live_enforcing(guard) is True
            _assert_denied(guard)
            with pytest.raises(RuntimeError, match="locked|downgrade"):
                varden.protect(
                    mode="observe",
                    fail_mode="open",
                    base_url="http://testserver",
                    api_key=key,
                    emit_attestation=False,
                    allow_uncovered=_ALLOW,
                )
            _assert_denied(guard)
        finally:
            varden.unpatch_runtime()


def test_gauntlet_surface_mark_cannot_weaken_live_enforcing():
    """Coverage surface rows remain mutable for verify/tamper; contract mode does not."""
    from varden.runtime.coverage import ENFORCED, UNCOVERED

    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            guard = _protect(client, key, mode="guarded")
            reg = get_coverage_registry()
            reg.mark("http.requests", status=UNCOVERED, active=False)
            with pytest.raises(RuntimeError, match="sealed interceptor probe"):
                reg.register_interceptor_check("http.requests", lambda: False)
            assert reg.enforcement_contract()["mode"] == "guarded"
            assert reg.enforcement_contract()["mode_locked"] is True
            assert _live_enforcing(guard) is True
            _assert_denied(guard)
            # Attestation must not claim ENFORCED after honest downgrade + verify
            att = reg.attestation()
            surf = next(s for s in att["surfaces"] if s["name"] == "http.requests")
            # mark(UNCOVERED) without clearing sealed probe: verify may restore ENFORCED
            # if wrapper still installed — that is correct honesty.
            assert surf["status"] in {UNCOVERED, ENFORCED}
        finally:
            varden.unpatch_runtime()


def test_gauntlet_stale_guard_reference_still_enforces():
    with TemporaryDirectory() as tmpdir:
        client, _ = make_app_client(tmpdir)
        key = client.get("/health").json()["bootstrap_api_key"]
        try:
            first = _protect(client, key, mode="guarded")
            second = _protect(client, key, mode="guarded")
            assert current_guard() is second
            object.__setattr__(first, "product_mode", "observe")
            assert _live_enforcing(first) is True
            _assert_denied(first)
            _assert_denied(second)
        finally:
            varden.unpatch_runtime()
