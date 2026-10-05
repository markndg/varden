"""Gauntlet Phase 4 — coverage honesty: PARTIAL must not satisfy require_coverage."""

from __future__ import annotations

from varden.runtime.coverage import (
    ENFORCED,
    NOT_ROUTED,
    OBSERVATIONAL,
    PARTIAL,
    UNCOVERED,
    UNSUPPORTED,
    CoverageRegistry,
)


def test_gauntlet_partial_does_not_satisfy_require_coverage():
    """G-COV-01: require_coverage demands ENFORCED, never PARTIAL."""
    reg = CoverageRegistry()
    reg.mark("filesystem", status=PARTIAL, active=True, applicable=True)
    reg.set_session(mode="strict", fail_mode="closed", require_coverage=["filesystem"], lock_mode=True)
    assert "filesystem" in reg.missing_required()
    ready = reg.strict_readiness()
    assert ready.get("ready") is False


def test_gauntlet_weaker_statuses_never_count_as_enforced():
    reg = CoverageRegistry()
    for status in (PARTIAL, OBSERVATIONAL, NOT_ROUTED, UNCOVERED, UNSUPPORTED):
        reg = CoverageRegistry()
        reg.mark("http.requests", status=status, active=True, applicable=True)
        reg.set_session(mode="strict", fail_mode="closed", require_coverage=["http"], lock_mode=True)
        assert "http" in reg.missing_required(), f"{status} must not satisfy require_coverage"


def test_gauntlet_enforced_satisfies_require_coverage():
    reg = CoverageRegistry()
    reg.mark("filesystem", status=ENFORCED, active=True, applicable=True, verified=True)
    reg.set_session(mode="strict", fail_mode="closed", require_coverage=["filesystem"], lock_mode=True)
    assert reg.missing_required() == []


def test_gauntlet_catalog_defaults_are_not_enforced_until_activated():
    reg = CoverageRegistry()
    for surface in reg._surfaces.values():
        if not surface.active:
            assert surface.status != ENFORCED or surface.name.startswith("mcp") is False
            # Inactive catalog entries must not claim live enforcement.
            if surface.status == ENFORCED:
                raise AssertionError(f"inactive surface {surface.name} defaults to ENFORCED")
