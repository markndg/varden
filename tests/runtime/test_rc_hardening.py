"""Release-candidate regression tests for coverage contract + CLI JSON purity."""

from __future__ import annotations

import io
import json
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from varden.cli import main as varden_main
from varden.runtime.cli import run_self_test
from varden.runtime.coverage import (
    ENFORCED,
    NOT_ROUTED,
    OBSERVATIONAL,
    PARTIAL,
    REQUIREMENT_CATEGORY_SURFACES,
    SURFACE_ALIASES,
    UNCOVERED,
    UNSUPPORTED,
    CoverageRegistry,
    canonical_surface_name,
    catalogue_surface_names,
    get_coverage_registry,
)


def _activate(reg: CoverageRegistry, **kwargs) -> None:
    kwargs.setdefault("mode", "strict")
    kwargs.setdefault("fail_mode", "closed")
    reg.set_session(lock_mode=True, **kwargs)


def test_missing_required_enforced_vs_weaker_statuses():
    reg = CoverageRegistry()
    _activate(reg, mode="strict", require_coverage=["http", "subprocess", "filesystem"])
    reg.mark("http.requests", status=ENFORCED, active=True, applicable=True)
    reg.mark("subprocess", status=ENFORCED, active=True, applicable=True)
    reg.mark("filesystem", status=ENFORCED, active=True, applicable=True)
    assert reg.missing_required() == []

    cases = [
        ("filesystem", PARTIAL),
        ("filesystem", OBSERVATIONAL),
        ("filesystem", NOT_ROUTED),
        ("filesystem", UNCOVERED),
        ("filesystem", UNSUPPORTED),
    ]
    for name, status in cases:
        reg.mark(name, status=status, active=True, applicable=True)
        missing = reg.missing_required()
        assert "filesystem" in missing, f"{status} must not satisfy require_coverage"


def test_allow_uncovered_is_exception_not_enforced():
    reg = CoverageRegistry()
    _activate(
        reg,
        mode="strict",
        require_coverage=["filesystem"],
        allow_uncovered=["filesystem"],
    )
    reg.mark("filesystem", status=PARTIAL, active=True, applicable=True)
    assert reg.missing_required() == []
    ready = reg.strict_readiness()
    assert ready["ready"] is True
    assert ready["status"] == "READY WITH EXCEPTIONS"
    assert "filesystem" in ready["accepted_exceptions"]
    # Exception path never upgrades surface status to ENFORCED.
    assert reg.get("filesystem").status == PARTIAL


def test_partial_required_surface_blocks_protected_posture():
    from varden.runtime.posture import NOT_READY, evaluate_posture

    reg = CoverageRegistry()
    _activate(reg, mode="strict", require_coverage=["http", "subprocess"])
    reg.mark("http.requests", status=PARTIAL, active=True, applicable=True)
    reg.mark("subprocess", status=ENFORCED, active=True, applicable=True)
    report = evaluate_posture(reg, self_test="not_run")
    assert report.result == NOT_READY
    assert report.to_dict().get("result") == NOT_READY


def test_coverage_registry_reset_clears_session_security_state():
    reg = get_coverage_registry()
    reg.reset()
    reg.set_session(
        mode="strict",
        fail_mode="closed",
        session_id="sess-1",
        require_coverage=["http", "mcp"],
        allow_uncovered=["filesystem"],
        lock_mode=True,
    )
    reg.mark("http.requests", status=ENFORCED, active=True, applicable=True)
    reg.discover("mcp", detail={"reason": "config present"})
    att1 = reg.attestation()
    assert att1["mode"] == "strict"
    assert att1["session_id"] == "sess-1"
    assert att1["require_coverage"] == ["http", "mcp"]
    assert att1["mode_locked"] is True

    reg.reset()
    att2 = reg.attestation()
    assert att2["mode"] == "guarded"
    assert att2["fail_mode"] == "closed"
    assert att2["session_id"] is None
    assert att2["require_coverage"] == []
    assert att2["accepted_exceptions"] == []
    assert att2["mode_locked"] is False
    assert att2["discovered"] == []
    assert all(not s["active"] for s in att2["surfaces"])

    # Second activation must not inherit prior require_coverage / mode lock.
    reg.set_session(mode="guarded", fail_mode="closed", require_coverage=["subprocess"], lock_mode=True)
    assert reg.attestation()["require_coverage"] == ["subprocess"]
    assert "http" not in reg.attestation()["require_coverage"]
    reg.reset()


def test_surface_aliases_resolve_to_catalogue():
    names = catalogue_surface_names()
    for alias, canonical in SURFACE_ALIASES.items():
        assert canonical in names
        assert canonical_surface_name(alias) == canonical
        assert alias not in names

    reg = CoverageRegistry()
    reg.mark("llm.openai", status=ENFORCED, active=True, applicable=True)
    surf = reg.get("llm.openai")
    assert surf is not None
    assert surf.name == "llm.openai_transport"
    assert reg.get("llm.openai_transport") is surf


def test_requirement_mappings_resolve_to_catalogue_or_alias():
    names = catalogue_surface_names()
    for category, surfaces in REQUIREMENT_CATEGORY_SURFACES.items():
        for surface in surfaces:
            resolved = canonical_surface_name(surface)
            assert resolved in names, f"{surface} (via {category}) must resolve to catalogue"
        # Category keys may coincide with a primary surface name (e.g. subprocess).
        if category in names:
            assert category in {s for s in surfaces}


def test_hardcoded_surface_refs_in_sdk_are_canonical_or_aliased():
    sdk = Path(__file__).resolve().parents[2] / "varden_sdk" / "sdk.py"
    text = sdk.read_text(encoding="utf-8")
    found = set(re.findall(r"mark\(\s*['\"]([a-z0-9_.]+)['\"]", text))
    names = catalogue_surface_names()
    for name in found:
        resolved = canonical_surface_name(name)
        assert resolved in names, f"sdk mark({name!r}) does not resolve to catalogue"


def test_cli_runtime_readiness_json_is_pure(monkeypatch):
    payload = {
        "status": "READY",
        "ready": True,
        "required_coverage_missing": [],
        "discovered_blocking": [],
        "accepted_exceptions": [],
    }

    def _fake_api(method, path, **kwargs):
        assert path == "/runtime/readiness"
        return payload

    monkeypatch.setattr("varden.runtime.cli._api", _fake_api)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = varden_main(["runtime", "readiness", "--json"])
    assert code == 0
    out = buf.getvalue()
    assert "STRICT MODE READINESS" not in out
    data = json.loads(out)
    assert data["status"] == "READY"
    assert data["ready"] is True


def test_cli_runtime_readiness_human_unchanged(monkeypatch):
    payload = {
        "status": "NOT READY",
        "ready": False,
        "required_coverage_missing": ["mcp"],
        "discovered_blocking": [],
        "accepted_exceptions": [],
    }
    monkeypatch.setattr("varden.runtime.cli._api", lambda *a, **k: payload)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = varden_main(["runtime", "readiness"])
    assert code == 0
    out = buf.getvalue()
    assert out.startswith("STRICT MODE READINESS:")
    assert "mcp" in out


def test_cli_posture_json_is_pure():
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = varden_main(["posture", "--json"])
    assert code == 0
    data = json.loads(buf.getvalue())
    assert "result" in data
    assert "STRICT MODE" not in buf.getvalue()


def test_runtime_self_test_positive_exit_and_fields():
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_self_test(as_json=True)
    assert code == 0
    data = json.loads(buf.getvalue())
    assert data["ok"] is True
    assert data["failed"] == []
    surfaces = {p["surface"] for p in data["probes"]}
    assert "coverage.verify" in surfaces
    assert any(s.startswith("http.") for s in surfaces)
    assert "subprocess" in surfaces
    assert "filesystem" in surfaces
    for probe in data["probes"]:
        for key in (
            "surface",
            "probe_executed",
            "interceptor_invoked",
            "guard_invoked",
            "decision",
            "verification",
            "reason",
        ):
            assert key in probe
    fs = next(p for p in data["probes"] if p["surface"] == "filesystem")
    assert fs["verification"] != "ENFORCED"
    assert fs["verification"] in {"pass", "partial"}


def test_runtime_self_test_negative_exit_on_tamper(monkeypatch):
    from varden.runtime import cli as runtime_cli

    real_execute = runtime_cli._execute_self_test

    def _force_tamper(**kwargs):
        code, payload = real_execute(**kwargs)
        payload["probes"].append(
            {
                "surface": "injected",
                "probe_executed": True,
                "interceptor_invoked": False,
                "guard_invoked": False,
                "decision": "tamper",
                "verification": "tamper",
                "reason": "forced",
            }
        )
        payload["failed"] = [p["surface"] for p in payload["probes"] if p["verification"] in runtime_cli._FAIL_VERDICTS]
        payload["ok"] = False
        return 1, payload

    monkeypatch.setattr(runtime_cli, "_execute_self_test", _force_tamper)
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = runtime_cli.run_self_test(as_json=True)
    assert code == 1
    data = json.loads(buf.getvalue())
    assert data["ok"] is False
    assert "injected" in data["failed"]
