"""Table-driven tests for authoritative runtime posture."""

from __future__ import annotations

import json
import re

import pytest

from varden.cli import main as varden_main
from varden.runtime.coverage import (
    ENFORCED,
    NOT_ROUTED,
    OBSERVATIONAL,
    PARTIAL,
    UNCOVERED,
    UNSUPPORTED,
    CoverageRegistry,
)
from varden.runtime.posture import (
    NOT_FULLY_ROUTED,
    NOT_PROTECTED,
    NOT_READY,
    PROTECTED,
    PROTECTED_WITH_GAPS,
    SCHEMA_VERSION,
    VALID_RESULTS,
    evaluate_posture,
)


def _fresh_registry() -> CoverageRegistry:
    reg = CoverageRegistry()
    reg.reset()
    return reg


def _activate(
    reg: CoverageRegistry,
    *,
    mode: str = "guarded",
    fail_mode: str = "closed",
    require_coverage: list[str] | None = None,
    allow_uncovered: list[str] | None = None,
) -> None:
    reg.set_session(
        mode=mode,
        fail_mode=fail_mode,
        require_coverage=require_coverage,
        allow_uncovered=allow_uncovered,
        lock_mode=True,
    )


def _mark_core_enforced(reg: CoverageRegistry, *, filesystem: str = ENFORCED, network_extras: bool = False) -> None:
    reg.mark("http.requests", status=ENFORCED, active=True, applicable=True)
    reg.mark("http.httpx", status=ENFORCED, active=True, applicable=True)
    reg.mark("subprocess", status=ENFORCED, active=True, applicable=True)
    reg.mark("filesystem", status=filesystem, active=True, applicable=True)
    reg.mark("tools.python", status=ENFORCED, active=True, applicable=True)
    if network_extras:
        reg.mark("http.raw_sockets", status=UNCOVERED, active=False, applicable=True)
        reg.mark("http.aiohttp", status=UNSUPPORTED, active=False, applicable=True)
        reg.mark("http.urllib3", status=UNCOVERED, active=False, applicable=True)


@pytest.mark.parametrize(
    "case,setup,expected",
    [
        (
            "inactive_installed",
            lambda reg: None,
            NOT_PROTECTED,
        ),
        (
            "observe_mode_active",
            lambda reg: (
                _activate(reg, mode="observe", fail_mode="open"),
                _mark_core_enforced(reg),
            ),
            NOT_PROTECTED,
        ),
        (
            "active_ready_all_enforced",
            lambda reg: (
                _activate(reg),
                _mark_core_enforced(reg, filesystem=ENFORCED),
            ),
            PROTECTED,
        ),
        (
            "active_ready_filesystem_partial",
            lambda reg: (
                _activate(reg),
                _mark_core_enforced(reg, filesystem=PARTIAL),
            ),
            PROTECTED_WITH_GAPS,
        ),
        (
            "active_ready_network_extras",
            lambda reg: (
                _activate(reg),
                _mark_core_enforced(reg, filesystem=ENFORCED, network_extras=True),
            ),
            PROTECTED_WITH_GAPS,
        ),
        (
            "applicable_mcp_not_routed",
            lambda reg: (
                _activate(reg),
                _mark_core_enforced(reg, filesystem=ENFORCED),
                reg.discover("mcp", detail={"reason": "mcp.json present"}),
                reg.mark(
                    "mcp",
                    status=NOT_ROUTED,
                    active=False,
                    applicable=True,
                    limitations=["MCP config discovered but traffic is not routed through the Varden gateway."],
                ),
            ),
            NOT_FULLY_ROUTED,
        ),
        (
            "mcp_not_applicable_stays_protected",
            lambda reg: (
                _activate(reg),
                _mark_core_enforced(reg, filesystem=ENFORCED),
                # catalog default: mcp NOT_ROUTED but applicable=False
            ),
            PROTECTED,
        ),
        (
            "required_mcp_not_routed",
            lambda reg: (
                _activate(reg, mode="strict", require_coverage=["http", "subprocess", "mcp"]),
                _mark_core_enforced(reg, filesystem=ENFORCED),
                reg.mark("mcp", status=NOT_ROUTED, active=False, applicable=True),
            ),
            NOT_FULLY_ROUTED,
        ),
        (
            "strict_readiness_failure",
            lambda reg: (
                _activate(reg, mode="strict", require_coverage=["http", "subprocess"]),
                # leave http uncovered
                reg.mark("subprocess", status=ENFORCED, active=True),
            ),
            NOT_READY,
        ),
        (
            "observational_applicable",
            lambda reg: (
                _activate(reg),
                _mark_core_enforced(reg, filesystem=ENFORCED),
                reg.mark(
                    "tools.langchain",
                    status=OBSERVATIONAL,
                    active=False,
                    applicable=True,
                    limitations=["Callbacks alone are observational"],
                ),
            ),
            PROTECTED_WITH_GAPS,
        ),
    ],
)
def test_posture_combinations(case, setup, expected):
    reg = _fresh_registry()
    setup(reg)
    report = evaluate_posture(reg)
    assert report.result == expected, f"{case}: {report.result} != {expected}; gaps={[g.to_dict() for g in report.gaps]}"


def test_precedence_not_ready_over_not_routed():
    reg = _fresh_registry()
    _activate(reg, mode="strict", require_coverage=["http", "mcp"])
    _mark_core_enforced(reg, filesystem=ENFORCED)
    reg.discover("mcp", detail={"reason": "present"})
    reg.mark("mcp", status=NOT_ROUTED, active=False, applicable=True)
    # http required but uncovered → material readiness failure wins over routing
    reg.mark("http.requests", status=UNCOVERED, active=False)
    reg.mark("http.httpx", status=UNCOVERED, active=False)
    report = evaluate_posture(reg)
    assert report.result == NOT_READY


def test_precedence_not_routed_over_partial():
    reg = _fresh_registry()
    _activate(reg)
    _mark_core_enforced(reg, filesystem=PARTIAL)
    reg.discover("mcp", detail={"reason": "present"})
    reg.mark("mcp", status=NOT_ROUTED, active=False, applicable=True)
    report = evaluate_posture(reg)
    assert report.result == NOT_FULLY_ROUTED


def test_inactive_never_protected_or_with_gaps():
    reg = _fresh_registry()
    # Even with ENFORCED-looking catalog noise, inactive → NOT_PROTECTED
    reg.mark("subprocess", status=ENFORCED, active=False)
    report = evaluate_posture(reg)
    assert report.result == NOT_PROTECTED
    assert report.result not in {PROTECTED, PROTECTED_WITH_GAPS}


def test_invalid_attestation_never_protected():
    report = evaluate_posture(attestation={}, attestation_valid=False)
    assert report.result == NOT_PROTECTED
    assert report.verification["attestation"] == "invalid"


def test_mcp_not_routed_never_protected_when_applicable():
    reg = _fresh_registry()
    _activate(reg)
    _mark_core_enforced(reg, filesystem=ENFORCED)
    reg.mark("mcp", status=NOT_ROUTED, active=False, applicable=True)
    report = evaluate_posture(reg)
    assert report.result != PROTECTED


def test_partial_never_protected_when_applicable():
    reg = _fresh_registry()
    _activate(reg)
    _mark_core_enforced(reg, filesystem=PARTIAL)
    report = evaluate_posture(reg)
    assert report.result != PROTECTED


def test_json_schema_shape():
    reg = _fresh_registry()
    _activate(reg)
    _mark_core_enforced(reg, filesystem=PARTIAL, network_extras=True)
    reg.discover("mcp", detail={"reason": "mcp.json", "paths": ["/tmp/mcp.json"]})
    reg.mark(
        "mcp",
        status=NOT_ROUTED,
        active=False,
        applicable=True,
        evidence={"paths": ["/tmp/mcp.json"]},
        limitations=["MCP config discovered but traffic is not routed through the Varden gateway."],
    )
    report = evaluate_posture(reg)
    data = report.to_dict()
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["result"] in VALID_RESULTS
    assert data["result"] == NOT_FULLY_ROUTED
    assert "runtime" in data and "mode" in data["runtime"]
    assert "verification" in data
    assert data["verification"]["attestation"] == "valid"
    assert data["verification"]["self_test"] == "not_run"
    assert "surfaces" in data
    assert "network" in data["surfaces"] or "subprocess" in data["surfaces"]
    assert isinstance(data["gaps"], list)
    assert any(g["surface"] == "mcp" and g["state"] == "not_routed" for g in data["gaps"])
    mcp_gap = next(g for g in data["gaps"] if g["surface"] == "mcp")
    assert mcp_gap["remediation_available"] is True
    assert "varden mcp wrap" in (mcp_gap.get("remediation") or "")
    blob = json.dumps(data)
    assert "\x1b[" not in blob


def test_human_output_semantics():
    reg = _fresh_registry()
    _activate(reg)
    _mark_core_enforced(reg, filesystem=PARTIAL)
    reg.discover("mcp", detail={"reason": "present"})
    reg.mark("mcp", status=NOT_ROUTED, active=False, applicable=True)
    text = evaluate_posture(reg).format_human()
    assert "Varden Security Posture" in text
    assert "NOT FULLY ROUTED" in text
    assert "Attestation: VALID" in text
    assert "NOT_ROUTED" in text or "NOT ROUTED" in text
    assert "PARTIAL" in text
    assert "PROTECTED" not in text.split("Result")[-1] or "NOT FULLY" in text
    # Must not claim protected result
    assert re.search(r"Result\n\s+PROTECTED\n", text) is None
    assert "\x1b[" not in text


def test_allow_uncovered_accepted_does_not_block_protected():
    reg = _fresh_registry()
    _activate(reg, allow_uncovered=["filesystem"])
    _mark_core_enforced(reg, filesystem=PARTIAL)
    report = evaluate_posture(reg)
    # filesystem gap accepted → remaining surfaces enforced → PROTECTED
    assert report.result == PROTECTED
    assert any(g.accepted_exception for g in report.gaps)


def test_cli_posture_json(capsys):
    code = varden_main(["posture", "--json"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["result"] in VALID_RESULTS
    assert data["result"] == NOT_PROTECTED  # CLI process typically inactive
    assert data["runtime"]["active"] is False
    assert data["verification"]["readiness"] in {"n/a", "ready"}
    assert "\x1b[" not in out


def test_cli_posture_human(capsys):
    code = varden_main(["posture"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Varden Security Posture" in out
    assert "NOT PROTECTED" in out
