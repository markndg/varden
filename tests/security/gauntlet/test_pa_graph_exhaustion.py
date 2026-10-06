"""Gauntlet Phase 3 — incomplete graph analysis must never claim safety."""

from __future__ import annotations

from varden.predictive_authority.benchmarks import build_stress_graph
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.hazardous import detect_hazardous_analysis
from varden.predictive_authority.reachability import DEFAULT_MAX_VISITS, authority_hop_cost, bounded_reachability


def test_gauntlet_truncated_without_hazard_is_not_safe_conclusion():
    """G-PA-GRAPH-01: visit budget exhausted with no found hazard ≠ safe."""
    g = build_stress_graph(early_benign=5000, with_hazard=False)
    result = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=3,
        predicate=lambda n: "aws.ec2.modify" in n,
        hop_cost=lambda e, d: authority_hop_cost(e, d, g),
        max_visits=DEFAULT_MAX_VISITS,
    )
    assert result.truncated is True
    assert result.to_dict()["safe_conclusion"] is False
    analysis = detect_hazardous_analysis(g, max_depth=3)
    assert not analysis.findings
    assert analysis.truncated or analysis.analysis_incomplete
    assert analysis.safe_conclusion is False
    assert analysis.to_dict()["hazard_status"] == "NOT_OBSERVED"


def test_gauntlet_hazard_before_truncation_remains_valid():
    """Hazard found within budget remains reported; never claimed safe."""
    g = build_stress_graph(early_benign=1900, with_hazard=True)
    analysis = detect_hazardous_analysis(g, max_depth=3)
    assert analysis.findings
    assert analysis.safe_conclusion is False


def test_gauntlet_hazard_beyond_bound_not_claimed_absent():
    """Real hazard past MAX_VISITS must not be reported as proven absent/safe."""
    g = build_stress_graph(early_benign=5000, with_hazard=True)
    analysis = detect_hazardous_analysis(g, max_depth=3)
    assert g.get_node("cap:zzz.aws.ec2.modify") is not None
    assert analysis.to_dict()["hazard_status"] == "NOT_OBSERVED"
    assert analysis.safe_conclusion is False


def test_gauntlet_config_bounds_are_finite():
    cfg = PredictiveAuthorityConfig(enabled=True, mode="enforce")
    assert cfg.max_nodes > 0 and cfg.max_edges > 0 and cfg.max_depth > 0
    assert cfg.max_nodes < 1_000_000
