"""BA–BC: bounded traversal stress semantics (not precision timing)."""

from __future__ import annotations

import time

from varden.predictive_authority.benchmarks import build_stress_graph, worst_case_traversal_report
from varden.predictive_authority.config import PredictiveAuthorityConfig
from varden.predictive_authority.hazardous import detect_hazardous_analysis
from varden.predictive_authority.reachability import DEFAULT_MAX_VISITS, authority_hop_cost, bounded_reachability


def test_ba_near_limit_hazardous_path():
    """BA: hazard found after ~1.5k–2k visits; complete if under max_visits."""
    g = build_stress_graph(early_benign=1900, with_hazard=True)
    assert g.node_count() == 10_000
    result = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=3,
        predicate=lambda n: "aws.ec2.modify" in n,
        hop_cost=lambda e, d: authority_hop_cost(e, d, g),
        max_visits=DEFAULT_MAX_VISITS,
    )
    assert result.reachable is True
    assert 1500 <= result.visited_nodes <= 2048
    assert result.truncated is False
    assert result.to_dict()["safe_conclusion"] is False
    analysis = detect_hazardous_analysis(g, max_depth=3)
    assert analysis.findings
    assert analysis.safe_conclusion is False


def test_bb_bound_exhaustion_negative_not_safe():
    """BB: no hazard; visit bound exhausted → incomplete, never SAFE."""
    g = build_stress_graph(early_benign=5000, with_hazard=False)
    result = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=3,
        predicate=lambda n: "aws.ec2.modify" in n,
        hop_cost=lambda e, d: authority_hop_cost(e, d, g),
        max_visits=DEFAULT_MAX_VISITS,
    )
    assert result.reachable is False
    assert result.truncated is True
    assert result.incompleteness_reason == "MAX_VISITS"
    assert result.visits > DEFAULT_MAX_VISITS or result.visited_nodes >= DEFAULT_MAX_VISITS
    assert result.to_dict()["safe_conclusion"] is False
    analysis = detect_hazardous_analysis(g, max_depth=3)
    assert not analysis.findings
    assert analysis.truncated or analysis.analysis_incomplete
    assert analysis.safe_conclusion is False
    assert analysis.to_dict()["hazard_status"] == "NOT_OBSERVED"


def test_bc_hazard_beyond_bound_not_observed():
    """BC: real hazard exists but not reached before MAX_VISITS — fail-safe, not 'absent'."""
    g = build_stress_graph(early_benign=5000, with_hazard=True)
    result = bounded_reachability(
        g,
        ["cap:credential.aws"],
        max_depth=3,
        predicate=lambda n: "aws.ec2.modify" in n,
        hop_cost=lambda e, d: authority_hop_cost(e, d, g),
        max_visits=DEFAULT_MAX_VISITS,
    )
    assert result.reachable is False
    assert result.truncated is True
    assert result.incompleteness_reason == "MAX_VISITS"
    assert result.to_dict()["safe_conclusion"] is False
    # Hazard node is present in the graph — simply not observed by bounded search.
    assert g.get_node("cap:zzz.aws.ec2.modify") is not None
    analysis = detect_hazardous_analysis(g, max_depth=3)
    assert analysis.to_dict()["hazard_status"] == "NOT_OBSERVED"
    assert analysis.safe_conclusion is False


def test_ba_bb_bc_report_metrics_and_loose_guard():
    """Characterization reports + deliberately generous near-bound smoke guard."""
    cfg = PredictiveAuthorityConfig()
    assert cfg.max_depth == 3
    assert cfg.max_nodes == 2048
    assert cfg.max_edges == 8192
    assert DEFAULT_MAX_VISITS == 4096

    t0 = time.perf_counter()
    ba = worst_case_traversal_report(name="BA", early_benign=1900, with_hazard=True, repeats=3)
    bb = worst_case_traversal_report(name="BB", early_benign=5000, with_hazard=False, repeats=3)
    bc = worst_case_traversal_report(name="BC", early_benign=5000, with_hazard=True, repeats=3)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert ba["hazard_found"] is True
    assert ba["analysis_status"] == "COMPLETE"
    assert ba["decision"] == "require_approval"
    assert 1500 <= ba["visited_nodes"] <= 2048

    assert bb["hazard_found"] is False
    assert bb["analysis_status"] == "TRUNCATED"
    assert bb["terminating_bound"] == "MAX_VISITS"
    assert bb["safe_conclusion"] is False
    assert bb["decision"] == "require_approval"
    assert bb["hazard_status"] == "NOT_OBSERVED"

    assert bc["hazard_found"] is False
    assert bc["analysis_status"] == "TRUNCATED"
    assert bc["hazard_status"] == "NOT_OBSERVED"
    assert bc["decision"] == "require_approval"
    assert bc["safe_conclusion"] is False

    # Loose guard: three near-bound workloads should stay well under several seconds.
    assert elapsed_ms < 3000.0, elapsed_ms
