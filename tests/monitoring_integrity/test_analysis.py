"""Predictive Authority paths for monitoring sabotage."""

from __future__ import annotations

from varden.models import Action
from varden.monitoring_integrity.analysis import analyse, counterfactual, get_analysis_cache
from varden.monitoring_integrity.assets import AssetRegistry
from varden.monitoring_integrity.service import enable_monitoring_integrity, reset_monitoring_integrity
from varden.predictive_authority.facts import apply_facts_to_state, extract_facts
from varden.predictive_authority.hazardous import detect_hazardous_paths
from varden.predictive_authority.graph import CapabilityGraph
from varden.predictive_authority.state import AuthorityState


def _registry():
    registry = AssetRegistry()
    registry.load_section(
        {
            "enabled": True,
            "mode": "guarded",
            "assets": [
                {
                    "id": "monitor.config",
                    "type": "enforcement_config",
                    "protected": True,
                    "owner": "operator",
                    "process_names": ["varden"],
                    "permitted_operations": ["read"],
                }
            ],
            "grants": [
                {"id": "read_config", "operations": ["read"], "assets": ["monitor.config"], "surface": "filesystem", "sequence": 1, "authority_neutral": True},
                {"id": "stage_config", "operations": ["write"], "assets": [], "surface": "filesystem", "sequence": 2, "authority_neutral": True},
                {"id": "reload", "operations": ["exec"], "assets": ["monitor.config"], "surface": "subprocess", "sequence": 3, "activation": True},
            ],
        },
        section_hash="model",
    )
    return registry


def test_multistep_path_interrupts_at_reload_not_at_the_read():
    report = analyse(_registry(), use_cache=False)
    assert report["hazard_found"] is True
    assert report["safe_conclusion"] is False
    interruption = report["interruption"]
    assert interruption["grant_id"] == "reload"
    assert interruption["enforceable"] is True
    assert interruption["outcome"] == "DENY"
    assert report["minimum_cut"]["proven"] is True
    assert report["minimum_cut"]["breaks_all_known_paths"] is True


def test_removing_reload_is_a_counterfactual_that_clears_the_known_path():
    report = counterfactual(_registry(), {"kind": "remove_permission", "grant_id": "reload"})
    assert report["before_hazards"] >= 1
    assert report["hazard_removed"] is True
    assert report["after_safe_conclusion"] is True


def test_unavailable_surface_does_not_become_safe():
    report = counterfactual(_registry(), {"kind": "surface_unavailable", "surface": "subprocess"})
    assert report["after_hazards"] >= 1
    assert report["after_safe_conclusion"] is False
    assert report["after_interruption"]["enforceable"] is False
    assert report["after_interruption"]["outcome"] == "NOT_ENFORCEABLE"


def test_depth_budget_is_not_reported_as_safe():
    report = analyse(_registry(), max_depth=0, use_cache=False)
    assert report["safe_conclusion"] is False
    assert report["analysis_incomplete"] is True
    assert report["incompleteness_reason"] == "DEPTH_BUDGET"


def test_exact_cut_budget_exhaustion_is_not_proven():
    report = analyse(_registry(), max_combinations=0, use_cache=False)
    assert report["hazard_found"] is True
    assert report["minimum_cut"]["proven"] is False
    assert report["minimum_cut"]["method"] == "greedy_approximation"
    assert report["analysis_incomplete"] is True


def test_cache_invalidates_when_the_registry_generation_changes():
    registry = _registry()
    first = analyse(registry)
    cache = get_analysis_cache()
    before = cache.hits
    second = analyse(registry)
    assert cache.hits == before + 1
    assert second["hazard_found"] is first["hazard_found"]
    registry.generation += 1
    analyse(registry)
    assert cache.misses >= 1


def test_no_grants_is_not_a_safety_claim():
    registry = AssetRegistry()
    registry.load_section({"enabled": True, "assets": []}, section_hash="empty")
    report = analyse(registry, use_cache=False)
    assert report["safe_conclusion"] is False
    assert report["incompleteness_reason"] == "NO_TOOL_GRANTS"


def test_session_graph_records_a_protected_asset_touch(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    token = enable_monitoring_integrity(
        {
            "enabled": True,
            "mode": "guarded",
            "assets": [
                {
                    "id": "monitor.config",
                    "type": "enforcement_config",
                    "protected": True,
                    "owner": "operator",
                    "path": str(live),
                    "permitted_operations": ["read"],
                }
            ],
        }
    )
    try:
        action = Action(type="filesystem", tool="open", args={"path": str(live), "mode": "w"}, agent_name="agent")
        facts = extract_facts(action)
        state = AuthorityState(session_key="s", graph=CapabilityGraph())
        apply_facts_to_state(state, facts)
        findings = detect_hazardous_paths(state.graph, max_depth=4)
        assert any(item.pattern == "monitoring_integrity_sabotage" for item in findings)
    finally:
        reset_monitoring_integrity(release_token=token)
