"""Predictive Authority engine — session transition analysis."""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from typing import Any

from ..models import Action, Decision
from .authority_delta import AuthorityDelta, compute_authority_delta
from .budget import AuthorityBudget
from .config import PredictiveAuthorityConfig, parse_predictive_config
from .counterfactual import CounterfactualExplanation, build_explanation
from .facts import ActionFacts, apply_facts_to_state, extract_facts
from .hazardous import HazardousFinding, detect_hazardous_analysis, detect_hazardous_paths
from .evidence import AnalysisStatus
from .policy import (
    PredictiveRecommendation,
    annotate_action_predicates,
    recommend,
    strengthen_decision,
    decision_rank,
)
from .registry import get_authority_registry
from .snapshot import SNAPSHOT_SCHEMA_VERSION, build_historical_snapshot
from .state import AuthorityState, AuthorityTransitionRecord


def _failure_decision(existing: Decision, failure_mode: str) -> Decision:
    """Apply configured PA failure behavior without weakening existing decision."""
    target = "allow"
    if failure_mode == "block":
        target = "block"
    elif failure_mode == "require_approval":
        target = "require_approval"
    else:
        return existing
    if decision_rank(target) <= decision_rank(existing.action):
        return existing
    return Decision(
        action=target,
        reason=f"predictive_authority analysis {failure_mode} (fail-safe)",
        matched_rule={"type": "predictive_authority_failure", "failure_mode": failure_mode},
        effective_action=target,
        route_target=existing.route_target,
    )


@dataclass
class PredictiveResult:
    config: PredictiveAuthorityConfig
    facts: ActionFacts | None = None
    delta: AuthorityDelta | None = None
    findings: list[HazardousFinding] = field(default_factory=list)
    recommendation: PredictiveRecommendation | None = None
    explanation: CounterfactualExplanation | None = None
    existing_decision: str = "allow"
    final_decision: Decision | None = None
    budget: AuthorityBudget | None = None
    error: str | None = None
    elapsed_ms: float = 0.0
    analysis_status: str = AnalysisStatus.OFF.value
    analysis_incomplete_reason: str | None = None
    before_snapshot: dict[str, Any] | None = None
    after_snapshot: dict[str, Any] | None = None
    # Full immutable historical payload for durable persistence (not stored in audit JSON).
    historical_snapshot: dict[str, Any] | None = None

    def to_metadata(self) -> dict[str, Any]:
        snap = self.historical_snapshot or {}
        return {
            "enabled": self.config.enabled,
            "mode": self.config.mode,
            "max_depth": self.config.max_depth,
            "existing_decision": self.existing_decision,
            "recommendation": self.recommendation.to_dict() if self.recommendation else None,
            "final_decision": self.final_decision.action if self.final_decision else self.existing_decision,
            "delta": self.delta.to_dict() if self.delta else None,
            "hazardous_paths": [f.to_dict() for f in self.findings],
            "explanation": self.explanation.to_dict() if self.explanation else None,
            "budget": self.budget.to_dict() if self.budget else None,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
            "action_summary": self.facts.summary if self.facts else None,
            "analysis_status": self.analysis_status,
            "analysis_incomplete_reason": self.analysis_incomplete_reason,
            # Explicit: incomplete/failed must never be represented as safe.
            "safe_conclusion": self.analysis_status == AnalysisStatus.COMPLETE.value
            and not (self.findings)
            and not self.error,
            "before": self.before_snapshot,
            "after": self.after_snapshot,
            # Integrity binding for side-stored full snapshot (hashed with audit event).
            "has_snapshot": bool(snap),
            "snapshot_schema_version": snap.get("schema_version", SNAPSHOT_SCHEMA_VERSION) if snap else None,
            "snapshot_content_hash": snap.get("content_hash") if snap else None,
        }


class PredictiveAuthorityEngine:
    def __init__(self, config: PredictiveAuthorityConfig | None = None) -> None:
        self.config = config or PredictiveAuthorityConfig()

    def evaluate(
        self,
        action: Action,
        existing: Decision,
        *,
        policy: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> tuple[Decision, PredictiveResult]:
        """Analyse candidate transition and optionally strengthen decision.

        ``commit=True`` applies facts to the live session state (normal path).
        Counterfactual analysis uses a temporary clone before commit.
        """
        start = time.perf_counter()
        result = PredictiveResult(config=self.config, existing_decision=existing.action, final_decision=existing)

        if not self.config.is_active():
            result.analysis_status = AnalysisStatus.OFF.value
            result.elapsed_ms = (time.perf_counter() - start) * 1000.0
            return existing, result

        registry = get_authority_registry()
        key = registry.session_key(
            tenant_id=action.tenant_id,
            trace_id=action.trace_id,
            workflow_id=action.workflow_id,
        )

        try:
            state = registry.get_or_create(key, self.config)
            budget = registry.budget(key)
            facts = extract_facts(action)
            result.facts = facts

            before_caps = {n: copy.deepcopy(c) for n, c in state.capabilities.items()}
            before_resources = {n: copy.deepcopy(r) for n, r in state.resources.items()}
            before_view = AuthorityState(
                session_key=state.session_key,
                graph=state.graph,
                capabilities=before_caps,
                resources=before_resources,
                provenance_refs=list(state.provenance_refs),
                approvals=list(state.approvals),
                irreversible_actions=list(state.irreversible_actions),
                initial_capability_names=set(state.initial_capability_names),
            )
            result.before_snapshot = {
                "capabilities": sorted(before_caps.keys()),
                "confirmed": sorted(n for n, c in before_caps.items() if c.kind.value == "confirmed"),
                "potential": sorted(n for n, c in before_caps.items() if c.kind.value == "potential"),
                "graph_version": state.graph.version,
            }

            before_cap_names = set(state.capabilities.keys())
            before_res_ids = set(state.resources.keys())
            before_domains = {c.domain for c in state.capabilities.values() if c.domain}

            apply_facts_to_state(state, facts)

            analysis = detect_hazardous_analysis(state.graph, max_depth=self.config.max_depth)
            findings = analysis.findings
            action_id = facts.action_node_id
            relevant = [
                f
                for f in findings
                if action_id in f.path.nodes
                or any(n not in before_res_ids and n.startswith("res:") for n in f.path.nodes)
                or any(
                    (n.startswith("cap:") or n.startswith("cap.potential:"))
                    and n.split(":", 1)[-1] not in before_cap_names
                    for n in f.path.nodes
                )
            ]
            if not relevant and findings and facts.capabilities:
                new_names = {c.name for c in facts.capabilities}
                relevant = [
                    f
                    for f in findings
                    if any(any(name in n for name in new_names) for n in f.path.nodes)
                ]
            result.findings = relevant or findings[:3]
            seen_disp: set[str] = set()
            deduped = []
            for f in result.findings:
                disp = f.path.to_dict()["display"]
                key_d = f"{f.pattern}:{disp}"
                if key_d in seen_disp:
                    continue
                seen_disp.add(key_d)
                deduped.append(f)
            result.findings = deduped

            # Analysis status: truncation is NEVER a safe conclusion.
            # Includes graph construction bounds AND reachability visit/path bounds.
            if state.graph.truncated or analysis.truncated or analysis.analysis_incomplete:
                result.analysis_status = AnalysisStatus.TRUNCATED.value
                result.analysis_incomplete_reason = (
                    state.graph.truncation_reason
                    or analysis.incompleteness_reason
                    or "MAX_VISITS"
                )
            else:
                result.analysis_status = AnalysisStatus.COMPLETE.value

            irrev = [facts.summary] if facts.irreversible else []
            delta = compute_authority_delta(before_view, state, hazardous_paths=[f.path for f in result.findings], irreversible=irrev)
            if not delta.added_capabilities:
                for cap in facts.capabilities:
                    if cap.name not in before_cap_names:
                        delta.added_capabilities.append(cap)
                delta.authority_expands = delta.authority_expands or bool(delta.added_capabilities)
            after_domains = {c.domain for c in state.capabilities.values() if c.domain}
            for d in sorted(after_domains - before_domains):
                if d not in delta.added_privilege_domains:
                    delta.added_privilege_domains.append(d)
                    delta.authority_expands = True

            result.delta = delta
            result.after_snapshot = {
                "capabilities": sorted(state.capabilities.keys()),
                "confirmed": sorted(n for n, c in state.capabilities.items() if c.kind.value == "confirmed"),
                "potential": sorted(n for n, c in state.capabilities.items() if c.kind.value == "potential"),
                "graph_version": state.graph.version,
                "truncated": state.graph.truncated,
            }

            budget_exceeded = bool(budget and budget.would_exceed(delta))
            recommendation = recommend(
                delta=delta,
                findings=result.findings,
                policy=policy,
                budget_exceeded=budget_exceeded,
                irreversible=facts.irreversible,
            )
            # Truncated analysis in enforce: apply failure_mode (default require_approval).
            if result.analysis_status == AnalysisStatus.TRUNCATED.value and self.config.is_enforce():
                fm = self.config.resolved_failure_mode()
                if fm == "block":
                    recommendation = PredictiveRecommendation(
                        action="block",
                        reason=f"analysis_truncated:{result.analysis_incomplete_reason or 'bound'}",
                        matched_predicates=["analysis_truncated"],
                        authority_expands=True,
                        structural_units=recommendation.structural_units,
                    )
                elif fm == "require_approval":
                    recommendation = PredictiveRecommendation(
                        action="require_approval",
                        reason="analysis_truncated: incomplete — not concluded safe",
                        matched_predicates=["analysis_truncated"],
                        authority_expands=True,
                        structural_units=recommendation.structural_units,
                    )

            result.recommendation = recommendation

            meta = dict(action.metadata or {})
            pa_meta = dict(meta.get("predictive_authority") or {})
            pa_meta["max_reachability_depth"] = self.config.max_depth
            meta["predictive_authority"] = pa_meta
            action.metadata = meta
            annotate_action_predicates(action, delta=delta, findings=result.findings, recommendation=recommendation)

            final = existing
            if self.config.is_enforce():
                final = strengthen_decision(existing, recommendation)
            result.final_decision = final

            explanation = build_explanation(
                action_summary=facts.summary,
                before=before_view,
                delta=delta,
                findings=result.findings,
                existing_decision=existing.action,
                predictive_recommendation=recommendation.action,
                final_decision=final.action,
                mode=self.config.mode,
            )
            result.explanation = explanation

            if budget is not None and commit:
                budget.apply(delta, summary=facts.summary)
                result.budget = budget
                registry.set_budget(key, budget)

            graph_dict = state.graph.to_dict()
            result.historical_snapshot = build_historical_snapshot(
                result=result,
                graph=graph_dict,
                session_key=key,
                trace_id=action.trace_id,
                tenant_id=action.tenant_id,
            )

            if commit:
                state.record_transition(
                    AuthorityTransitionRecord(
                        timestamp=time.time(),
                        action_summary=facts.summary,
                        added_capabilities=[c.name for c in delta.added_capabilities],
                        added_resources=[r.identifier for r in delta.added_sensitive_resources],
                        added_sinks=[r.identifier for r in delta.added_sinks],
                        irreversible=facts.irreversible,
                    ),
                    max_history=self.config.max_history,
                )
                registry.remember_explanation(key, explanation.to_dict())
                # Process-local event view for live session UI (also stamped with event_id on persist).
                registry.remember_event_view(
                    key,
                    {
                        "action_summary": facts.summary,
                        "mode": self.config.mode,
                        "analysis_status": result.analysis_status,
                        "analysis_incomplete_reason": result.analysis_incomplete_reason,
                        "max_depth": self.config.max_depth,
                        "existing_decision": existing.action,
                        "recommendation": recommendation.action,
                        "final_decision": final.action,
                        "delta": delta.to_dict(),
                        "hazardous_paths": [f.to_dict() for f in result.findings],
                        "explanation": explanation.to_dict(),
                        "before": result.before_snapshot,
                        "after": result.after_snapshot,
                        "graph": graph_dict,
                        "timestamp": time.time(),
                        "content_hash": (result.historical_snapshot or {}).get("content_hash"),
                    },
                )

            if self.config.audit:
                meta = dict(action.metadata or {})
                meta["predictive_authority"] = result.to_metadata()
                action.metadata = meta
            # Side-channel for durable persist after event_id is assigned (not in to_dict).
            try:
                object.__setattr__(action, "_varden_pa_snapshot", result.historical_snapshot)
            except Exception:
                pass

        except Exception as exc:  # noqa: BLE001 — fail-safe boundary
            result.error = f"{type(exc).__name__}: {exc}"
            result.analysis_status = AnalysisStatus.FAILED.value
            result.analysis_incomplete_reason = "ENGINE_FAILURE"
            fm = self.config.resolved_failure_mode() if self.config.is_enforce() else "preserve_existing"
            result.final_decision = _failure_decision(existing, fm) if self.config.is_enforce() else existing
            if self.config.audit:
                meta = dict(action.metadata or {})
                meta["predictive_authority"] = {
                    "mode": self.config.mode,
                    "error": result.error,
                    "analysis_status": result.analysis_status,
                    "failure_mode": fm,
                    "fail_safe": result.final_decision.action if result.final_decision else existing.action,
                    "safe_conclusion": False,
                }
                action.metadata = meta

        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        return result.final_decision or existing, result


def resolve_config(
    *,
    policy: dict[str, Any] | None = None,
    action: Action | None = None,
    explicit: PredictiveAuthorityConfig | None = None,
    env: dict[str, str] | None = None,
) -> PredictiveAuthorityConfig:
    if explicit is not None:
        return explicit
    raw = None
    if policy and isinstance(policy.get("predictive_authority"), dict):
        raw = policy
    elif action and isinstance((action.metadata or {}).get("predictive_authority_config"), dict):
        raw = (action.metadata or {}).get("predictive_authority_config")
    return parse_predictive_config(raw, env=env)


def apply_predictive_authority(
    action: Action,
    decision: Decision,
    *,
    policy: dict[str, Any] | None = None,
    config: PredictiveAuthorityConfig | None = None,
    env: dict[str, str] | None = None,
) -> tuple[Decision, PredictiveResult]:
    """Public integration point for the control-plane evaluate path."""
    cfg = resolve_config(policy=policy, action=action, explicit=config, env=env)
    engine = PredictiveAuthorityEngine(cfg)
    return engine.evaluate(action, decision, policy=policy or {})
