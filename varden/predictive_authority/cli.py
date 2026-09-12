"""CLI diagnostics for Predictive Authority."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .config import parse_predictive_config
from .registry import get_authority_registry


def predictive_authority_argv(args: Any) -> int:
    command = getattr(args, "authority_command", None) or getattr(args, "predictive_command", None)
    if command == "status":
        return cmd_status(args)
    if command == "graph":
        return cmd_graph(args)
    if command == "paths":
        return cmd_paths(args)
    if command == "budget":
        return cmd_budget(args)
    if command == "explain":
        return cmd_explain(args)
    if command == "demo":
        from .demo import run_predictive_demo

        return run_predictive_demo(json_out=getattr(args, "json", False))
    print("Unknown predictive authority command", file=sys.stderr)
    return 2


def _session_key(args: Any) -> str:
    tenant = getattr(args, "tenant", None) or "default"
    trace = getattr(args, "trace_id", None) or getattr(args, "trace", None) or "default"
    return f"{tenant}:{trace}"


def cmd_status(args: Any) -> int:
    reg = get_authority_registry()
    key = _session_key(args)
    state = reg.get(key)
    text = render_status(key, state, reg.budget(key), reg.last_explanation(key))
    if getattr(args, "json", False):
        payload = {
            "session_key": key,
            "state": state.to_dict() if state else None,
            "budget": reg.budget(key).to_dict() if reg.budget(key) else None,
            "last_explanation": reg.last_explanation(key),
        }
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(text)
    return 0


def render_status(key: str, state: Any, budget: Any, explanation: dict | None) -> str:
    lines = [
        "VARDEN PREDICTIVE AUTHORITY",
        "",
        f"Session: {key}",
    ]
    if state is None:
        lines.append("Mode: (no active predictive session in this process)")
        lines.append("")
        lines.append("Hint: enable predictive_authority in policy or VARDEN_PA_MODE=observe")
        return "\n".join(lines) + "\n"

    confirmed = state.confirmed_capabilities()
    potential = state.potential_capabilities()
    sensitive = state.sensitive_resources()
    sinks = state.external_sinks()
    lines.extend(
        [
            "",
            f"Current capabilities: {len(confirmed)} confirmed / {len(potential)} potential",
            f"Sensitive resources: {len(sensitive)}",
            f"External sinks: {len(sinks)}",
        ]
    )
    if state.history:
        last = state.history[-1]
        lines.extend(
            [
                "",
                f"Last transition: {last.action_summary}",
                f"Authority change: +{len(last.added_capabilities)} capabilities",
            ]
        )
    if explanation:
        lines.extend(
            [
                "",
                f"Existing decision: {str(explanation.get('existing_decision') or '').upper()}",
                f"Predictive recommendation: {str(explanation.get('predictive_recommendation') or '').upper()}",
                f"Final decision: {str(explanation.get('final_decision') or '').upper()}"
                + (f" ({explanation.get('mode')} mode)" if explanation.get("mode") == "observe" else ""),
            ]
        )
        paths = explanation.get("hazardous_paths") or []
        if paths:
            lines.append("")
            lines.append("Hazardous path")
            lines.append(f"  {paths[0]}")
        if explanation.get("privilege_domains"):
            lines.append("New privileged domains: " + ", ".join(explanation["privilege_domains"]))
    if budget and budget.enabled:
        lines.extend(
            [
                "",
                f"Authority budget: {budget.current_units}/{budget.max_units} (remaining {budget.remaining})",
            ]
        )
    return "\n".join(lines) + "\n"


def cmd_graph(args: Any) -> int:
    reg = get_authority_registry()
    state = reg.get(_session_key(args))
    if state is None:
        print(json.dumps({"error": "no_session"}))
        return 1
    print(json.dumps(state.graph.to_dict(), indent=2))
    return 0


def cmd_paths(args: Any) -> int:
    from .hazardous import detect_hazardous_paths

    reg = get_authority_registry()
    state = reg.get(_session_key(args))
    if state is None:
        print(json.dumps({"error": "no_session"}))
        return 1
    depth = int(getattr(args, "max_depth", 3) or 3)
    findings = detect_hazardous_paths(state.graph, max_depth=depth)
    print(json.dumps([f.to_dict() for f in findings], indent=2))
    return 0


def cmd_budget(args: Any) -> int:
    reg = get_authority_registry()
    budget = reg.budget(_session_key(args))
    if budget is None:
        print("No authority budget for session.")
        return 0
    print(json.dumps(budget.to_dict(), indent=2))
    return 0


def cmd_explain(args: Any) -> int:
    reg = get_authority_registry()
    explanation = reg.last_explanation(_session_key(args))
    event_id = getattr(args, "event_id", None)
    if event_id and not explanation:
        # Fall back to event metadata from store.
        from ..stores import EventStore

        db = str(getattr(args, "db", None) or Path("varden.db"))
        store = EventStore(db)
        row = store.get_event(int(event_id))
        if not row:
            print(f"event {event_id} not found", file=sys.stderr)
            return 1
        action = row.get("action") or {}
        explanation = ((action.get("metadata") or {}).get("predictive_authority") or {}).get("explanation")
        if explanation is None:
            explanation = (action.get("metadata") or {}).get("predictive_authority")
    if not explanation:
        print("No predictive explanation available.", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(explanation, indent=2, default=str))
    else:
        from .counterfactual import CounterfactualExplanation

        if isinstance(explanation, dict) and "action_summary" in explanation:
            print(
                CounterfactualExplanation(
                    action_summary=str(explanation.get("action_summary") or ""),
                    current_capabilities=list(explanation.get("current_capabilities") or []),
                    newly_reachable=list(explanation.get("newly_reachable") or []),
                    newly_potential=list(explanation.get("newly_potential") or []),
                    hazardous_paths=list(explanation.get("hazardous_paths") or []),
                    shortest_trajectory_length=explanation.get("shortest_trajectory_length"),
                    existing_decision=str(explanation.get("existing_decision") or "allow"),
                    predictive_recommendation=str(explanation.get("predictive_recommendation") or "allow"),
                    final_decision=str(explanation.get("final_decision") or "allow"),
                    mode=str(explanation.get("mode") or "observe"),
                    reason=str(explanation.get("reason") or ""),
                    provenance_evidence=list(explanation.get("provenance_evidence") or []),
                    irreversible=bool(explanation.get("irreversible")),
                    privilege_domains=list(explanation.get("privilege_domains") or []),
                ).render()
            )
        else:
            print(json.dumps(explanation, indent=2, default=str))
    return 0
