"""CLI for provenance / authority-flow commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .demo import run_provenance_demo
from .evaluate import run_evaluation
from .engine import analyse_action, explain_analysis
from .store import ProvenanceStore
from ..models import Action


def provenance_argv(args: Any) -> int:
    command = getattr(args, "provenance_command", None) or getattr(args, "authority_command", None)

    if getattr(args, "command", None) == "authority" and getattr(args, "authority_command", None) == "violations":
        return _cmd_violations(args)
    if getattr(args, "command", None) == "authority" and getattr(args, "authority_command", None) == "explain":
        return _cmd_explain(args)

    if command == "demo":
        return run_provenance_demo(
            host=getattr(args, "host", "127.0.0.1"),
            port=int(getattr(args, "port", 8000)),
            open_browser=not getattr(args, "no_browser", False),
        )
    if command == "evaluate":
        result = run_evaluation(json_out=getattr(args, "json", False))
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    if command == "sources":
        return _cmd_sources(args)
    if command == "trace":
        return _cmd_trace(args)
    if command == "explain":
        return _cmd_explain(args)
    if command == "violations":
        return _cmd_violations(args)

    print("Unknown provenance/authority command", file=sys.stderr)
    return 2


def _db_path(args: Any) -> str:
    return str(getattr(args, "db", None) or Path("varden.db"))


def _cmd_sources(args: Any) -> int:
    store = ProvenanceStore(_db_path(args))
    trace_id = getattr(args, "trace_id", None)
    if not trace_id:
        print("trace_id required", file=sys.stderr)
        return 2
    items = store.sources_for_trace(trace_id)
    print(json.dumps([s.to_dict() for s in items], indent=2))
    return 0


def _cmd_trace(args: Any) -> int:
    from ..stores import EventStore

    store = ProvenanceStore(_db_path(args))
    events = EventStore(_db_path(args)).list_trace_events(args.trace_id, limit=200)
    sources = store.sources_for_trace(args.trace_id)
    findings = [f for f in store.list_findings(limit=200) if f.get("trace_id") == args.trace_id]
    print(json.dumps({
        "trace_id": args.trace_id,
        "events": events,
        "sources": [s.to_dict() for s in sources],
        "findings": findings,
    }, indent=2, default=str))
    return 0


def _cmd_explain(args: Any) -> int:
    from ..stores import EventStore

    event_id = int(getattr(args, "event_id"))
    event = EventStore(_db_path(args)).get_event(event_id)
    if not event:
        # Allow explaining a synthetic action JSON file for offline use.
        path = getattr(args, "action_file", None)
        if path:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            analysis = analyse_action(Action(**{k: raw[k] for k in Action.__dataclass_fields__ if k in raw}) if isinstance(raw, dict) and "type" in raw else raw)
            print(explain_analysis(analysis, decision="ANALYSIS"))
            return 0
        print(f"event {event_id} not found", file=sys.stderr)
        return 1
    meta = (event.get("action") or {}).get("metadata") or {}
    decision = (event.get("decision") or {}).get("action")
    print(explain_analysis(meta, decision=decision))
    return 0


def _cmd_violations(args: Any) -> int:
    store = ProvenanceStore(_db_path(args))
    items = store.list_findings(limit=int(getattr(args, "limit", 50) or 50))
    interesting = {
        "delegation_violation", "authority_escalation", "confused_deputy",
        "untrusted_to_privileged", "provenance_exfiltration_chain",
        "unknown_provenance_sensitive_action", "cross_server_authority_flow",
    }
    rows = [r for r in items if r["type"] in interesting]
    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2))
    else:
        if not rows:
            print("No authority violations recorded.")
            return 0
        for row in rows:
            print(f"[{row['severity']}] {row['type']} trace={row.get('trace_id')} tool={row.get('tool')}")
            print(f"  {row.get('explanation')}")
    return 0
