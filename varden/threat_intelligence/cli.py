"""``varden intelligence`` commands.

``--json`` writes one JSON document to stdout and nothing else.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .approval import ApprovalError
from .config import ThreatIntelConfig
from .service import ThreatIntelService


def intelligence_argv(args: Any) -> int:
    command = getattr(args, "intelligence_command", None)
    config = ThreatIntelConfig.from_env()
    if getattr(args, "db", None):
        config.db_path = args.db
    if getattr(args, "policy", None):
        config.policy_file = args.policy
    service = _service(config)
    json_mode = bool(getattr(args, "json", False))
    try:
        if command == "status":
            return _emit(service.status(), json_mode, _print_status)
        if command == "sources":
            payload = {"sources": service.source_views()}
            return _emit(payload, json_mode, _print_sources)
        if command == "check":
            payload = service.check(getattr(args, "source", None))
            return _emit(payload, json_mode, _print_check)
        if command == "list":
            payload = service.list_items(
                source=getattr(args, "source", None),
                severity=getattr(args, "severity", None),
                lifecycle=getattr(args, "lifecycle", None),
                applicability=getattr(args, "status", None),
                since=getattr(args, "since", None),
                until=getattr(args, "until", None),
                surface=getattr(args, "surface", None),
            )
            return _emit(payload, json_mode, _print_list)
        if command == "show":
            return _emit(service.show(args.item_id), json_mode, _print_show)
        if command == "contract":
            return _emit(service.contract_for(args.item_id), json_mode, lambda payload: _print_json_human(payload))
        if command == "candidate":
            return _emit(service.candidate_for(args.item_id), json_mode, lambda payload: _print_json_human(payload))
        if command == "replay":
            return _emit(service.replay(args.item_id), json_mode, _print_replay)
        if command == "approve":
            return _emit(service.approve(args.item_id, actor=getattr(args, "actor", None) or "cli"), json_mode, _print_decision)
        if command == "dismiss":
            return _emit(service.decide(args.item_id, "dismiss", actor=getattr(args, "actor", None) or "cli"), json_mode, _print_decision)
        if command == "not-applicable":
            return _emit(service.decide(args.item_id, "not_applicable", actor=getattr(args, "actor", None) or "cli"), json_mode, _print_decision)
        if command == "review":
            return _emit(service.decide(args.item_id, "review", actor=getattr(args, "actor", None) or "cli"), json_mode, _print_decision)
    except KeyError:
        return _fail("unknown item or source", json_mode)
    except ApprovalError as exc:
        return _fail(exc.message, json_mode)
    print("Unknown intelligence command", file=sys.stderr)
    return 2


def _service(config: ThreatIntelConfig) -> ThreatIntelService:
    policy_engine = None
    event_store = None
    try:
        from varden.policy import PolicyEngine
        from varden.stores import EventStore

        event_store = EventStore(config.db_path)
        initial = None
        from pathlib import Path

        path = Path(config.policy_file)
        if path.exists():
            initial = json.loads(path.read_text(encoding="utf-8"))
        policy_engine = PolicyEngine(config.db_path, initial)
    except Exception:
        policy_engine = None
    return ThreatIntelService(config, policy_engine=policy_engine, event_store=event_store)


def _emit(payload: dict[str, Any], json_mode: bool, human) -> int:
    if json_mode:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0
    human(payload)
    return 0


def _fail(message: str, json_mode: bool) -> int:
    if json_mode:
        sys.stdout.write(json.dumps({"error": message}, sort_keys=True) + "\n")
    else:
        print(message, file=sys.stderr)
    return 1


def _print_status(payload: dict[str, Any]) -> None:
    print(f"Threat intelligence watcher: {payload.get('watcher')}")
    print(payload.get("watcher_meaning"))
    print(f"Enabled: {payload.get('enabled')}")
    last = payload.get("last_success")
    print(f"Last successful check: {last if last else 'never'}")
    nxt = payload.get("next_check")
    print(f"Next scheduled check: {nxt if nxt else 'not scheduled'}")
    print(f"New intelligence items: {payload.get('new_items')}")
    print(f"Affecting this runtime: {payload.get('affecting_this_runtime')}")
    counts = payload.get("counts") or {}
    print(
        "Stored {total}  Mapped {mapped}  Unmapped {unmapped}  Protected {protected}  Exposed {exposed}  Review {review}  Not applicable {not_applicable}  Awaiting approval {candidates_awaiting}".format(
            total=counts.get("total", 0),
            mapped=counts.get("mapped", 0),
            unmapped=counts.get("unmapped", 0),
            protected=counts.get("protected", 0),
            exposed=counts.get("exposed", 0),
            review=counts.get("review", 0),
            not_applicable=counts.get("not_applicable", 0),
            candidates_awaiting=counts.get("candidates_awaiting", 0),
        )
    )


def _print_sources(payload: dict[str, Any]) -> None:
    for row in payload.get("sources") or []:
        print(f"{row.get('title')}: {row.get('health')} ({row.get('implementation')})")
        if row.get("detail"):
            print(f"  {row.get('detail')}")


def _print_check(payload: dict[str, Any]) -> None:
    print(f"Watcher: {payload.get('watcher')}")
    for row in payload.get("sources") or []:
        print(f"{row.get('source')}: health={row.get('health')} items={row.get('items', 0)} fetched={row.get('fetched')}")


def _print_list(payload: dict[str, Any]) -> None:
    items = payload.get("items") or []
    if not items:
        print("No threat intelligence items.")
        return
    for row in items:
        active = "active" if row.get("rule_active") else "not active"
        print(
            f"{row.get('id')}  {row.get('applicability') or '-'}  {row.get('lifecycle')}  "
            f"{row.get('source')}  {row.get('severity')}  rule {active}"
        )


def _print_show(payload: dict[str, Any]) -> None:
    print(payload.get("title") or payload.get("id"))
    print(f"Source: {payload.get('source')} {payload.get('source_id')}")
    print(f"Lifecycle: {payload.get('lifecycle')}")
    print(f"Applicability: {payload.get('applicability')}")
    print(f"Rule active: {payload.get('rule_active')}")
    contract = payload.get("contract") or {}
    if contract:
        print(f"Contract: {contract.get('id') or 'none'}")
        print(contract.get("explanation") or "")
    assessment = payload.get("assessment") or {}
    for reason in assessment.get("reasons") or []:
        print(f"- {reason}")


def _print_replay(payload: dict[str, Any]) -> None:
    replay = payload.get("replay") or {}
    print(f"Replay status: {replay.get('status')}")
    print(f"Operations analysed: {replay.get('operations_analysed')}")
    print(f"Unaffected: {replay.get('unaffected')}")
    print(f"Would allow: {replay.get('would_allow')}")
    print(f"Would challenge: {replay.get('would_challenge')}")
    print(f"Would require approval: {replay.get('would_require_approval')}")
    print(f"Would deny: {replay.get('would_deny')}")
    print(f"Unknown: {replay.get('unknown')}")
    if replay.get("reason"):
        print(replay["reason"])


def _print_decision(payload: dict[str, Any]) -> None:
    print(f"{payload.get('item_id')} -> {payload.get('lifecycle')}")
    if "rule_active" in payload:
        print(f"Rule active: {payload.get('rule_active')}")


def _print_json_human(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
