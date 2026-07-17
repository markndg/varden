from __future__ import annotations

import os
import sys
from typing import Any

from .store import WebShieldStore

OSS_TENANT_ID = "default"


def _store(db_path: str | None) -> WebShieldStore:
    path = db_path or os.environ.get("VARDEN_DB_PATH", "varden.db")
    # Trust decisions are local and don't require the event pipeline or a
    # live policy engine; both are unused by the trust methods themselves.
    return WebShieldStore(path, event_store=None, policy_engine=None)


def _cmd_list(db_path: str | None) -> int:
    store = _store(db_path)
    rows = store.list_trust(OSS_TENANT_ID)
    if not rows:
        print("No local Web Shield trust decisions.")
        return 0
    print(f"{'origin':<40} {'state':<10} created_by")
    for row in rows:
        print(f"{row['origin']:<40} {row['state']:<10} {row.get('created_by') or '-'}")
    return 0


def _cmd_add(origin: str, db_path: str | None) -> int:
    store = _store(db_path)
    store.set_trust(OSS_TENANT_ID, origin, "trusted", created_by="cli")
    print(f"Trusted origin: {origin}")
    return 0


def _cmd_remove(origin: str, db_path: str | None) -> int:
    store = _store(db_path)
    removed = store.remove_trust(OSS_TENANT_ID, origin)
    print(f"Removed trust decision for {origin}." if removed else f"No trust decision found for {origin}.")
    return 0


def trust_argv(args: Any) -> int:
    command = getattr(args, "trust_command", None)
    db_path = getattr(args, "db_path", None)
    if command == "list":
        return _cmd_list(db_path)
    if command == "add":
        return _cmd_add(args.origin, db_path)
    if command == "remove":
        return _cmd_remove(args.origin, db_path)
    print("Usage: varden web-shield trust {list|add|remove}", file=sys.stderr)
    return 2
