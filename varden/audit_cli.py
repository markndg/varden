"""CLI for audit integrity verification."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _default_db_path() -> str:
    return os.environ.get("VARDEN_DB_PATH") or str(Path.cwd() / "varden.db")


def audit_argv(args: argparse.Namespace) -> int:
    cmd = getattr(args, "audit_command", None)
    if cmd != "verify":
        print("usage: varden audit verify [--db PATH] [--json]", file=sys.stderr)
        return 2

    from varden.audit_integrity import format_verify_report
    from varden.stores import EventStore

    db_path = getattr(args, "db", None) or _default_db_path()
    store = EventStore(db_path)
    result = store.verify_integrity()
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_verify_report(result), end="")
    if result.get("valid"):
        return 0
    return 1
