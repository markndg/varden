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
    if cmd == "redact-migrate":
        return _redact_migrate(args)
    if cmd != "verify":
        print("usage: varden audit verify|redact-migrate [--db PATH] [--json]", file=sys.stderr)
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


def _redact_migrate(args: argparse.Namespace) -> int:
    from varden.audit_migrate import redact_migrate
    from varden.stores import EventStore

    secret = os.environ.get("VARDEN_SIGNING_SECRET") or ""
    if len(secret) < 16:
        print("VARDEN_SIGNING_SECRET of at least 16 characters is required", file=sys.stderr)
        return 2
    db_path = getattr(args, "db", None) or _default_db_path()
    try:
        manifest = redact_migrate(db_path, master_secret=secret)
    except Exception as exc:
        print(f"redact-migrate failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    verified = EventStore(db_path).verify_integrity()
    report = {
        "affected_records": manifest["affected_records"],
        "original_head": manifest["original_head"],
        "replacement_head": manifest["replacement_head"],
        "chain_valid": bool(verified.get("valid")),
        "rewritten": True,
        "remanence": manifest["remanence"],
    }
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"affected_records={report['affected_records']} chain_valid={report['chain_valid']}\n{report['remanence']}"
        )
    return 0 if verified.get("valid") else 1
