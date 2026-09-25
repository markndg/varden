"""`varden keys`: provision API keys directly in the auth database.

Local-auth deployments with dev bootstrap disabled have no built-in
credential, so the operator creates them here (filesystem access to the auth
DB is the trust anchor). Raw keys are printed once and stored only as SHA-256.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .auth import DEV_API_KEYS, OSS_TENANT_ID, ROLES, LocalAuth
from .config import AppConfig


def _auth_db(args: Any) -> str:
    if getattr(args, "auth_db", None):
        return args.auth_db
    if getattr(args, "config", None):
        return AppConfig.from_env_file(args.config).auth_db_path
    return os.getenv("VARDEN_AUTH_DB_PATH", "varden_auth.db")


def add_keys_parser(sub: Any) -> None:
    keys = sub.add_parser("keys", help="Create, list or revoke API keys in the auth database")
    keys.add_argument("--config", default=None, help="Env file used by the server (to locate the auth DB)")
    keys.add_argument("--auth-db", default=None, help="Path to the auth DB (overrides --config / VARDEN_AUTH_DB_PATH)")
    keys_sub = keys.add_subparsers(dest="keys_command")
    create = keys_sub.add_parser("create", help="Create a key and print it once")
    create.add_argument("--role", required=True, choices=sorted(ROLES, key=ROLES.get),
                        help="agent = ingest-only (give this to protected processes); viewer/analyst/admin = humans")
    create.add_argument("--json", action="store_true")
    lst = keys_sub.add_parser("list", help="List key hashes, roles and revocation state")
    lst.add_argument("--json", action="store_true")
    revoke = keys_sub.add_parser("revoke", help="Revoke a raw key")
    revoke.add_argument("api_key")


def keys_argv(args: Any) -> int:
    auth = LocalAuth(_auth_db(args), None, manage_signing_keys=False)
    cmd = getattr(args, "keys_command", None)
    if cmd == "create":
        rec = auth.create_api_key(tenant_id=OSS_TENANT_ID, role=args.role)
        if args.json:
            print(json.dumps(rec))
        else:
            print(rec["api_key"])
            print(f"# role={rec['role']} — shown once; store it now.", flush=True)
        return 0
    if cmd == "list":
        rows = auth.list_api_keys()
        for row in rows:
            row["dev_demo_key"] = any(row["key_hash"] == __import__("hashlib").sha256(k.encode()).hexdigest() for k in DEV_API_KEYS)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                state = "revoked" if row["revoked"] else "active"
                tag = " (public demo key)" if row["dev_demo_key"] else ""
                print(f"{row['key_hash'][:16]}…  {row['role']:<8} {state}{tag}")
        return 0
    if cmd == "revoke":
        auth.revoke_api_key(args.api_key)
        print("revoked")
        return 0
    print("usage: varden keys {create,list,revoke}")
    return 2
