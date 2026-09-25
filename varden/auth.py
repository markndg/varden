from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time, uuid

OSS_TENANT_ID = "default"
from .db import connect, init_db

# "agent" is an ingest-only role for protected processes (SDK, MCP gateway,
# session shims, browser extension). It can submit actions for a decision and
# log results, and nothing else: it cannot read events, change policy or
# approve anything. Give agents this role, never a human role.
ROLES = {"agent": 0, "viewer": 1, "analyst": 2, "admin": 3}

# Well-known development credentials. These strings are public (they are in the
# README), so they are only ever valid while dev bootstrap is enabled. Starting
# with dev bootstrap disabled actively revokes them.
DEV_ADMIN_API_KEY = "admin-demo-key"
DEV_AGENT_API_KEY = "agent-demo-key"
DEV_API_KEYS = (DEV_ADMIN_API_KEY, DEV_AGENT_API_KEY)

class LocalAuth:
    def __init__(self, db_path: str, signing_secret: str | None, *, manage_signing_keys: bool = True):
        self.db_path = db_path
        self.signing_secret = signing_secret
        init_db(db_path)
        # Offline tools (`varden keys`) pass manage_signing_keys=False so they
        # never rotate the server's signing key to whatever their env holds.
        if manage_signing_keys and signing_secret:
            self._ensure_active_signing_key(signing_secret)

    def _ensure_active_signing_key(self, signing_secret: str) -> None:
        """Make the configured secret the only active signing key.

        Previously the configured secret was only used when the auth DB was first
        created, so a DB initialised in dev kept signing (and verifying) bearer
        tokens with ``change-me`` forever, and changing VARDEN_SIGNING_SECRET had
        no effect. Now the configured secret always wins; older keys are
        deactivated and are no longer accepted for verification.
        """
        keys = self.list_signing_keys()
        current = next((k for k in keys if hmac.compare_digest(str(k["secret"]), str(signing_secret))), None)
        with connect(self.db_path) as conn:
            conn.execute("UPDATE signing_keys SET active = 0")
            if current is not None:
                conn.execute("UPDATE signing_keys SET active = 1 WHERE key_id = ?", (current["key_id"],))
            conn.commit()
        if current is None:
            self.add_signing_key(signing_secret, active=True)

    def create_tenant(self, name: str):
        tenant_id = OSS_TENANT_ID if name == OSS_TENANT_ID else str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO tenants(tenant_id,name,created_at) VALUES (?,?,?)", (tenant_id, name, time.time()))
            conn.commit()
        return {"tenant_id": tenant_id, "name": name}

    def get_tenant_by_name(self, name: str):
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM tenants WHERE name = ? ORDER BY created_at ASC LIMIT 1", (name,)).fetchone()
            return dict(row) if row else None

    def ensure_tenant(self, name: str):
        return self.get_tenant_by_name(name) or self.create_tenant(name)

    def create_user(self, username: str, tenant_id: str, role: str = "viewer"):
        user_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO users(user_id,username,tenant_id,role,created_at) VALUES (?,?,?,?,?)",
                         (user_id, username, tenant_id, role, time.time()))
            conn.commit()
        return {"user_id": user_id, "username": username, "tenant_id": tenant_id, "role": role}

    def get_user(self, username: str, tenant_id: str):
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND tenant_id = ? ORDER BY created_at ASC LIMIT 1",
                (username, tenant_id),
            ).fetchone()
            return dict(row) if row else None

    def ensure_user(self, username: str, tenant_id: str, role: str = "viewer"):
        user = self.get_user(username, tenant_id)
        if user:
            if user.get("role") != role:
                with connect(self.db_path) as conn:
                    conn.execute("UPDATE users SET role = ? WHERE user_id = ?", (role, user["user_id"]))
                    conn.commit()
                user["role"] = role
            return user
        return self.create_user(username, tenant_id, role=role)


    def list_tenants(self):
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM tenants ORDER BY created_at ASC").fetchall()]

    def list_users(self, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute("SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at ASC", (tenant_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
            return [dict(r) for r in rows]

    def list_api_keys(self, tenant_id: str | None = None):
        with connect(self.db_path) as conn:
            if tenant_id:
                rows = conn.execute("SELECT key_hash,tenant_id,role,created_at,revoked,revoked_at FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
            else:
                rows = conn.execute("SELECT key_hash,tenant_id,role,created_at,revoked,revoked_at FROM api_keys ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def revoke_api_key(self, api_key: str):
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with connect(self.db_path) as conn:
            conn.execute("UPDATE api_keys SET revoked = 1, revoked_at = ? WHERE key_hash = ?", (time.time(), key_hash))
            conn.commit()
        return {"revoked": True, "key_hash": key_hash}

    def create_service_account(self, name: str, tenant_id: str, role: str = "viewer"):
        username = f"svc::{name}"
        user = self.ensure_user(username, tenant_id, role=role)
        key = self.create_api_key(tenant_id=tenant_id, role=role)
        return {"user": user, "api_key": key["api_key"]}

    def create_api_key(self, key: str | None = None, tenant_id: str | None = None, role: str = "viewer"):
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {sorted(ROLES)}")
        raw = key or secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        with connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO api_keys(key_hash,tenant_id,role,created_at,revoked,revoked_at) VALUES (?,?,?,?,0,NULL)",
                         (key_hash, tenant_id, role, time.time()))
            conn.commit()
        return {"api_key": raw, "tenant_id": tenant_id, "role": role}

    def authenticate_api_key(self, api_key: str):
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
            if not row:
                return None
            rec = dict(row)
            return None if rec["revoked"] else rec

    def add_signing_key(self, secret: str, active: bool = True):
        key_id = str(uuid.uuid4())
        with connect(self.db_path) as conn:
            conn.execute("INSERT INTO signing_keys(key_id,secret,created_at,active) VALUES (?,?,?,?)",
                         (key_id, secret, time.time(), 1 if active else 0))
            conn.commit()
        return {"key_id": key_id, "active": active}

    def list_signing_keys(self):
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM signing_keys ORDER BY created_at DESC").fetchall()]

    def _active_signing_key(self):
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT * FROM signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def issue_bearer_token(self, user_id: str, tenant_id: str, role: str, expires_in: int = 3600):
        signing = self._active_signing_key()
        effective_tenant_id = OSS_TENANT_ID if tenant_id else OSS_TENANT_ID
        payload = {"user_id": user_id, "tenant_id": effective_tenant_id, "role": role, "exp": int(time.time()) + expires_in, "kid": signing["key_id"]}
        body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("utf-8").rstrip("=")
        sig = hmac.new(signing["secret"].encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

    def verify_bearer_token(self, token: str):
        try:
            body, sig = token.split(".", 1)
            payload = json.loads(base64.urlsafe_b64decode((body + "=" * (-len(body) % 4)).encode("utf-8")).decode("utf-8"))
            if payload.get("exp", 0) < int(time.time()):
                return None
            for key in self.list_signing_keys():
                if not key.get("active"):
                    continue
                if key["key_id"] != payload.get("kid"):
                    continue
                expected = hmac.new(key["secret"].encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, expected):
                    return payload
            return None
        except Exception:
            return None

    def require_role(self, api_key: str | None = None, bearer_token: str | None = None, min_role: str = "viewer"):
        record = None
        if api_key:
            record = self.authenticate_api_key(api_key)
        if record is None and bearer_token:
            record = self.verify_bearer_token(bearer_token)
        if record is None and bearer_token:
            record = self.authenticate_api_key(bearer_token)
        if not record:
            return False, "invalid credentials", None
        record = dict(record)
        record["tenant_id"] = OSS_TENANT_ID
        if ROLES.get(record.get("role"), -1) < ROLES[min_role]:
            return False, "insufficient role", record
        return True, "ok", record
