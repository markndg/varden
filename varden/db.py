from __future__ import annotations
import sqlite3

SCHEMA = '''
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
INSERT OR IGNORE INTO schema_migrations(version) VALUES (2);

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash TEXT PRIMARY KEY,
  tenant_id TEXT,
  role TEXT NOT NULL,
  created_at REAL NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at REAL
);

CREATE TABLE IF NOT EXISTS signing_keys (
  key_id TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  created_at REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS workflow_sessions (
  workflow_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tenant_id TEXT,
  created_at REAL NOT NULL,
  closed_at REAL,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp REAL NOT NULL,
  action_json TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  status TEXT NOT NULL,
  input_payload_json TEXT,
  output_payload_json TEXT,
  error TEXT,
  replayable INTEGER NOT NULL DEFAULT 0,
  replay_key TEXT,
  workflow_id TEXT,
  agent_name TEXT,
  parent_event_id INTEGER,
  trace_id TEXT,
  tenant_id TEXT,
  event_hash TEXT,
  prev_hash TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at REAL NOT NULL,
  event_id INTEGER,
  tenant_id TEXT,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  sink TEXT NOT NULL,
  delivered INTEGER NOT NULL DEFAULT 0,
  acknowledged INTEGER NOT NULL DEFAULT 0,
  acknowledged_at REAL,
  acknowledged_by TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  key_hash TEXT PRIMARY KEY,
  created_at REAL NOT NULL,
  response_json TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at REAL NOT NULL,
  tenant_id TEXT,
  job_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  leased_until REAL,
  last_error TEXT,
  dead_lettered INTEGER NOT NULL DEFAULT 0,
  worker_id TEXT
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at REAL NOT NULL,
  created_by TEXT,
  version_name TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  status TEXT NOT NULL
);
'''


def _apply_migrations(conn):
    cols = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
    if "trace_id" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN trace_id TEXT")

    versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    if 3 not in versions:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS token_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              trace_id TEXT NOT NULL,
              workflow_id TEXT,
              timestamp REAL NOT NULL,
              model TEXT NOT NULL,
              input_tokens INTEGER NOT NULL,
              output_tokens INTEGER NOT NULL,
              cost_usd REAL NOT NULL,
              tool_name TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_token_events_trace_id ON token_events(trace_id);
            CREATE INDEX IF NOT EXISTS idx_token_events_workflow_id ON token_events(workflow_id);
            CREATE INDEX IF NOT EXISTS idx_token_events_timestamp ON token_events(timestamp);

            CREATE TABLE IF NOT EXISTS token_budgets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              policy_id TEXT NOT NULL,
              trace_id TEXT,
              workflow_id TEXT,
              window TEXT NOT NULL,
              limit_usd REAL NOT NULL,
              current_usd REAL NOT NULL DEFAULT 0,
              reset_at REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_token_budgets_key
              ON token_budgets(policy_id, window, COALESCE(trace_id, ''), COALESCE(workflow_id, ''));

            CREATE TABLE IF NOT EXISTS mcp_servers (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              config_path TEXT NOT NULL,
              transport TEXT,
              command TEXT,
              args_json TEXT,
              discovered_at REAL NOT NULL,
              last_scanned_at REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_name_path ON mcp_servers(name, config_path);

            CREATE TABLE IF NOT EXISTS mcp_tools (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              server_id INTEGER NOT NULL,
              tool_name TEXT NOT NULL,
              description TEXT,
              input_schema_json TEXT,
              discovered_at REAL NOT NULL,
              FOREIGN KEY(server_id) REFERENCES mcp_servers(id)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tools_server_name ON mcp_tools(server_id, tool_name);

            INSERT OR IGNORE INTO schema_migrations(version) VALUES (3);
            """
        )
    if 4 not in versions:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(token_budgets)").fetchall()}
        if "reserved_usd" not in cols:
            conn.execute(
                "ALTER TABLE token_budgets ADD COLUMN reserved_usd REAL NOT NULL DEFAULT 0"
            )
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (4)")

    if 5 not in versions:
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_events_tenant_trace ON events(tenant_id, trace_id);
            CREATE INDEX IF NOT EXISTS idx_events_tenant_timestamp ON events(tenant_id, timestamp);

            CREATE TABLE IF NOT EXISTS webshield_tools (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT,
              identity_key TEXT NOT NULL,
              owner_origin TEXT NOT NULL,
              top_origin TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              api_surface TEXT NOT NULL,
              exact_hash TEXT NOT NULL,
              canonical_hash TEXT NOT NULL,
              tool_json TEXT NOT NULL,
              risk_score INTEGER NOT NULL DEFAULT 0,
              risk_band TEXT NOT NULL DEFAULT 'low',
              findings_json TEXT NOT NULL DEFAULT '[]',
              trust_state TEXT,
              status TEXT NOT NULL DEFAULT 'active',
              registration_count INTEGER NOT NULL DEFAULT 1,
              first_seen_at REAL NOT NULL,
              last_seen_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_webshield_tools_identity
              ON webshield_tools(tenant_id, identity_key);
            CREATE INDEX IF NOT EXISTS idx_webshield_tools_owner_origin ON webshield_tools(owner_origin);

            CREATE TABLE IF NOT EXISTS webshield_sessions (
              session_id TEXT PRIMARY KEY,
              tenant_id TEXT,
              tab_id TEXT,
              top_origin TEXT,
              started_at REAL NOT NULL,
              last_seen_at REAL NOT NULL,
              extension_version TEXT,
              sdk_version TEXT,
              connected INTEGER NOT NULL DEFAULT 1,
              protection_mode TEXT NOT NULL DEFAULT 'connected'
            );
            CREATE INDEX IF NOT EXISTS idx_webshield_sessions_tenant ON webshield_sessions(tenant_id);

            CREATE TABLE IF NOT EXISTS webshield_trust (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT,
              origin TEXT NOT NULL,
              state TEXT NOT NULL,
              created_at REAL NOT NULL,
              created_by TEXT,
              expires_at REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_webshield_trust_origin ON webshield_trust(tenant_id, origin);

            CREATE TABLE IF NOT EXISTS webshield_approvals (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT,
              request_id TEXT NOT NULL,
              session_id TEXT,
              identity_key TEXT,
              tool_name TEXT,
              owner_origin TEXT,
              args_summary_json TEXT,
              risk_score INTEGER NOT NULL DEFAULT 0,
              risk_band TEXT,
              reason TEXT,
              status TEXT NOT NULL DEFAULT 'pending',
              created_at REAL NOT NULL,
              resolved_at REAL,
              resolved_by TEXT,
              expires_at REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_webshield_approvals_request ON webshield_approvals(tenant_id, request_id);

            INSERT OR IGNORE INTO schema_migrations(version) VALUES (5);
            """
        )

    if 6 not in versions:
        # Idempotency hardening (docs/web-shield-hardening-review.md #3): the
        # cache identity must be scoped by tenant/principal/method/route, and
        # store a body hash (to detect key reuse with a different request)
        # plus an expiry. Existing rows predate scoping and are simply
        # unreachable under the new composite key_hash going forward (they
        # are not "history" — idempotency entries are an ephemeral dedup
        # cache, not an audit trail, so leaving them as harmless orphans
        # rather than deleting them is the safest migration).
        cols = {row[1] for row in conn.execute("PRAGMA table_info(idempotency_keys)").fetchall()}
        if "body_hash" not in cols:
            conn.execute("ALTER TABLE idempotency_keys ADD COLUMN body_hash TEXT")
        if "expires_at" not in cols:
            conn.execute("ALTER TABLE idempotency_keys ADD COLUMN expires_at REAL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_expires_at ON idempotency_keys(expires_at)")
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (6)")

    if 7 not in versions:
        # Recursive canonicalisation (docs/web-shield-hardening-review.md #7):
        # add the structural_hash column alongside the existing exact_hash/
        # canonical_hash columns (kept for compatibility; canonical_hash now
        # holds the fully recursive security_normalised_hash). Also adds the
        # registration-instance-identity columns (docs/web-shield-hardening-review.md #6):
        # existing rows are migrated in place and marked legacy_instance
        # since they predate per-instance tracking and cannot retroactively
        # resolve which frame/session actually produced them.
        tool_cols = {row[1] for row in conn.execute("PRAGMA table_info(webshield_tools)").fetchall()}
        if "structural_hash" not in tool_cols:
            conn.execute("ALTER TABLE webshield_tools ADD COLUMN structural_hash TEXT")
        if "instance_id" not in tool_cols:
            conn.execute("ALTER TABLE webshield_tools ADD COLUMN instance_id TEXT")
        if "frame_id" not in tool_cols:
            conn.execute("ALTER TABLE webshield_tools ADD COLUMN frame_id TEXT")
        if "session_id" not in tool_cols:
            conn.execute("ALTER TABLE webshield_tools ADD COLUMN session_id TEXT")
        if "instance_provenance" not in tool_cols:
            conn.execute("ALTER TABLE webshield_tools ADD COLUMN instance_provenance TEXT")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS webshield_tool_instances (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT,
              instance_id TEXT NOT NULL,
              identity_key TEXT NOT NULL,
              owner_origin TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              session_id TEXT,
              frame_id TEXT,
              registration_source TEXT,
              exact_hash TEXT,
              canonical_hash TEXT,
              structural_hash TEXT,
              tool_json TEXT,
              status TEXT NOT NULL DEFAULT 'active',
              legacy_instance INTEGER NOT NULL DEFAULT 0,
              first_seen_at REAL NOT NULL,
              last_seen_at REAL NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_webshield_instances_id ON webshield_tool_instances(tenant_id, instance_id);
            CREATE INDEX IF NOT EXISTS idx_webshield_instances_identity ON webshield_tool_instances(tenant_id, identity_key);
            """
        )
        # Backfill: give every pre-existing logical tool row a synthetic
        # legacy instance rather than leaving it with zero instances (which
        # would look, in the API/dashboard, like it was never registered).
        # legacy_instance=1 marks it honestly as unable to resolve which
        # session/frame actually produced it — never inventing that provenance.
        existing_tools = conn.execute("SELECT * FROM webshield_tools").fetchall()
        for tool_row in existing_tools:
            legacy_instance_id = f"legacy-{tool_row['tenant_id'] or 'default'}-{tool_row['identity_key']}"
            conn.execute(
                """INSERT OR IGNORE INTO webshield_tool_instances
                   (tenant_id, instance_id, identity_key, owner_origin, tool_name, session_id, frame_id,
                    registration_source, exact_hash, canonical_hash, structural_hash, tool_json, status,
                    legacy_instance, first_seen_at, last_seen_at)
                   VALUES (?,?,?,?,?,NULL,NULL,NULL,?,?,?,?,?,1,?,?)""",
                (
                    tool_row["tenant_id"], legacy_instance_id, tool_row["identity_key"], tool_row["owner_origin"],
                    tool_row["tool_name"], tool_row["exact_hash"], tool_row["canonical_hash"], tool_row["structural_hash"],
                    tool_row["tool_json"], tool_row["status"], tool_row["first_seen_at"], tool_row["last_seen_at"],
                ),
            )
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (7)")

class _AutoCloseConnection(sqlite3.Connection):
    """sqlite3.Connection used as a context manager only commits/rolls back
    on ``__exit__`` — it does *not* close the underlying file descriptor.
    Every call site in this codebase uses ``with connect(path) as conn:``
    expecting the connection to be fully torn down afterwards, so without
    this override every such block leaks one open file descriptor. Under
    light load that leak is invisible; under the connection churn of, e.g.,
    Web Shield's alert-polling thread plus a burst of API calls (the attack
    lab), it exhausts the process's file descriptor limit within minutes
    (``OSError: [Errno 24] Too many open files``). This closes the
    connection after the normal commit/rollback so ``with connect(...) as
    conn:`` behaves the way every call site already assumes it does."""

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30.0, factory=_AutoCloseConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        _apply_migrations(conn)
        conn.commit()
    finally:
        conn.close()
