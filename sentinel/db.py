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

def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        _apply_migrations(conn)
        conn.commit()
    finally:
        conn.close()
