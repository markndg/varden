"""Durable Predictive Authority continuity — tombstones, session markers, worker leases.

Process-local live ``AuthorityState`` cannot survive restart or span workers.
This store persists *continuity signals* (not full graphs) in the control-plane
SQLite database so enforce mode can fail-safe when:

- an authority session is reintroduced after eviction or process restart
- the bounded in-memory tombstone table forgets a key (durable flag)
- more than one worker lease is active against the same database

Full cross-process authority *replay* is out of scope; this store provides
honest fail-closed continuity, not shared live graphs.
"""

from __future__ import annotations

import os
import socket
import time
import uuid
from typing import Any

from ..db import connect, init_db

# Leases older than this are ignored for multi-worker detection.
DEFAULT_LEASE_TTL_SECONDS = 45.0


class ContinuityStore:
    """SQLite-backed continuity signals shared by workers on the same db_path."""

    def __init__(self, db_path: str, *, worker_id: str | None = None, lease_ttl: float = DEFAULT_LEASE_TTL_SECONDS):
        self.db_path = db_path
        init_db(db_path)
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"
        self.lease_ttl = float(lease_ttl)
        self.process_id = uuid.uuid4().hex

    # -- meta flags -----------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT value FROM pa_continuity_meta WHERE key = ?",
                (key,),
            ).fetchone()
        return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO pa_continuity_meta(key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, value, time.time()),
            )
            conn.commit()

    def continuity_degraded(self) -> bool:
        return self.get_meta("continuity_degraded") == "1"

    def set_continuity_degraded(self, reason: str) -> None:
        self.set_meta("continuity_degraded", "1")
        self.set_meta("continuity_degraded_reason", reason)

    def clear_continuity_degraded(self) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM pa_continuity_meta WHERE key IN (?, ?)", ("continuity_degraded", "continuity_degraded_reason"))
            conn.commit()

    # -- sessions / tombstones ------------------------------------------------

    def record_authority(self, session_key: str) -> None:
        """Mark that this session held accumulated authority in the current process."""
        now = time.time()
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO pa_continuity_sessions(
                  session_key, had_authority, tombstoned, tombstone_reason, process_id, updated_at
                ) VALUES (?, 1, 0, NULL, ?, ?)
                ON CONFLICT(session_key) DO UPDATE SET
                  had_authority=1,
                  process_id=excluded.process_id,
                  updated_at=excluded.updated_at
                """,
                (session_key, self.process_id, now),
            )
            conn.commit()

    def record_tombstone(self, session_key: str, reason: str) -> None:
        now = time.time()
        with connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO pa_continuity_sessions(
                  session_key, had_authority, tombstoned, tombstone_reason, process_id, updated_at
                ) VALUES (?, 1, 1, ?, ?, ?)
                ON CONFLICT(session_key) DO UPDATE SET
                  had_authority=1,
                  tombstoned=1,
                  tombstone_reason=excluded.tombstone_reason,
                  process_id=excluded.process_id,
                  updated_at=excluded.updated_at
                """,
                (session_key, reason, self.process_id, now),
            )
            conn.commit()

    def lookup(self, session_key: str) -> dict[str, Any] | None:
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM pa_continuity_sessions WHERE session_key = ?",
                (session_key,),
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def consume_recreate_signal(self, session_key: str) -> tuple[bool, str | None]:
        """Return (continuity_broken, reason) when recreating a missing live session.

        Signals:
        - durable tombstone for this key
        - prior had_authority recorded under a *different* process_id (restart /
          other worker loss of live state)
        """
        row = self.lookup(session_key)
        if row is None:
            return False, None
        if int(row.get("tombstoned") or 0):
            reason = str(row.get("tombstone_reason") or "evicted")
            # Clear tombstone bit but keep had_authority for audit; live state
            # will carry continuity_broken for this process lifetime.
            with connect(self.db_path) as conn:
                conn.execute(
                    """
                    UPDATE pa_continuity_sessions
                    SET tombstoned=0, process_id=?, updated_at=?
                    WHERE session_key=?
                    """,
                    (self.process_id, time.time(), session_key),
                )
                conn.commit()
            return True, reason
        prior_process = str(row.get("process_id") or "")
        if int(row.get("had_authority") or 0) and prior_process and prior_process != self.process_id:
            with connect(self.db_path) as conn:
                conn.execute(
                    """
                    UPDATE pa_continuity_sessions
                    SET process_id=?, updated_at=?
                    WHERE session_key=?
                    """,
                    (self.process_id, time.time(), session_key),
                )
                conn.commit()
            return True, "process_restart_or_worker_migration"
        return False, None

    def clear_session(self, session_key: str) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM pa_continuity_sessions WHERE session_key = ?", (session_key,))
            conn.commit()

    def clear_all_sessions(self) -> None:
        with connect(self.db_path) as conn:
            conn.execute("DELETE FROM pa_continuity_sessions")
            conn.commit()
        self.clear_continuity_degraded()

    # -- worker leases --------------------------------------------------------

    def touch_lease(self) -> None:
        """Refresh this worker's lease (non-atomic vs count; prefer touch_lease_and_count)."""
        self.touch_lease_and_count()

    def touch_lease_and_count(self) -> int:
        """Atomically renew this lease and return the active-worker count.

        Uses ``BEGIN IMMEDIATE`` so two workers starting together cannot both
        observe a count of 1 before either commit — the second waiter sees the
        first lease and reports >= 2.
        """
        now = time.time()
        cutoff = now - self.lease_ttl
        with connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO pa_worker_leases(worker_id, hostname, pid, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                  last_seen=excluded.last_seen,
                  hostname=excluded.hostname,
                  pid=excluded.pid
                """,
                (self.worker_id, socket.gethostname(), os.getpid(), now),
            )
            # Opportunistic GC of stale leases (outside the active TTL window).
            conn.execute(
                "DELETE FROM pa_worker_leases WHERE last_seen < ?",
                (now - self.lease_ttl * 4,),
            )
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM pa_worker_leases WHERE last_seen >= ?",
                (cutoff,),
            ).fetchone()
            conn.commit()
        return int(row["n"] if row else 0)

    def active_worker_count(self) -> int:
        """Return active lease count without renewing this worker's lease."""
        now = time.time()
        cutoff = now - self.lease_ttl
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM pa_worker_leases WHERE last_seen >= ?",
                (cutoff,),
            ).fetchone()
        return int(row["n"] if row else 0)

    def active_worker_ids(self) -> list[str]:
        now = time.time()
        cutoff = now - self.lease_ttl
        with connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT worker_id FROM pa_worker_leases WHERE last_seen >= ? ORDER BY worker_id",
                (cutoff,),
            ).fetchall()
        return [str(r["worker_id"]) for r in rows]

    def probe(self) -> None:
        """Read+write probe used at attach time; raises on unavailable stores."""
        # Read path
        _ = self.get_meta("continuity_degraded")
        # Write path (lease renew) — catches read-only / missing / locked DBs.
        self.touch_lease_and_count()
