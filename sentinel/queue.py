from __future__ import annotations
import hashlib, json, time
from .db import connect, init_db

class SQLiteQueue:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def enqueue(self, job_type: str, payload: dict, tenant_id: str | None = None, max_attempts: int = 3):
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO jobs(created_at,tenant_id,job_type,payload_json,status,attempts,max_attempts,leased_until,last_error,dead_lettered,worker_id) VALUES (?,?,?,?, 'queued',0,?,NULL,NULL,0,NULL)",
                (time.time(), tenant_id, job_type, json.dumps(payload, ensure_ascii=False), max_attempts),
            )
            conn.commit()
            return int(cur.lastrowid)

    def reserve(self, lease_seconds: int = 30, worker_id: str | None = None):
        now = time.time()
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE status='queued' AND (leased_until IS NULL OR leased_until < ?) AND dead_lettered=0 ORDER BY id ASC LIMIT 1",
                (now,),
            ).fetchone()
            if not row:
                return None
            conn.execute("UPDATE jobs SET status='leased', leased_until=?, attempts=attempts+1, worker_id=? WHERE id=?",
                         (now + lease_seconds, worker_id, row["id"]))
            conn.commit()
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
            return dict(row)

    def complete(self, job_id: int):
        with connect(self.db_path) as conn:
            conn.execute("UPDATE jobs SET status='done', leased_until=NULL WHERE id=?", (job_id,))
            conn.commit()

    def fail(self, job_id: int, error: str):
        with connect(self.db_path) as conn:
            row = conn.execute("SELECT attempts,max_attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                return
            if row["attempts"] >= row["max_attempts"]:
                conn.execute("UPDATE jobs SET status='dead_letter', dead_lettered=1, last_error=?, leased_until=NULL WHERE id=?",
                             (error, job_id))
            else:
                conn.execute("UPDATE jobs SET status='queued', last_error=?, leased_until=NULL WHERE id=?",
                             (error, job_id))
            conn.commit()

    def list_jobs(self, limit: int = 100):
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
