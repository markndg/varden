from __future__ import annotations
import hashlib, json, time
from .db import connect, init_db
class IdempotencyStore:
    def __init__(self, db_path: str): self.db_path=db_path; init_db(db_path)
    def _hash(self, key: str) -> str: return hashlib.sha256(key.encode("utf-8")).hexdigest()
    def get(self, key: str):
        with connect(self.db_path) as conn:
            row=conn.execute("SELECT response_json FROM idempotency_keys WHERE key_hash=?", (self._hash(key),)).fetchone()
            return json.loads(row["response_json"]) if row and row["response_json"] else None
    def put(self, key: str, response):
        with connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO idempotency_keys(key_hash,created_at,response_json) VALUES (?,?,?)", (self._hash(key), time.time(), json.dumps(response, ensure_ascii=False))); conn.commit()
