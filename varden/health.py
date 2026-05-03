from __future__ import annotations
import sqlite3
class HealthChecks:
    def __init__(self, db_path: str, auth_db_path: str):
        self.db_path=db_path; self.auth_db_path=auth_db_path
    def liveness(self): return {"status":"alive"}
    def readiness(self):
        checks={"db":self._check(self.db_path),"auth_db":self._check(self.auth_db_path)}
        return {"status":"ready" if all(v["ok"] for v in checks.values()) else "not_ready","checks":checks}
    def diagnostics(self): return {"db_path":self.db_path,"auth_db_path":self.auth_db_path,"readiness":self.readiness()}
    def _check(self, path):
        try:
            conn=sqlite3.connect(path); conn.execute("SELECT 1"); conn.close(); return {"ok":True}
        except Exception as exc:
            return {"ok":False,"error":str(exc)}
