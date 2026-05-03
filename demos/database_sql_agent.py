from __future__ import annotations
import os
import requests

BASE_URL = os.getenv("VARDEN_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("VARDEN_API_KEY", "admin-demo-key")
AGENT_NAME = "sql-demo-agent"
SQL_TOOL = "sql.query"


def run(statement: str):
    payload = {
        "args": [statement],
        "kwargs": {"sql": statement, "database": "app"},
        "agent_name": AGENT_NAME,
        "trace_id": "demo-trace-sql",
    }
    return requests.post(f"{BASE_URL}/demo/tool?tool_name={SQL_TOOL}", headers={"x-api-key": API_KEY}, json=payload, timeout=5)
