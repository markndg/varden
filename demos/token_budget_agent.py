from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

BASE_URL = "http://127.0.0.1:8000"
API_KEY = "admin-demo-key"
TRACE_ID = "demo-token-budget-trace"
WORKFLOW_ID = "demo-token-budget-workflow"

DEMO_BUDGET_RULE = {
    "id": "demo-session-cap",
    "type": "token_budget",
    "title": "Demo session token budget",
    "enabled": True,
    "limit_usd": 0.0001,
    "window": "session",
    "hard_cap": True,
}


def _json_request(path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={"x-api-key": API_KEY, "content-type": "application/json"},
    )
    with urlopen(request, timeout=10.0) as response:
        return json.loads(response.read().decode("utf-8"))


def _ensure_demo_budget_policy() -> None:
    current = _json_request("/policy")
    rules = list(current.get("budget_rules") or [])
    if not any(str(rule.get("id")) == DEMO_BUDGET_RULE["id"] for rule in rules if isinstance(rule, dict)):
        current.setdefault("budget_rules", []).append(DEMO_BUDGET_RULE)
        _json_request("/policy", method="PUT", payload=current)


def run() -> int:
    _ensure_demo_budget_policy()
    print("Varden OSS demo: token budget enforcement on llm_call")
    body = {
        "action": {
            "type": "llm_call",
            "tool": "openai.chat.completions.create",
            "trace_id": TRACE_ID,
            "workflow_id": WORKFLOW_ID,
            "args": {"kwargs": {"model": "gpt-4o", "max_tokens": 64000}},
        },
        "payload": {"kwargs": {"model": "gpt-4o", "max_tokens": 64000}},
    }
    try:
        _json_request("/sdk/guard", method="POST", payload=body)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8")
        if exc.code == 403 and "budget" in detail.lower():
            print("✅ Varden blocked the projected LLM spend as expected")
            print("   response:", detail[:240])
            budgets = _json_request("/token-budgets")
            print("   configured rules:", budgets.get("summary", {}).get("rules_configured"))
            print("   Open the dashboard Overview → Token budgets or Rules → budget tab.")
            return 0
        print("❌ Unexpected guard response:", exc.code, detail)
        return 1
    print("❌ Expected llm_call to be blocked by token budget, but guard allowed it.")
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
