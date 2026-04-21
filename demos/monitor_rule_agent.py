from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import arbiter

BASE_URL = 'http://127.0.0.1:8000'
API_KEY = 'admin-demo-key'
AGENT_NAME = 'monitor-demo-agent'

# This is the entire adoption story for developers.
# Start the Sentinel control plane locally, then just do:
#   import arbiter
#   arbiter.protect()
arbiter.protect()


DEMO_MONITOR_POLICY = {
    'block': [],
    'warn': [],
    'monitor': [
        {
            'title': 'Monitor SQL query tool',
            'type': 'tool_call',
            'tool': 'sql.query',
        },
    ],
    'allow': [],
}


def _json_request(path: str, method: str = 'GET', payload: dict[str, Any] | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode('utf-8')
    request = Request(
        f'{BASE_URL}{path}',
        data=data,
        method=method,
        headers={
            'x-api-key': API_KEY,
            'content-type': 'application/json',
        },
    )
    with urlopen(request, timeout=10.0) as response:
        return json.loads(response.read().decode('utf-8'))


def latest_event_detail() -> dict[str, Any]:
    query = urlencode({'limit': 1, 'agent': AGENT_NAME})
    events = _json_request(f'/events?{query}')
    latest = (events.get('items') or [{}])[0]
    event_id = latest.get('id')
    return _json_request(f'/events/{event_id}') if event_id else {}


@arbiter.tool('sql.query')
def run_sql(statement: str) -> dict[str, Any]:
    return {
        'rows': [{'id': 42, 'email': 'ops@example.com'}],
        'statement': statement,
        'database': 'app',
    }


def run() -> int:
    previous_policy = _json_request('/policy')
    _json_request('/policy', method='PUT', payload=DEMO_MONITOR_POLICY)
    print('Arbiter OSS demo: monitor rule with one-line protection')
    print('Only setup in this file: import arbiter + arbiter.protect()')

    try:
        with arbiter.trace_agent(AGENT_NAME, lineage={'source': 'reporting-db'}):
            print('1) Running a normal SQL tool call that policy should monitor but still allow...')
            result = run_sql('select id, email from users limit 1')
            print('   query rows:', result['rows'])

        detail = latest_event_detail()
        latest = detail.get('event') or {}
        decision = latest.get('decision') or {}
        status = latest.get('status')
        decision_action = decision.get('action')
        print('   latest event status:', status)
        print('   latest decision action:', decision_action)
        print('   matched rule:', detail.get('rule_label') or (decision.get('matched_rule') or {}).get('title'))
        print('   Open the dashboard at / and refresh to see the monitored SQL event in the trace flow.')
        if status != 'allowed' or decision_action != 'monitor':
            print('   [FAIL] demo check failed: expected status=allowed and decision action=monitor')
            return 1
        return 0
    finally:
        _json_request('/policy', method='PUT', payload=previous_policy)


if __name__ == '__main__':
    raise SystemExit(run())
