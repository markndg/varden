from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import httpx
import arbiter

BASE_URL = 'http://127.0.0.1:8000'
API_KEY = 'admin-demo-key'
AGENT_NAME = 'allowed-demo-agent'

# This is the entire adoption story for developers.
# Start the Sentinel control plane locally, then just do:
#   import arbiter
#   arbiter.protect()
arbiter.protect()


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


def run() -> int:
    print('Arbiter OSS demo: allowed action with one-line protection')
    print('Only setup in this file: import arbiter + arbiter.protect()')
    safe_payload = {
        'title': 'public status heartbeat',
        'notes': 'availability green and latency normal',
        'target': 'public-health-endpoint',
    }

    with arbiter.trace_agent(AGENT_NAME, lineage={'source': 'public-status'}):
        print('1) Sending a benign report that policy should allow...')
        try:
            httpx.post('https://example.com/health', json=safe_payload, timeout=2.0)
        except Exception as exc:
            print('   network result:', exc.__class__.__name__)
            print('   Sentinel already recorded the allow decision before the outbound call completed.')

    detail = latest_event_detail()
    latest = detail.get('event') or {}
    print('   latest event status:', latest.get('status'))
    print('   latest classifiers:', ((latest.get('action') or {}).get('classifiers')))
    print('   Open the dashboard at / and refresh to see the allow event and trace flow.')
    return 0


if __name__ == '__main__':
    raise SystemExit(run())
