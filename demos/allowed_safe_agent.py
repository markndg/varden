from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import varden

BASE_URL = 'http://127.0.0.1:8000'
API_KEY = 'admin-demo-key'
AGENT_NAME = 'allowed-demo-agent'

# This is the entire adoption story for developers.
# Start the Varden control plane locally, then just do:
#   import varden
#   varden.protect()
varden.protect()

DEMO_ALLOWED_POLICY = {
    'block': [],
    'warn': [],
    'monitor': [],
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


def run() -> int:
    previous_policy = _json_request('/policy')
    _json_request('/policy', method='PUT', payload=DEMO_ALLOWED_POLICY)
    print('Varden OSS demo: allowed action with one-line protection')
    print('Only setup in this file: import varden + varden.protect()')
    safe_payload = {
        'title': 'public status heartbeat',
        'notes': 'availability green and latency normal',
        'target': 'public-health-endpoint',
    }

    try:
        with varden.trace_agent(AGENT_NAME, lineage={'source': 'public-status'}):
            print('1) Sending a benign report that policy should allow...')
            try:
                httpx.post('https://example.com/health', json=safe_payload, timeout=2.0)
            except Exception as exc:
                print('   network result:', exc.__class__.__name__)
                print('   Varden already recorded the allow decision before the outbound call completed.')

        detail = latest_event_detail()
        latest = detail.get('event') or {}
        decision = latest.get('decision') or {}
        status = latest.get('status')
        decision_action = decision.get('action')
        print('   latest event status:', status)
        print('   latest decision action:', decision_action)
        print('   latest classifiers:', ((latest.get('action') or {}).get('classifiers')))
        print('   Open the dashboard at / and refresh to see the allow event and trace flow.')
        if status != 'allowed' or decision_action not in (None, 'allow'):
            print('   [FAIL] demo check failed: expected status=allowed and decision action=allow')
            return 1
        return 0
    finally:
        _json_request('/policy', method='PUT', payload=previous_policy)


if __name__ == '__main__':
    raise SystemExit(run())
