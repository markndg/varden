from __future__ import annotations

import json
import subprocess
import sys
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import arbiter

BASE_URL = 'http://127.0.0.1:8000'
API_KEY = 'admin-demo-key'
AGENT_NAME = 'blocked-demo-agent'

# This is the entire adoption story for developers.
# Start the Sentinel control plane locally, then just do:
#   import arbiter
#   arbiter.protect()
arbiter.protect()


DEMO_BLOCK_RULES = [
    {'type': 'tool_call', 'tool': 'delete_database'},
    {'type': 'tool_call', 'tool': 'subprocess.run', 'field:args.args': {'contains': 'delete_database'}},
    {'type': 'tool_call', 'tool': 'subprocess.Popen', 'field:args.args': {'contains': 'delete_database'}},
]


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


def _ensure_demo_policy() -> None:
    current = _json_request('/policy')
    changed = False
    for rule in DEMO_BLOCK_RULES:
        if rule not in current.get('block', []):
            current.setdefault('block', []).insert(0, rule)
            changed = True
    if changed:
        _json_request('/policy', method='PUT', payload=current)


def event_detail(event_id: int) -> dict[str, Any]:
    return _json_request(f'/events/{event_id}')


def list_backups(path: str) -> list[str]:
    return [f'{path}/backup-2026-04-06.sql.gz']


def run() -> int:
    _ensure_demo_policy()
    print('Arbiter OSS demo: blocked action with one-line protection')
    print('Only setup in this file: import arbiter + arbiter.protect()')
    print('1) Running normal application code...')
    with arbiter.trace_agent(AGENT_NAME, lineage={'source': 'demo-script'}):
        print('   safe result:', list_backups('/var/lib/postgres'))
        print('2) Attempting a dangerous subprocess that policy should block before it executes...')
        try:
            subprocess.run(
                [sys.executable, '-c', "print('sentinel blocked demo')", 'delete_database', 'prod-customer-db'],
                check=False,
            )
        except arbiter.SentinelBlockedError as exc:
            print('   ✅ Sentinel blocked the subprocess as expected')
            print('   decision:', exc.decision)
            event_id = exc.decision.get('event_id')
            latest = {}
            if event_id:
                try:
                    detail = event_detail(event_id)
                    latest = detail.get('event') or {}
                except Exception as fetch_error:
                    print(f'   note: event detail lookup skipped ({fetch_error})')
            print('   latest event status:', latest.get('status') if latest else 'blocked')
            print('   latest tool:', ((latest.get('action') or {}).get('tool')) if latest else 'subprocess.run')
            print('   Open the dashboard at / to see the event flow update automatically.')
            return 0
    print('   ❌ Expected the action to be blocked, but it ran.')
    return 1


if __name__ == '__main__':
    raise SystemExit(run())
