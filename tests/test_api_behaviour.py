from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import contextmanager

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig


@contextmanager
def make_client(tmpdir: str):
    policy_path = Path(tmpdir) / 'policy.json'
    policy_path.write_text('{"block":[{"type":"tool_call","tool":"delete_database"}],"warn":[{"classifier:internal":true}],"monitor":[],"allow":[]}', encoding='utf-8')
    cfg = AppConfig(
        env='dev',
        db_path=str(Path(tmpdir) / 'varden.db'),
        auth_db_path=str(Path(tmpdir) / 'varden_auth.db'),
        policy_file=str(policy_path),
        signing_secret='dev-secret',
        rate_limit_per_minute=1000,
    )
    app = create_app(cfg)
    with TestClient(app) as client:
        yield client


def test_root_redirects_to_ui():
    with TemporaryDirectory() as tmpdir:
        with make_client(tmpdir) as client:
            r = client.get('/', follow_redirects=False)
            assert r.status_code in {302, 307}
            assert r.headers['location'] == '/ui'


def test_blocked_demo_returns_403():
    with TemporaryDirectory() as tmpdir:
        with make_client(tmpdir) as client:
            key = client.get('/health').json()['bootstrap_api_key']
            r = client.post('/demo/tool?tool_name=delete_database', headers={'x-api-key': key}, json={'args': [], 'kwargs': {'target': 'prod'}})
            assert r.status_code == 403
            assert 'BLOCKED' in r.text


def test_dashboard_overview_returns_metrics():
    with TemporaryDirectory() as tmpdir:
        with make_client(tmpdir) as client:
            key = client.get('/health').json()['bootstrap_api_key']
            client.post('/demo/tool?tool_name=list_files', headers={'x-api-key': key}, json={'args': [], 'kwargs': {'path': '/tmp'}})
            r = client.get('/dashboard/overview', headers={'x-api-key': key})
            assert r.status_code == 200
            body = r.json()
            assert 'metrics' in body
            assert body['metrics']['total_events'] >= 1

def test_event_detail_endpoint_returns_explainability():
    with TemporaryDirectory() as tmpdir:
        with make_client(tmpdir) as client:
            key = client.get('/health').json()['bootstrap_api_key']
            client.post('/demo/tool?tool_name=list_files', headers={'x-api-key': key}, json={'args': [], 'kwargs': {'path': '/tmp'}})
            events = client.get('/events', headers={'x-api-key': key}).json()['items']
            event_id = events[0]['id']
            r = client.get(f'/events/{event_id}', headers={'x-api-key': key})
            assert r.status_code == 200
            body = r.json()
            assert body['event']['id'] == event_id
            assert 'explainability' in body
            assert 'decision_latency_ms' in body['explainability']


def test_trace_endpoint_returns_graph():
    with TemporaryDirectory() as tmpdir:
        with make_client(tmpdir) as client:
            key = client.get('/health').json()['bootstrap_api_key']
            trace_id = 'trace-demo-1'
            body1 = {'action': {'type': 'tool_call', 'tool': 'list_files', 'args': {'path': '/tmp'}, 'agent_name': 'sdk-test', 'trace_id': trace_id}, 'payload': {'path': '/tmp'}}
            r1 = client.post('/sdk/guard', headers={'x-api-key': key}, json=body1)
            assert r1.status_code == 200
            first_event_id = r1.json()['event_id']
            body2 = {'action': {'type': 'http_request', 'tool': 'httpx', 'url': 'https://example.com', 'method': 'POST', 'args': {'body': 'internal customer data'}, 'agent_name': 'sdk-test', 'trace_id': trace_id, 'parent_event_id': first_event_id}, 'payload': {'body': 'internal customer data'}}
            client.post('/sdk/guard', headers={'x-api-key': key}, json=body2)
            trace = client.get(f'/traces/{trace_id}', headers={'x-api-key': key})
            assert trace.status_code == 200
            payload = trace.json()
            assert payload['trace_id'] == trace_id
            assert len(payload['events']) >= 2
            assert payload['graph']['edges']


def test_dashboard_overview_includes_rule_labels_for_non_allow_decisions():
    with TemporaryDirectory() as tmpdir:
        with make_client(tmpdir) as client:
            key = client.get('/health').json()['bootstrap_api_key']
            seeded = client.post('/demo/run', headers={'x-api-key': key})
            assert seeded.status_code == 200
            overview = client.get('/dashboard/overview', headers={'x-api-key': key})
            assert overview.status_code == 200
            recent = overview.json()['recent_events']
            blocked_or_warned = [row for row in recent if row['status'] in {'blocked', 'warned'}]
            assert blocked_or_warned
            assert all(row.get('matched_rule_label') for row in blocked_or_warned)
