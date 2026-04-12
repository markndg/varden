from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

import arbiter
from sentinel.app_factory import create_app
from sentinel.config import AppConfig


def make_client(tmpdir: str):
    policy_path = Path(tmpdir) / 'policy.json'
    policy_path.write_text('{"block":[{"type":"tool_call","tool":"delete_database"}],"warn":[{"classifier:internal":true}],"monitor":[],"allow":[]}', encoding='utf-8')
    cfg = AppConfig(
        env='dev',
        db_path=str(Path(tmpdir) / 'sentinel.db'),
        auth_db_path=str(Path(tmpdir) / 'sentinel_auth.db'),
        policy_file=str(policy_path),
        signing_secret='dev-secret',
        rate_limit_per_minute=1000,
    )
    app = create_app(cfg)
    return TestClient(app)


def test_sdk_guard_endpoint_allows_and_logs():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get('/health').json()['bootstrap_api_key']
        body = {
            'action': {'type': 'tool_call', 'tool': 'list_files', 'args': {'path': '/tmp'}, 'agent_name': 'sdk-test'},
            'payload': {'path': '/tmp'},
        }
        r = client.post('/sdk/guard', headers={'x-api-key': key}, json=body)
        assert r.status_code == 200
        decision = r.json()['decision']
        assert decision['action'] in {'allow', 'warn'}
        events = client.get('/events', headers={'x-api-key': key}).json()
        assert events['total'] >= 1


def test_python_sdk_exports_protect():
    assert hasattr(arbiter, 'protect')
    assert hasattr(arbiter, 'tool')
    assert hasattr(arbiter, 'trace_agent')


def test_sdk_bootstrap_credentials_can_be_auto_loaded(monkeypatch):
    from arbiter.sdk import SentinelClient
    calls = {"bootstrap": 0}

    def fake_bootstrap(self):
        calls["bootstrap"] += 1
        return {"bootstrap_api_key": "auto-key", "base_url": "http://bootstrap"}

    monkeypatch.setattr(SentinelClient, "bootstrap", fake_bootstrap)
    guard = arbiter.protect(base_url="http://placeholder", auto_instrument=False)
    assert guard.client.api_key == "auto-key"
    assert guard.client.base_url == "http://bootstrap"
    arbiter.unpatch_runtime()


def test_rules_page_exists():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        r = client.get('/ui/rules')
        assert r.status_code == 200
        assert 'Rule Builder' in r.text
