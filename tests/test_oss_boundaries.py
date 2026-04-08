from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from sentinel.app_factory import create_app
from sentinel.config import AppConfig


def make_client(tmpdir: str, *, scan_mode: str = 'fast'):
    policy_path = Path(tmpdir) / 'policy.json'
    policy_path.write_text('{"block":[{"type":"tool_call","tool":"delete_database"}],"warn":[{"classifier:internal":true}],"monitor":[],"allow":[]}', encoding='utf-8')
    cfg = AppConfig(
        env='dev',
        db_path=str(Path(tmpdir) / 'sentinel.db'),
        auth_db_path=str(Path(tmpdir) / 'sentinel_auth.db'),
        policy_file=str(policy_path),
        signing_secret='dev-secret',
        rate_limit_per_minute=1000,
        scan_mode=scan_mode,
    )
    app = create_app(cfg)
    return TestClient(app)


def test_admin_endpoints_are_not_exposed_in_oss():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        key = client.get('/health').json()['bootstrap_api_key']
        for path in ['/admin/config', '/admin/users', '/admin/tenants', '/admin/service-accounts', '/admin/backup/export']:
            r = client.get(path, headers={'x-api-key': key})
            assert r.status_code == 404


def test_health_reports_scan_mode_and_overview_latency():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir, scan_mode='fast')
        key = client.get('/health').json()['bootstrap_api_key']
        health = client.get('/health').json()
        assert health['scan_mode'] == 'fast'
        client.post('/demo/tool?tool_name=list_files', headers={'x-api-key': key}, json={'args': [], 'kwargs': {'path': '/tmp'}})
        overview = client.get('/dashboard/overview', headers={'x-api-key': key}).json()
        assert overview['config']['scan_mode'] == 'fast'
        assert 'avg_decision_latency_ms' in overview['metrics']



def test_oss_uses_default_tenant_everywhere():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        health = client.get("/health").json()
        assert health["tenant_id"] == "default"
        key = health["bootstrap_api_key"]
        headers = {"x-api-key": key}
        block = client.post("/demo/tool?tool_name=delete_database", headers=headers, json={"args": [], "kwargs": {}})
        assert block.status_code == 403
        events = client.get("/events", headers=headers).json()
        assert events["items"]
        assert all(item.get("tenant_id") == "default" for item in events["items"])
