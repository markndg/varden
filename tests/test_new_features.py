from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from sentinel.app_factory import create_app
from sentinel.config import AppConfig
from sentinel.cli import main


def make_client(tmpdir: str):
    policy_path = Path(tmpdir) / 'policy.json'
    policy_path.write_text('''{
      "block": [{"type":"tool_call","tool":"delete_database"}],
      "warn": [{"classifier:internal": true}, {"classifier:secrets": true}],
      "monitor": [],
      "allow": []
    }''', encoding='utf-8')
    cfg = AppConfig(
        env='dev',
        db_path=str(Path(tmpdir) / 'sentinel.db'),
        auth_db_path=str(Path(tmpdir) / 'sentinel_auth.db'),
        policy_file=str(policy_path),
        signing_secret='dev-secret',
        rate_limit_per_minute=1000,
    )
    return TestClient(create_app(cfg))


def test_demo_endpoint_and_policy_simulation():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        headers = {'x-api-key': client.get('/health').json()['bootstrap_api_key']}
        seeded = client.post('/demo/run', headers=headers)
        assert seeded.status_code == 200
        payload = seeded.json()
        assert {item['status'] for item in payload['scenarios']} >= {'allowed', 'warned', 'blocked'}
        trace_id = payload['scenarios'][0]['trace_id']
        candidate = {"block": [], "warn": [{"field:risk_score": {"gte": 1}}], "monitor": [], "allow": []}
        simulated = client.post(f'/policy/simulate?trace_id={trace_id}', headers=headers, json=candidate)
        assert simulated.status_code == 200
        body = simulated.json()
        assert body['trace_id'] == trace_id
        assert body['results']


def test_cli_help_returns_zero():
    assert main([]) == 0
