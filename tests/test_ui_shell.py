from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

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


def test_ui_shell_serves_bundled_frontend():
    with TemporaryDirectory() as tmpdir:
        client = make_client(tmpdir)
        html = client.get('/ui').text
        assert '/static/app/assets/app.js' in html
        assert "window.__SENTINEL_PAGE__ = 'overview'" in html
        rules = client.get('/ui/rules').text
        assert '/static/app/assets/app.css' in rules
        assert "window.__SENTINEL_PAGE__ = 'rules'" in rules
