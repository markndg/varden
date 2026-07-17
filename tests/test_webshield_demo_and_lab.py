import json
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.config import AppConfig
from varden.webshield.demo import _bootstrap_webshield_policy
from varden.webshield.extension_build import build_extension, extension_path
from varden.webshield.trust_cli import trust_argv


def _cfg(tmpdir: str, policy_path: str | None = None) -> AppConfig:
    return AppConfig(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=policy_path or str(Path(tmpdir) / "policy.json"),
        signing_secret="dev-secret",
        rate_limit_per_minute=1000,
    )


def _client(tmpdir: str, policy_path: str | None = None) -> TestClient:
    return TestClient(create_app(_cfg(tmpdir, policy_path)))


def _bootstrap_headers(client: TestClient) -> dict:
    key = client.get("/health").json()["bootstrap_api_key"]
    return {"x-api-key": key}


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_bootstrap_webshield_policy_merges_default_pack_into_fresh_file():
    with TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "policy.json"
        note = _bootstrap_webshield_policy(policy_path)
        assert "merged" in note.lower() or "already present" in note.lower()
        doc = json.loads(policy_path.read_text(encoding="utf-8"))
        webmcp_rule_count = sum(
            1
            for bucket in ("block", "require_approval", "sanitise", "warn", "monitor")
            for rule in doc.get(bucket) or []
            if str(rule.get("type", "")).startswith("webmcp.")
        )
        assert webmcp_rule_count > 0


def test_bootstrap_webshield_policy_is_idempotent_and_additive():
    with TemporaryDirectory() as tmpdir:
        policy_path = Path(tmpdir) / "policy.json"
        _bootstrap_webshield_policy(policy_path)
        doc_before = json.loads(policy_path.read_text(encoding="utf-8"))
        baseline_rule_count = sum(len(doc_before.get(b) or []) for b in ("block", "warn", "monitor", "allow"))

        note = _bootstrap_webshield_policy(policy_path)
        assert "already present" in note.lower()
        doc_after = json.loads(policy_path.read_text(encoding="utf-8"))
        rule_count_after = sum(len(doc_after.get(b) or []) for b in ("block", "warn", "monitor", "allow"))
        assert rule_count_after == baseline_rule_count


def test_webshield_lab_page_is_served_and_self_contained():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            resp = client.get("/webshield/lab")
            assert resp.status_code == 200
            assert "Attack Lab" in resp.text
            assert "/static/webshield-lab/lab.js" in resp.text

            js = client.get("/static/webshield-lab/lab.js")
            assert js.status_code == 200
            assert "registerTool" in js.text

            css = client.get("/static/webshield-lab/lab.css")
            assert css.status_code == 200


def test_extension_path_points_at_a_real_manifest():
    path = Path(extension_path())
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 3
    assert (path / "src" / "page-world.js").exists()
    assert (path / "src" / "background.js").exists()


def test_build_extension_produces_reproducible_zip():
    with TemporaryDirectory() as tmpdir:
        out1 = Path(tmpdir) / "one.zip"
        out2 = Path(tmpdir) / "two.zip"
        assert build_extension(str(out1)) == 0
        assert build_extension(str(out2)) == 0
        assert out1.read_bytes() == out2.read_bytes()

        import zipfile
        with zipfile.ZipFile(out1) as zf:
            names = zf.namelist()
        assert "manifest.json" in names
        assert "src/background.js" in names


def test_trust_cli_round_trip():
    with TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "trust.db")
        assert trust_argv(Args(trust_command="list", db_path=db_path)) == 0
        assert trust_argv(Args(trust_command="add", origin="https://example.com", db_path=db_path)) == 0
        assert trust_argv(Args(trust_command="list", db_path=db_path)) == 0
        assert trust_argv(Args(trust_command="remove", origin="https://example.com", db_path=db_path)) == 0
        assert trust_argv(Args(trust_command="bogus")) == 2


def test_demo_seeded_registrations_are_visible_end_to_end():
    with TemporaryDirectory() as tmpdir:
        from varden.webshield.demo import _seed_dashboard

        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            api_key = headers["x-api-key"]

            import varden.webshield.demo as demo_mod

            original_post = demo_mod._post_json

            def routed_post(url, payload, key):
                path = url.split("http://placeholder", 1)[-1] if "http://placeholder" in url else url.split("/webshield", 1)
                # Route the seeding helper's HTTP call straight into the TestClient
                # instead of a real socket, so this test needs no live server.
                endpoint = "/webshield" + url.split("/webshield", 1)[1]
                resp = client.post(endpoint, json=payload, headers={"x-api-key": key})
                if resp.status_code >= 400 and resp.status_code != 403:
                    resp.raise_for_status()
                if resp.status_code == 403:
                    import urllib.error
                    raise urllib.error.HTTPError(url, 403, "blocked", None, None)
                return resp.json()

            demo_mod._post_json = routed_post
            try:
                seeded = demo_mod._seed_dashboard("http://placeholder", api_key)
            finally:
                demo_mod._post_json = original_post

            assert seeded == 4
            overview = client.get("/webshield/overview", headers=headers).json()
            assert overview["tools_registered"] >= 3
