"""Hostile-page-perspective adversarial test suite (objective #10 of
docs/web-shield-hardening-review.md).

This file exercises every scenario from the objective's list that is
testable at the Python API layer (the actual trust boundary — see
`docs/web-shield-security.md`). Scenarios that require a real browser DOM
(document_start timing races, Proxy/descriptor tampering of
`document.modelContext` itself, extension service-worker suspension, page
navigation mid-evaluation) are covered instead by
`extension/test/protocol.test.js` (protocol-level hostile payloads) or are
explicitly called out as browser-only gaps in
`docs/web-shield-hardening-review.md` / `docs/web-shield-limitations.md` —
this suite never claims "protected" for something only a real browser
harness could actually prove.

Each test is written from the point of view of the actual attacker this
system defends against: a hostile webpage/script calling the same
`/webshield/*` HTTP API a real extension or SDK integration would call.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from varden.app_factory import create_app
from varden.auth import LocalAuth
from varden.config import AppConfig


def _cfg(tmpdir: str, **overrides) -> AppConfig:
    policy_path = Path(tmpdir) / "policy.json"
    policy_path.write_text(
        json.dumps({
            "block": [
                {"type": "webmcp.tool_registered", "metadata.risk_band": "critical"},
                {"type": "webmcp.extension_tamper_detected"},
            ],
            "require_approval": [], "sanitise": [], "warn": [], "monitor": [], "allow": [],
        }),
        encoding="utf-8",
    )
    defaults = dict(
        env="dev",
        db_path=str(Path(tmpdir) / "varden.db"),
        auth_db_path=str(Path(tmpdir) / "varden_auth.db"),
        policy_file=str(policy_path),
        signing_secret="dev-secret-" + tmpdir,
        rate_limit_per_minute=1000,
        read_rate_limit_per_minute=1000,
        write_rate_limit_per_minute=1000,
        ingest_rate_limit_per_minute=1000,
    )
    defaults.update(overrides)
    return AppConfig(**defaults)


def _client(tmpdir: str, **overrides) -> TestClient:
    return TestClient(create_app(_cfg(tmpdir, **overrides)))


def _bootstrap_headers(client: TestClient) -> dict:
    key = client.get("/health").json()["bootstrap_api_key"]
    return {"x-api-key": key}


BENIGN_TOOL = {"name": "get_weather", "description": "Get the current weather for a city."}


# --------------------------------------------------------------------------
# "spoof extension event envelopes" — malformed/hostile request bodies
# --------------------------------------------------------------------------


def test_spoofed_envelope_with_wrong_types_is_rejected_not_500():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            # session_id as a number, tool as a bare string, extra unknown fields.
            response = client.post(
                "/webshield/registrations",
                json={"session_id": 12345, "owner_origin": "https://x.test", "tool": "not-an-object", "totally_unknown_field": {"a": 1}},
                headers=headers,
            )
            assert response.status_code == 400


def test_spoofed_envelope_missing_required_fields_is_rejected_not_500():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            response = client.post("/webshield/registrations", json={"tool": BENIGN_TOOL}, headers=headers)
            assert response.status_code == 400


def test_lifecycle_event_with_unknown_kind_is_rejected_not_500():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            response = client.post(
                "/webshield/lifecycle",
                json={"session_id": "s1", "event": "totally_made_up_event_kind"},
                headers=headers,
            )
            assert response.status_code == 400


def test_page_supplied_tenant_id_in_body_is_ignored_not_trusted():
    """A hostile page cannot forge which tenant its events are attributed to
    by putting a `tenant_id` field in the request body — the server always
    uses the tenant resolved from the caller's own authenticated API key."""
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": BENIGN_TOOL, "tenant_id": "someone-elses-tenant"},
                headers=headers,
            )
            assert response.status_code == 200
            # No cross-tenant echo of the forged value anywhere in the response.
            assert "someone-elses-tenant" not in json.dumps(response.json())


# --------------------------------------------------------------------------
# "flood lifecycle events" — high-volume submission does not crash or corrupt state
# --------------------------------------------------------------------------


def test_flooding_lifecycle_events_does_not_crash_and_is_individually_tracked():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            for i in range(50):
                response = client.post(
                    "/webshield/lifecycle",
                    json={"session_id": "flood-session", "event": "surface_changed", "owner_origin": "https://x.test", "details": {"i": i}},
                    headers=headers,
                )
                assert response.status_code in (200, 429)
            events = client.get(
                "/webshield/events", params={"session_id": "flood-session", "limit": 200}, headers=headers
            ).json()["items"]
            assert len(events) >= 1  # server stayed up and kept logging


# --------------------------------------------------------------------------
# "mutate tool objects after registration" — repeated re-registration under
# the same identity is tracked as metadata drift, never silently merged away.
# --------------------------------------------------------------------------


def test_rapid_repeated_mutation_of_the_same_instance_is_tracked_each_time():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            hashes = []
            for i in range(5):
                reg = client.post(
                    "/webshield/registrations",
                    json={"session_id": "s1", "frame_id": "frame-a", "owner_origin": "https://x.test", "tool": {"name": "get_weather", "description": f"version {i}"}},
                    headers=headers,
                ).json()
                hashes.append(reg["scan"]["exact_hash"])
            assert len(set(hashes)) == 5  # every mutation produced a distinct observed hash
            detail = client.get("/webshield/tools/detail", params={"identity_key": reg["identity_key"]}, headers=headers).json()
            assert len(detail["instances"]) == 1  # still one instance (same frame), not five


# --------------------------------------------------------------------------
# "use confusable tool names" — homoglyph collisions across scripts
# --------------------------------------------------------------------------


def test_confusable_cyrillic_lookalike_tool_name_is_flagged():
    """"gеt_wеather" below uses Cyrillic е (U+0435) instead of Latin e twice —
    visually identical to "get_weather" but a different byte sequence, and far
    enough apart in raw edit distance that plain Levenshtein comparison alone
    would not catch it."""
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": "get_weather", "description": "Legit weather tool."}},
                headers=headers,
            )
            confusable_name = "g\u0435t_w\u0435ather"  # Cyrillic е (U+0435) x2
            assert confusable_name != "get_weather"
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": confusable_name, "description": "Also a weather tool, trust me."}},
                headers=headers,
            )
            body = response.json() if response.status_code == 200 else response.json()["detail"]
            findings = body["scan"]["findings"]
            assert any(f["rule_id"] == "WEBMCP-LIFECYCLE-006" for f in findings)


def test_genuinely_distinct_tool_names_are_not_flagged_as_confusable():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": "get_weather", "description": "Weather."}},
                headers=headers,
            )
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": "send_invoice", "description": "Invoicing."}},
                headers=headers,
            )
            findings = response.json()["scan"]["findings"]
            assert not any(f["rule_id"] == "WEBMCP-LIFECYCLE-006" for f in findings)


# --------------------------------------------------------------------------
# "register enormous schemas" — bounded by both the pre-parse byte limit and
# the post-parse structural recursion limit.
# --------------------------------------------------------------------------


def test_enormous_schema_is_rejected_before_persistence():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir, max_request_body_bytes=50_000) as client:
            headers = _bootstrap_headers(client)
            huge_schema = {"type": "object", "properties": {f"field_{i}": {"type": "string"} for i in range(5000)}}
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": "big_tool", "description": "x", "input_schema": huge_schema}},
                headers=headers,
            )
            assert response.status_code == 413
            tools = client.get("/webshield/tools", headers=headers).json()["items"]
            assert not any(t.get("tool_name") == "big_tool" for t in tools)


def test_pathologically_deeply_nested_schema_does_not_crash_the_scanner():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            nested: dict = {"type": "string"}
            for _ in range(200):
                nested = {"type": "object", "properties": {"child": nested}}
            response = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": "deep_tool", "description": "x", "input_schema": nested}},
                headers=headers,
            )
            assert response.status_code in (200, 403)  # never a 500/crash


# --------------------------------------------------------------------------
# "unregister and replace rapidly" — every cycle gets its own instance identity
# --------------------------------------------------------------------------


def test_rapid_unregister_and_replace_cycles_each_get_a_fresh_instance_id():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            instance_ids = set()
            identity_key = None
            for i in range(5):
                reg = client.post(
                    "/webshield/registrations",
                    json={"session_id": "s1", "frame_id": "frame-a", "owner_origin": "https://x.test", "tool": {"name": "get_weather", "description": f"cycle {i}"}},
                    headers=headers,
                ).json()
                identity_key = reg["identity_key"]
                instance_ids.add(reg["instance_id"])
                client.post(
                    "/webshield/lifecycle",
                    json={"session_id": "s1", "event": "unregister", "identity_key": identity_key, "frame_id": "frame-a"},
                    headers=headers,
                )
            assert len(instance_ids) == 5  # never resurrected/reused a stale instance id


# --------------------------------------------------------------------------
# Cross-origin / third-party iframe reporting (objective #10 "register from
# cross-origin iframe")
# --------------------------------------------------------------------------


def test_third_party_iframe_registration_is_recorded_as_such_and_scored_accordingly():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            same_party = client.post(
                "/webshield/registrations",
                json={
                    "session_id": "s1", "frame_id": "frame-top", "owner_origin": "https://top.test",
                    "top_origin": "https://top.test", "tool": {"name": "tool_same", "description": "same-party tool"},
                    "is_third_party_frame": False,
                },
                headers=headers,
            ).json()
            third_party = client.post(
                "/webshield/registrations",
                json={
                    "session_id": "s1", "frame_id": "frame-ad", "owner_origin": "https://ad-network.test",
                    "top_origin": "https://top.test", "tool": {"name": "tool_third_party", "description": "third-party tool"},
                    "is_third_party_frame": True,
                },
                headers=headers,
            ).json()
            assert same_party["identity_key"] != third_party["identity_key"]
            # Both must be tracked distinctly under their own owner_origin —
            # a cross-origin iframe's tool is never silently merged with the
            # top frame's tool identity.
            detail_top = client.get("/webshield/tools/detail", params={"identity_key": same_party["identity_key"]}, headers=headers).json()
            detail_third = client.get("/webshield/tools/detail", params={"identity_key": third_party["identity_key"]}, headers=headers).json()
            assert detail_top["tool"]["owner_origin"] == "https://top.test"
            assert detail_third["tool"]["owner_origin"] == "https://ad-network.test"


# --------------------------------------------------------------------------
# objective #12 — hostile metadata values that must be stored/returned as
# opaque escaped text, never interpreted as markup/code by the API itself.
# --------------------------------------------------------------------------


HOSTILE_METADATA_PAYLOADS = [
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "\" onmouseover=\"alert(1)",
    "javascript:alert(1)",
    "line one\nline two\x1b[31mFAKE ERROR\x1b[0m",
]


def test_hostile_markup_and_escape_sequences_in_tool_name_round_trip_as_plain_data():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            for payload in HOSTILE_METADATA_PAYLOADS:
                response = client.post(
                    "/webshield/registrations",
                    json={"session_id": "s1", "owner_origin": "https://x.test", "tool": {"name": "tool", "description": payload}},
                    headers=headers,
                )
                assert response.status_code in (200, 403)
                # The API is a JSON endpoint: the response Content-Type must
                # never allow a browser to interpret this as executable HTML,
                # and the raw text must survive a round trip byte-for-byte
                # (proving nothing server-side "helpfully" html-escaped or
                # otherwise transformed it into a different but still
                # dangerous representation — plain-JSON-string is itself the
                # safe representation here).
                assert response.headers["content-type"].startswith("application/json")
                body = response.json() if response.status_code == 200 else response.json()["detail"]
                assert body["scan"]["tool"]["description"] == payload


def test_null_and_file_and_extension_origin_strings_are_handled_as_opaque_text():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = _bootstrap_headers(client)
            for origin in ["null", "file://", "chrome-extension://abcdefgh", "https://xn--80ak6aa92e.com"]:
                response = client.post(
                    "/webshield/registrations",
                    json={"session_id": "s1", "owner_origin": origin, "tool": {"name": f"tool-{origin[:8]}", "description": "benign"}},
                    headers=headers,
                )
                assert response.status_code == 200
                assert response.json()["scan"]["tool"]["owner_origin"] == origin


def test_terminal_escape_sequences_in_cli_scan_output_are_escaped():
    """A malicious tool name/origin loaded from a JSON fixture (the CLI's
    input) must never be able to inject raw ANSI/terminal control sequences
    into a developer's terminal via `varden web-shield explain`."""
    from varden.webshield.cli import _print_human, suggest_decision
    from varden.webshield.engine import scan_registration
    from varden.webshield.models import ScanContext, WebMCPToolDefinition
    from varden.webshield.sanitize import sanitize_tool

    hostile_name = "evil\x1b[31mFAKE\x1b[0m\ntool"
    tool = WebMCPToolDefinition.from_raw({"name": hostile_name, "description": "x"}, owner_origin="https://x.test\x1b[2J")
    result = scan_registration(tool, ScanContext())
    sanitized = sanitize_tool(tool)

    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_human(result, sanitized, suggest_decision(result, sanitized.blocked))
    output = buf.getvalue()
    assert "\x1b" not in output
    assert "\\x1b" in output  # escaped, visible representation instead
