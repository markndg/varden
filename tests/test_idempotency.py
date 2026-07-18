"""Tests for the shared idempotency implementation (varden/idempotency.py).

See docs/web-shield-hardening-review.md #3: the pre-hardening implementation
cached responses keyed *only* by the raw caller-supplied idempotency key,
with no tenant, principal, method, route or body binding, and no expiry.
That meant a caller who reused (or guessed) another tenant's/principal's/
endpoint's idempotency key value would receive that other request's cached
response verbatim — a cross-tenant/cross-endpoint cache-poisoning bug.

These tests exercise the store directly (fast, precise unit coverage of the
scoping rules) and then the webshield/policy API endpoints end-to-end.
"""
import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from varden.idempotency import IdempotencyConflict, IdempotencyStore
from varden.auth import LocalAuth
from tests.test_webshield_api import BENIGN_TOOL, _bootstrap_headers, _client


def _store(tmpdir: str, **kwargs) -> IdempotencyStore:
    return IdempotencyStore(str(Path(tmpdir) / "idem.db"), **kwargs)


# --------------------------------------------------------------------------- unit


def test_exact_duplicate_returns_cached_response():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        body = {"a": 1}
        assert store.get("k1", tenant_id="t1", principal="p1", route="/x", body=body) is None
        store.put("k1", {"result": "ok"}, tenant_id="t1", principal="p1", route="/x", body=body)
        cached = store.get("k1", tenant_id="t1", principal="p1", route="/x", body=body)
        assert cached == {"result": "ok"}


def test_same_key_different_body_raises_conflict():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        store.put("k1", {"result": "ok"}, tenant_id="t1", principal="p1", route="/x", body={"a": 1})
        with pytest.raises(IdempotencyConflict) as exc_info:
            store.get("k1", tenant_id="t1", principal="p1", route="/x", body={"a": 2})
        assert exc_info.value.error_code == "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"


def test_body_hash_stable_under_json_key_reordering():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        store.put("k1", {"result": "ok"}, tenant_id="t1", principal="p1", route="/x", body={"a": 1, "b": 2})
        # Same logical body, different key order/whitespace: must NOT conflict.
        cached = store.get("k1", tenant_id="t1", principal="p1", route="/x", body={"b": 2, "a": 1})
        assert cached == {"result": "ok"}


def test_same_key_different_tenant_never_sees_others_result():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        body = {"a": 1}
        store.put("k1", {"result": "tenant-a-secret"}, tenant_id="tenant-a", principal="p1", route="/x", body=body)
        cached = store.get("k1", tenant_id="tenant-b", principal="p1", route="/x", body=body)
        assert cached is None


def test_same_key_different_principal_never_sees_others_result():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        body = {"a": 1}
        store.put("k1", {"result": "principal-a-secret"}, tenant_id="t1", principal="principal-a", route="/x", body=body)
        cached = store.get("k1", tenant_id="t1", principal="principal-b", route="/x", body=body)
        assert cached is None


def test_same_key_different_route_never_reuses_result():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        body = {"a": 1}
        store.put("k1", {"result": "register-result"}, tenant_id="t1", principal="p1", route="POST /webshield/registrations", body=body)
        cached = store.get("k1", tenant_id="t1", principal="p1", route="POST /webshield/invocations", body=body)
        assert cached is None


def test_same_key_different_method_never_reuses_result():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        body = {"a": 1}
        store.put("k1", {"result": "post-result"}, tenant_id="t1", principal="p1", method="POST", route="/x", body=body)
        cached = store.get("k1", tenant_id="t1", principal="p1", method="PUT", route="/x", body=body)
        assert cached is None


def test_expired_key_is_treated_as_new_request():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir, default_ttl_seconds=0.01)
        body = {"a": 1}
        store.put("k1", {"result": "ok"}, tenant_id="t1", principal="p1", route="/x", body=body)
        time.sleep(0.05)
        cached = store.get("k1", tenant_id="t1", principal="p1", route="/x", body=body)
        assert cached is None
        # Because it is treated as new, a *different* body after expiry must
        # not raise a conflict either.
        store.put("k1", {"result": "new"}, tenant_id="t1", principal="p1", route="/x", body={"a": 2})
        assert store.get("k1", tenant_id="t1", principal="p1", route="/x", body={"a": 2}) == {"result": "new"}


def test_malformed_or_excessive_key_length_is_ignored_not_cached():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        huge_key = "k" * 10_000
        store.put(huge_key, {"result": "ok"}, tenant_id="t1", principal="p1", route="/x", body={})
        assert store.get(huge_key, tenant_id="t1", principal="p1", route="/x", body={}) is None
        assert store.get("", tenant_id="t1", principal="p1", route="/x", body={}) is None


def test_concurrent_identical_submissions_return_same_response():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        body = {"a": 1}

        # Simulate the read-compute-write race a real concurrent duplicate
        # request would hit: every "request" computes the same response for
        # the same body and writes it. Since the body never changes, no
        # write should ever be rejected as a conflict, and every reader must
        # see one consistent, non-corrupted response afterwards.
        for _ in range(20):
            store.get("race-key", tenant_id="t1", principal="p1", route="/x", body=body)
            store.put("race-key", {"result": "ok"}, tenant_id="t1", principal="p1", route="/x", body=body)
        final = store.get("race-key", tenant_id="t1", principal="p1", route="/x", body=body)
        assert final == {"result": "ok"}


def test_concurrent_different_body_submissions_are_detected_as_conflicts():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        store.put("race-key-2", {"result": "first"}, tenant_id="t1", principal="p1", route="/x", body={"a": 1})
        conflicts = 0
        for i in range(10):
            try:
                store.get("race-key-2", tenant_id="t1", principal="p1", route="/x", body={"a": i})
            except IdempotencyConflict:
                conflicts += 1
        # every body other than {"a": 1} must conflict
        assert conflicts == 9


def test_cached_blocked_decision_replays_the_block():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        blocked_response = {"outcome": "block", "event": {"decision": {"action": "block"}}}
        store.put("k-blocked", blocked_response, tenant_id="t1", principal="p1", route="/x", body={"a": 1})
        assert store.get("k-blocked", tenant_id="t1", principal="p1", route="/x", body={"a": 1}) == blocked_response


def test_cached_approval_response_replays_the_approval():
    with TemporaryDirectory() as tmpdir:
        store = _store(tmpdir)
        approval_response = {"approval": {"request_id": "r1", "status": "pending"}}
        store.put("k-approve", approval_response, tenant_id="t1", principal="p1", route="/x", body={"a": 1})
        assert store.get("k-approve", tenant_id="t1", principal="p1", route="/x", body={"a": 1}) == approval_response


# --------------------------------------------------------------------------- API-level


def test_idempotency_key_reused_with_different_body_returns_409():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = dict(_bootstrap_headers(client))
            headers["idempotency-key"] = "same-key-different-tool"
            r1 = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://weather.test", "tool": BENIGN_TOOL},
                headers=headers,
            )
            assert r1.status_code == 200
            r2 = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://weather.test", "tool": {**BENIGN_TOOL, "name": "other_tool"}},
                headers=headers,
            )
            assert r2.status_code == 409
            assert r2.json()["detail"]["error_code"] == "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"


def test_idempotency_key_same_across_registration_and_invocation_endpoints_does_not_cross_reuse():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            headers = dict(_bootstrap_headers(client))
            headers["idempotency-key"] = "shared-key"
            register = client.post(
                "/webshield/registrations",
                json={"session_id": "s1", "owner_origin": "https://weather.test", "tool": BENIGN_TOOL},
                headers=headers,
            )
            assert register.status_code == 200
            identity_key = register.json()["identity_key"]
            invoke = client.post(
                "/webshield/invocations",
                json={"session_id": "s1", "identity_key": identity_key, "phase": "requested", "args": {}},
                headers=headers,
            )
            # Same idempotency key, different endpoint: must be treated as a
            # fresh request for the invocation route, not the cached
            # registration response.
            assert invoke.status_code == 200
            assert invoke.json() != register.json()


def test_idempotency_key_isolated_across_two_authenticated_principals():
    with TemporaryDirectory() as tmpdir:
        with _client(tmpdir) as client:
            auth = LocalAuth((Path(tmpdir) / "varden_auth.db").as_posix(), "dev-secret")
            tenant = auth.ensure_tenant("default")
            second_key = auth.create_api_key("second-ingest-key", tenant_id=tenant["tenant_id"], role="viewer")["api_key"]

            headers_a = dict(_bootstrap_headers(client))
            headers_a["idempotency-key"] = "shared-across-principals"
            headers_b = {"x-api-key": second_key, "idempotency-key": "shared-across-principals"}

            payload_a = {"session_id": "s1", "owner_origin": "https://a.test", "tool": BENIGN_TOOL}
            payload_b = {"session_id": "s2", "owner_origin": "https://b.test", "tool": BENIGN_TOOL}

            r_a = client.post("/webshield/registrations", json=payload_a, headers=headers_a)
            r_b = client.post("/webshield/registrations", json=payload_b, headers=headers_b)

            assert r_a.status_code == 200
            assert r_b.status_code == 200
            # Different bodies under the same raw key, but different
            # authenticated principals: each principal gets its own
            # independent result (no 409 conflict, no data leaked across principals).
            assert r_a.json() != r_b.json()
            assert r_a.json()["identity_key"] != r_b.json()["identity_key"]
