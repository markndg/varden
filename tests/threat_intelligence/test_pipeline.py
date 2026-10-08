"""Threat intelligence tests. Fixtures are frozen. No live upstream calls."""

from __future__ import annotations

import gzip
import io
import json
import socket
import threading
import zipfile
from pathlib import Path

import pytest

from varden.models import Action, EventRecord
from varden.policy import PolicyEngine
from varden.stores import EventStore
from varden.threat_intelligence import lifecycle
from varden.threat_intelligence.applicability import (
    InstallationFacts,
    ObservabilityFact,
    SurfaceFact,
    assess_contract,
)
from varden.threat_intelligence.approval import ApprovalError
from varden.threat_intelligence.config import ThreatIntelConfig
from varden.threat_intelligence.contracts import build_contract
from varden.threat_intelligence.http_client import HttpResult, IntelHttpError, SafeHttpClient, _gunzip_limited, default_transport
from varden.threat_intelligence.service import ThreatIntelService
from varden.threat_intelligence.sources.atlas import AtlasSource
from varden.threat_intelligence.sources.cwe import CweSource, inspect_zip_limits, parse_cwe_xml
from varden.threat_intelligence.sources.nvd import WINDOW_RECORD_CAP, NvdSource
from varden.threat_intelligence.sources.owasp import OwaspSource

FIXTURES = Path(__file__).parent / "fixtures"
HOSTS = frozenset({"example.com", "github.com", "objects.githubusercontent.com"})


def _facts(rows, *, policy=None, provenance=True, authority=True, classification=True):
    facts = InstallationFacts(policy=policy or {"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []})
    for name, applicable, coverage in rows:
        facts.surfaces[name] = SurfaceFact(name=name, applicable=applicable, coverage=coverage)
    for name, available in {
        "provenance": provenance,
        "authority_flow": authority,
        "data_classification": classification,
        "tool_invocation": True,
        "destination": True,
    }.items():
        facts.observability[name] = ObservabilityFact(name=name, available=available)
    return facts


def _service(tmp_path, *, enabled=True, facts=None, events=None):
    policy_path = tmp_path / "policy.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_doc = {"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []}
    policy_path.write_text(json.dumps(policy_doc), encoding="utf-8")
    config = ThreatIntelConfig(
        enabled=enabled,
        db_path=str(tmp_path / "ti.db"),
        policy_file=str(policy_path),
        nvd_min_interval_seconds=0,
    )
    engine = PolicyEngine(config.db_path, json.loads(policy_path.read_text(encoding="utf-8")))
    event_store = EventStore(config.db_path)
    for event in events or []:
        event_store.log(event)
    service = ThreatIntelService(
        config,
        policy_engine=engine,
        event_store=event_store,
        http_client=_client(),
        facts_provider=(lambda: facts) if facts is not None else None,
    )
    return service, policy_path, engine


def _client(**kwargs):
    def transport(url, headers, timeout, max_bytes):
        raise IntelHttpError("transport", f"unexpected url {url}")

    return SafeHttpClient(transport=transport, sleeper=lambda _delay: None, max_attempts=1)


def _event(action):
    record = EventRecord.new(action=action, decision={"action": "allow", "reason": "fixture"}, status="allowed")
    return record.to_dict()


def _http(body, status=200, headers=None):
    hdrs = headers or {"content-type": "application/json"}

    def transport(url, headers_in, timeout, max_bytes):
        if len(body) > max_bytes:
            raise IntelHttpError("oversized", "too big")
        return HttpResult(status=status, headers=hdrs, body=body, url=url, unchanged=status == 304)

    return SafeHttpClient(transport=transport, sleeper=lambda _delay: None, max_attempts=1)


def test_disabled_check_does_not_fetch(tmp_path):
    calls = []

    def transport(url, headers, timeout, max_bytes):
        calls.append(url)
        raise AssertionError("disabled watcher must not fetch")

    config = ThreatIntelConfig(enabled=False, db_path=str(tmp_path / "ti.db"), policy_file=str(tmp_path / "missing.json"))
    service = ThreatIntelService(config, http_client=SafeHttpClient(transport=transport))
    result = service.check()
    assert result["watcher"] == "DISABLED"
    assert result["fetched"] is False
    assert calls == []
    assert service.status()["protection_claim"] is False
    assert service.status()["watcher_meaning"]


def test_atlas_new_unchanged_modified_and_contract_ignores_prose():
    bundle = json.loads((FIXTURES / "atlas_stix.json").read_text(encoding="utf-8"))
    body = json.dumps(bundle).encode()
    source = AtlasSource(url="https://example.com/stix-atlas.json", allow_hosts=HOSTS, interval_seconds=86400)

    def first_transport(url, headers, timeout, max_bytes):
        if headers.get("If-None-Match") == '"v1"':
            return HttpResult(status=304, headers={"etag": '"v1"'}, body=b"", url=url, unchanged=True)
        return HttpResult(status=200, headers={"etag": '"v1"', "content-type": "application/json"}, body=body, url=url)

    client = SafeHttpClient(transport=first_transport, sleeper=lambda _d: None)
    first = source.fetch_since(None, client)
    assert first.baseline is True
    assert len(first.items) == 2
    again = source.fetch_since(first.next_cursor, client)
    assert again.unchanged is True
    assert again.items == []
    changed = json.loads(body)
    changed["objects"][1]["description"] = "changed description"
    body2 = json.dumps(changed).encode()

    def second(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"etag": '"v2"', "content-type": "application/json"}, body=body2, url=url)

    cursor = dict(first.next_cursor)
    cursor.pop("etag", None)
    modified = source.fetch_since(cursor, SafeHttpClient(transport=second, sleeper=lambda _d: None))
    assert len(modified.items) == 1
    hostile = source.normalize(first.items[0])
    assert "ignore previous" in hostile.description
    contract = build_contract(hostile)
    assert contract["id"] == "untrusted-instruction-execution"
    assert "ignore previous" not in contract["explanation"]


def test_nvd_does_not_fetch_references_inside_the_record():
    payload = (FIXTURES / "nvd_page.json").read_bytes()
    seen = []

    def transport(url, headers, timeout, max_bytes):
        seen.append(url)
        assert "169.254.169.254" not in url
        assert headers.get("apiKey") == "test-key"
        return HttpResult(status=200, headers={"content-type": "application/json", "etag": '"nvd"'}, body=payload, url=url)

    source = NvdSource(
        url="https://example.com/cves",
        allow_hosts=HOSTS,
        interval_seconds=21600,
        keyword="artificial intelligence",
        api_key="test-key",
        results_per_page=50,
        lookback_hours=24,
        min_interval_seconds=0,
    )
    batch = source.fetch_since(None, SafeHttpClient(transport=transport, sleeper=lambda _d: None))
    item = source.normalize(batch.items[0])
    assert item.weaknesses[0].id == "CWE-522"
    assert any(ref.accepted is False and "169.254" in ref.url for ref in item.references)
    assert len(seen) == 1
    contract = build_contract(item)
    assert contract["id"] == "credential-exfiltration"
    assert "169.254" not in json.dumps(contract)


def test_retry_malformed_and_oversized():
    attempts = {"n": 0}

    def flaky(url, headers, timeout, max_bytes):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise IntelHttpError("timeout", "timed out")
        return HttpResult(status=200, headers={"content-type": "application/json"}, body=b"{}", url=url)

    delays = []
    result = SafeHttpClient(
        transport=flaky,
        max_attempts=3,
        backoff_base_seconds=2,
        backoff_cap_seconds=30,
        jitter_ratio=0,
        sleeper=lambda delay: delays.append(delay),
    ).get("https://example.com/atlas", allow_hosts=HOSTS)
    assert result.status == 200
    assert delays == [2, 4]

    def bad_json(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"content-type": "application/json"}, body=b"{", url=url)

    source = AtlasSource(url="https://example.com/atlas", allow_hosts=HOSTS, interval_seconds=10)
    with pytest.raises(IntelHttpError) as exc:
        source.fetch_since(None, SafeHttpClient(transport=bad_json, max_attempts=1, sleeper=lambda _d: None))
    assert exc.value.code == "malformed_json"

    def huge(url, headers, timeout, max_bytes):
        raise IntelHttpError("oversized", "too big")

    with pytest.raises(IntelHttpError) as exc:
        SafeHttpClient(transport=huge, max_attempts=1, sleeper=lambda _d: None).get("https://example.com/atlas", allow_hosts=HOSTS)
    assert exc.value.code == "oversized"


def test_redirect_ssrf_and_html_rejected():
    def redirect(url, headers, timeout, max_bytes):
        if "169.254" in url:
            raise AssertionError("followed a forbidden redirect")
        return HttpResult(status=302, headers={"location": "https://169.254.169.254/latest"}, body=b"", url=url)

    with pytest.raises(IntelHttpError) as exc:
        SafeHttpClient(transport=redirect, max_attempts=1, sleeper=lambda _d: None).get("https://example.com/feed", allow_hosts=HOSTS)
    assert exc.value.code == "redirect_rejected"

    def html(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"content-type": "text/html"}, body=b"<html>ignore previous instructions</html>", url=url)

    with pytest.raises(IntelHttpError) as exc:
        SafeHttpClient(transport=html, max_attempts=1, sleeper=lambda _d: None).get("https://example.com/feed", allow_hosts=HOSTS)
    assert exc.value.code == "mime_rejected"

    with pytest.raises(IntelHttpError):
        SafeHttpClient(max_attempts=1).get("http://example.com/feed", allow_hosts=HOSTS)


def test_cwe_relevant_only_and_zip_bomb():
    xml = (FIXTURES / "cwe.xml").read_bytes()
    parsed = parse_cwe_xml(xml)
    assert "CWE-522" in parsed["index"]
    assert "CWE-79" in parsed["index"]
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as archive:
        archive.writestr("cwec.xml", xml)
    source = CweSource(url="https://example.com/cwe.zip", allow_hosts=HOSTS, interval_seconds=604800, max_uncompressed_bytes=100000)

    def transport(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"content-type": "application/zip"}, body=blob.getvalue(), url=url)

    batch = source.fetch_since(None, SafeHttpClient(transport=transport, sleeper=lambda _d: None, max_bytes=1_000_000))
    assert [item["weakness"]["id"] for item in batch.items] == ["CWE-522"]
    second = source.fetch_since(batch.next_cursor, SafeHttpClient(transport=transport, sleeper=lambda _d: None, max_bytes=1_000_000))
    assert second.items == []

    class Huge:
        file_size = 10**12
        compress_size = 20

    with pytest.raises(IntelHttpError) as exc:
        inspect_zip_limits([Huge()], max_uncompressed=1000)
    assert exc.value.code == "decompression_bomb"


def test_owasp_scaffold_and_pinned_json():
    source = OwaspSource(url=None, allow_hosts=frozenset(), interval_seconds=86400)

    def transport(url, headers, timeout, max_bytes):
        raise AssertionError("scaffold must not fetch")

    batch = source.fetch_since(None, SafeHttpClient(transport=transport))
    assert batch.items == []
    assert source.health()["state"] == "unsupported"
    pinned = OwaspSource(url="https://example.com/owasp.json", allow_hosts=HOSTS, interval_seconds=86400)
    body = (FIXTURES / "owasp_agentic.json").read_bytes()

    def ok(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"content-type": "application/json"}, body=body, url=url)

    fetched = pinned.fetch_since(None, SafeHttpClient(transport=ok, sleeper=lambda _d: None))
    rogue = pinned.normalize(fetched.items[1])
    contract = build_contract(rogue)
    assert contract["review_only"] is True


def test_applicability_does_not_upgrade_partial_or_unrouted():
    item_contract = {
        "id": "credential-exfiltration",
        "version": "1",
        "sources": [{"type": "nvd", "id": "CVE-1"}],
        "invariant": "sensitive_information_must_not_cross_an_unauthorised_trust_boundary",
        "required_observability": ["provenance", "data_classification", "destination", "authority_flow"],
        "unacceptable_outcomes": ["sensitive_to_untrusted_destination"],
        "enforcement_surfaces": ["http", "mcp", "filesystem"],
        "required_surfaces": ["http", "mcp", "filesystem"],
        "proof": {"type": "http_request", "classifier:secrets": True},
        "explanation": "template",
        "mapping_ids": ["CWE-522"],
        "mapping_version": "1",
        "review_only": False,
        "review_reason": None,
    }
    proving = {"block": [], "require_approval": [{"id": "secrets", "classifier:secrets": True}], "warn": [], "monitor": [], "allow": []}
    rows_off = [("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")]
    assert assess_contract(item_contract, _facts([("http", True, "ENFORCED"), *rows_off], policy=proving))["result"] == "PROTECTED"
    assert assess_contract(item_contract, _facts([("http", True, "PARTIAL"), *rows_off], policy=proving))["result"] == "EXPOSED"
    unrouted = assess_contract(item_contract, _facts([("http", True, "ENFORCED"), ("mcp", True, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")], policy=proving))
    assert unrouted["result"] == "EXPOSED"
    assert any("not routed" in reason for reason in unrouted["reasons"])
    assert assess_contract(item_contract, _facts([("http", False, "UNCOVERED"), *rows_off], policy=proving))["result"] == "NOT_APPLICABLE"
    assert assess_contract(item_contract, _facts([("http", True, "ENFORCED"), *rows_off], policy=proving, provenance=None))["result"] == "REVIEW"
    assert assess_contract(item_contract, _facts([("http", True, "ENFORCED"), *rows_off]))["result"] == "EXPOSED"


def test_candidate_replay_and_explicit_approval(tmp_path):
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    events = [
        _event({"type": "http_request", "tool": "httpx", "classifiers": {"secrets": True}, "url": "https://example.com"}),
        _event({"type": "http_request", "tool": "httpx", "classifiers": {}, "url": "https://example.com/health"}),
    ]
    service, policy_path, engine = _service(tmp_path, facts=facts, events=events)
    before = policy_path.read_text(encoding="utf-8")
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))
    outcome = service.ingest_raw("nvd", [{"cve": raw["vulnerabilities"][0]["cve"]}])
    assert outcome["outcomes"][0]["lifecycle"] == lifecycle.AWAITING_APPROVAL
    assert before == policy_path.read_text(encoding="utf-8")
    shown = service.show("nvd:CVE-2024-99999")
    assert shown["rule_active"] is False
    assert "ignore previous" not in shown["candidate"]["rule"]["description"].lower()
    replay = shown["replay"]
    assert replay["status"] == "COMPLETE"
    assert replay["operations_analysed"] == 2
    assert replay["would_require_approval"] == 1
    assert replay["would_allow"] == 1
    approved = service.approve("nvd:CVE-2024-99999", actor="alice")
    assert approved["rule_active"] is True
    shown_after = service.show("nvd:CVE-2024-99999")
    assert shown_after["applicability"] == "PROTECTED"
    assert shown_after["assessment"]["policy_proves_invariant"] is True
    live = json.loads(policy_path.read_text(encoding="utf-8"))
    assert any(rule.get("id") == "ti-credential-exfiltration" for rule in live["require_approval"])
    decision = engine.evaluate(Action(type="http_request", tool="httpx", classifiers={"secrets": True}))
    assert decision.effective_action == "require_approval"
    second = service.approve("nvd:CVE-2024-99999", actor="alice")
    assert second["idempotent"] is True
    audit = service.store.list_audit("nvd:CVE-2024-99999")
    assert any(row["new_state"] == lifecycle.ENFORCED and row["actor"] == "alice" for row in audit)
    with pytest.raises(KeyError):
        service.approve("missing", actor="alice")


def test_protected_and_partial_do_not_invent_a_rule(tmp_path):
    proving = {"block": [], "require_approval": [{"id": "secrets", "classifier:secrets": True}], "warn": [], "monitor": [], "allow": []}
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service, policy_path, _engine = _service(
        tmp_path,
        facts=_facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")], policy=proving),
    )
    outcome = service.ingest_raw("nvd", [{"cve": raw}])
    assert outcome["outcomes"][0]["applicability"] == "PROTECTED"
    assert service.show("nvd:CVE-2024-99999")["candidate"]["possible"] is False
    assert "ti-credential-exfiltration" not in policy_path.read_text(encoding="utf-8")
    service2, _, _ = _service(
        tmp_path / "partial",
        facts=_facts([("http", True, "PARTIAL"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")], policy=proving),
    )
    outcome2 = service2.ingest_raw("nvd", [{"cve": raw}])
    doc = service2.show("nvd:CVE-2024-99999")
    assert doc["applicability"] == "EXPOSED"
    assert doc["candidate"]["reason_code"] == "GAP_IS_COVERAGE"
    assert outcome2["outcomes"][0]["lifecycle"] == lifecycle.REVIEW


def test_unknown_technique_stays_review(tmp_path):
    facts = _facts([("tools", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("subprocess", False, "UNCOVERED"), ("filesystem", False, "UNCOVERED")])
    service, policy_path, _engine = _service(tmp_path, facts=facts)
    bundle = json.loads((FIXTURES / "atlas_stix.json").read_text(encoding="utf-8"))
    unknown = next(obj for obj in bundle["objects"] if obj.get("type") == "attack-pattern" and "T9999" in json.dumps(obj))
    outcome = service.ingest_raw("atlas", [{"stix": unknown, "source_version": "2026.09", "upstream_url": "https://example.com/stix"}])
    assert outcome["outcomes"][0]["applicability"] == "REVIEW"
    shown = service.show(outcome["outcomes"][0]["id"])
    assert shown["rule_active"] is False
    assert "javascript" not in json.dumps(shown.get("contract"))


def test_conflicting_allow_is_reported(tmp_path):
    policy = {
        "block": [],
        "require_approval": [],
        "warn": [],
        "monitor": [],
        "allow": [{"id": "allow-secrets", "type": "http_request", "classifier:secrets": True}],
    }
    service, policy_path, _engine = _service(
        tmp_path,
        facts=_facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")], policy=policy),
    )
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    service.policy_engine.update_policy(policy)
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service.ingest_raw("nvd", [{"cve": raw}])
    shown = service.show("nvd:CVE-2024-99999")
    assert shown["candidate"]["conflicts"]
    assert shown["rule_active"] is False


def test_empty_and_bounded_replay(tmp_path):
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service, _, _ = _service(tmp_path, facts=facts, events=[])
    service.ingest_raw("nvd", [{"cve": raw}])
    assert service.show("nvd:CVE-2024-99999")["replay"]["status"] == "INSUFFICIENT_REPLAY_DATA"
    events = [_event({"type": "http_request", "tool": "httpx", "classifiers": {}}) for _ in range(5)]
    service2, _, _ = _service(tmp_path / "bounded", facts=facts, events=events)
    service2.config.replay_max_events = 2
    service2.ingest_raw("nvd", [{"cve": raw}])
    bounded = service2.show("nvd:CVE-2024-99999")
    assert bounded["replay"]["status"] == "BOUNDED"
    assert bounded["replay"]["operations_analysed"] == 2


def test_source_failure_leaves_policy_untouched(tmp_path):
    service, policy_path, _engine = _service(tmp_path, facts=_facts([]))
    before = policy_path.read_bytes()

    def boom(url, headers, timeout, max_bytes):
        raise IntelHttpError("timeout", "down")

    service.client = SafeHttpClient(transport=boom, max_attempts=1, sleeper=lambda _d: None)
    result = service.check("atlas")
    assert result["sources"][0]["health"] == "error"
    assert policy_path.read_bytes() == before


def test_firewall_modules_do_not_depend_on_threat_intelligence():
    root = Path(__file__).resolve().parents[2] / "varden"
    for relative in ("policy.py", "sdk.py", "runtime/boundary.py", "runtime/coverage.py"):
        text = (root / relative).read_text(encoding="utf-8")
        assert "threat_intelligence" not in text


def test_clock_anomaly_and_hash_change_without_new_timestamp():
    source = AtlasSource(url="https://example.com/stix", allow_hosts=HOSTS, interval_seconds=10)
    future = {
        "type": "attack-pattern",
        "name": "future",
        "description": "x",
        "created": "2999-01-01T00:00:00.000Z",
        "modified": "2999-01-01T00:00:00.000Z",
        "external_references": [{"external_id": "AML.T0051"}],
    }
    item = source.normalize({"stix": future, "source_version": "2026.09"})
    assert item.clock_anomaly == "published_in_future"
    first = source.normalize({"stix": {"type": "attack-pattern", "name": "a", "description": "one", "modified": "2024-01-01T00:00:00.000Z", "external_references": [{"external_id": "AML.T0051"}]}})
    second = source.normalize({"stix": {"type": "attack-pattern", "name": "a", "description": "two", "modified": "2024-01-01T00:00:00.000Z", "external_references": [{"external_id": "AML.T0051"}]}})
    assert first.raw_content_hash != second.raw_content_hash
    assert first.modified_at == second.modified_at


def test_invalid_utf8_rejected():
    def transport(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"content-type": "application/json"}, body=b"\xff\xfe", url=url)

    source = NvdSource(
        url="https://example.com/cves",
        allow_hosts=HOSTS,
        interval_seconds=10,
        keyword="",
        api_key=None,
        results_per_page=10,
        lookback_hours=1,
        min_interval_seconds=0,
    )
    with pytest.raises(IntelHttpError) as exc:
        source.fetch_since(None, SafeHttpClient(transport=transport, sleeper=lambda _d: None))
    assert exc.value.code == "invalid_utf8"


def test_dismiss_and_review_do_not_write_policy(tmp_path):
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    service, policy_path, _engine = _service(tmp_path, facts=facts)
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service.ingest_raw("nvd", [{"cve": raw}])
    before = policy_path.read_text(encoding="utf-8")
    reviewed = service.decide("nvd:CVE-2024-99999", "review", actor="bob")
    assert reviewed["lifecycle"] == lifecycle.REVIEW
    assert reviewed["rule_active"] is False
    assert policy_path.read_text(encoding="utf-8") == before
    with pytest.raises(ApprovalError):
        service.approve("nvd:CVE-2024-99999", actor="bob")


def test_approval_rejects_a_poisoned_candidate_rule(tmp_path):
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    service, policy_path, _engine = _service(tmp_path, facts=facts)
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service.ingest_raw("nvd", [{"cve": raw}])
    doc = service.store.get_item("nvd:CVE-2024-99999")
    doc["candidate"]["rule"]["url"] = "http://169.254.169.254/latest/meta-data"
    service.store.save_item(doc)
    before = policy_path.read_text(encoding="utf-8")
    with pytest.raises(ApprovalError):
        service.approve("nvd:CVE-2024-99999", actor="alice")
    assert policy_path.read_text(encoding="utf-8") == before
    assert "169.254.169.254" not in policy_path.read_text(encoding="utf-8")


def test_approval_rejects_a_stale_displayed_hash_and_changed_coverage(tmp_path):
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    service, policy_path, _engine = _service(tmp_path, facts=facts)
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service.ingest_raw("nvd", [{"cve": raw}])
    shown = service.show("nvd:CVE-2024-99999")
    with pytest.raises(ApprovalError):
        service.approve("nvd:CVE-2024-99999", actor="alice", expected_content_hash="not-the-hash")
    assert "ti-credential-exfiltration" not in policy_path.read_text(encoding="utf-8")
    service._facts_provider = lambda: _facts([("http", False, "UNCOVERED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    with pytest.raises(ApprovalError):
        service.approve("nvd:CVE-2024-99999", actor="alice", expected_content_hash=shown["raw_content_hash"])
    assert "ti-credential-exfiltration" not in policy_path.read_text(encoding="utf-8")


def test_stale_protected_claim_is_dropped_when_the_rule_disappears(tmp_path):
    proving = {"block": [], "require_approval": [{"id": "secrets", "type": "http_request", "classifier:secrets": True}], "warn": [], "monitor": [], "allow": []}
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")], policy=proving)
    service, policy_path, engine = _service(tmp_path, facts=facts)
    policy_path.write_text(json.dumps(proving), encoding="utf-8")
    engine.update_policy(proving)
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    outcome = service.ingest_raw("nvd", [{"cve": raw}])
    assert outcome["outcomes"][0]["applicability"] == "PROTECTED"
    empty = {"block": [], "require_approval": [], "warn": [], "monitor": [], "allow": []}
    policy_path.write_text(json.dumps(empty), encoding="utf-8")
    engine.update_policy(empty)
    service.status()
    assert service.show("nvd:CVE-2024-99999")["applicability"] == "EXPOSED"


def test_concurrent_approvals_keep_both_rules(tmp_path):
    facts = _facts(
        [
            ("http", True, "ENFORCED"),
            ("mcp", False, "NOT_ROUTED"),
            ("filesystem", False, "UNCOVERED"),
            ("tools", True, "ENFORCED"),
            ("subprocess", False, "UNCOVERED"),
        ]
    )
    service, policy_path, _engine = _service(tmp_path, facts=facts)
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service.ingest_raw("nvd", [{"cve": raw}])
    bundle = json.loads((FIXTURES / "atlas_stix.json").read_text(encoding="utf-8"))
    known = next(obj for obj in bundle["objects"] if obj.get("type") == "attack-pattern" and "T0051" in json.dumps(obj))
    service.ingest_raw("atlas", [{"stix": known, "source_version": "2026.09", "upstream_url": "https://example.com/stix"}])
    barrier = threading.Barrier(2)
    errors = []

    def run(item_id: str) -> None:
        barrier.wait()
        try:
            service.approve(item_id, actor="alice")
        except Exception as exc:  # pragma: no cover - assertion below
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=("nvd:CVE-2024-99999",)),
        threading.Thread(target=run, args=("atlas:AML.T0051",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    live = json.loads(policy_path.read_text(encoding="utf-8"))
    ids = {rule.get("id") for rule in live["require_approval"]}
    assert ids == {"ti-credential-exfiltration", "ti-untrusted-instruction-execution"}


def test_replay_matches_live_policy_engine(tmp_path):
    facts = _facts([("http", True, "ENFORCED"), ("mcp", False, "NOT_ROUTED"), ("filesystem", False, "UNCOVERED")])
    event = _event({"type": "http_request", "tool": "httpx", "classifiers": {"secrets": True}, "url": "https://example.com"})
    service, policy_path, engine = _service(tmp_path, facts=facts, events=[event])
    raw = json.loads((FIXTURES / "nvd_page.json").read_text(encoding="utf-8"))["vulnerabilities"][0]["cve"]
    service.ingest_raw("nvd", [{"cve": raw}])
    replay = service.replay("nvd:CVE-2024-99999")["replay"]
    service.approve("nvd:CVE-2024-99999", actor="alice")
    decision = engine.evaluate(Action(type="http_request", tool="httpx", classifiers={"secrets": True}, url="https://example.com"))
    assert replay["would_require_approval"] == 1
    assert decision.effective_action == "require_approval"
    assert policy_path.read_text(encoding="utf-8").count("ti-credential-exfiltration") == 1


def test_transport_pins_the_resolved_address(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    seen = {}

    def fake_create(addr, timeout=None):
        seen["addr"] = addr
        raise OSError("stopped after pin")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", fake_create)
    with pytest.raises(IntelHttpError) as exc:
        default_transport("https://example.com/feed", {}, 1.0, 100)
    assert exc.value.code == "transport"
    assert seen["addr"][0] == "8.8.8.8"


def test_transport_refuses_a_private_resolution(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]

    def fail_connect(addr, timeout=None):
        raise AssertionError("connected to a private address")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", fail_connect)
    with pytest.raises(IntelHttpError) as exc:
        default_transport("https://example.com/feed", {}, 1.0, 100)
    assert exc.value.code == "ssrf_rejected"


def test_gzip_bomb_is_rejected_at_the_cap():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as handle:
        handle.write(b"A" * 200_000)
    with pytest.raises(IntelHttpError) as exc:
        _gunzip_limited(buf.getvalue(), 1000)
    assert exc.value.code == "decompression_bomb"


def test_cwe_xml_with_entities_is_refused():
    raw = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Weakness_Catalog Version="1"><Weakness ID="522" Name="&xxe;"/></Weakness_Catalog>
"""
    with pytest.raises(IntelHttpError) as exc:
        parse_cwe_xml(raw)
    assert exc.value.code == "malformed_json"


def test_nvd_window_cap_closes_a_hostile_total(monkeypatch):
    source = NvdSource(
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        allow_hosts=frozenset({"services.nvd.nist.gov"}),
        interval_seconds=1,
        keyword="artificial intelligence",
        api_key=None,
        results_per_page=1,
        lookback_hours=1,
        min_interval_seconds=0,
    )
    body = json.dumps(
        {
            "totalResults": 10**9,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-1", "descriptions": [{"lang": "en", "value": "x"}], "weaknesses": [], "references": []}}
            ],
        }
    ).encode()

    def transport(url, headers, timeout, max_bytes):
        return HttpResult(status=200, headers={"content-type": "application/json"}, body=body, url=url)

    cursor = {"start_index": WINDOW_RECORD_CAP - 1, "window_end": "2026-01-01T00:00:00", "last_mod_start": "2026-01-01T00:00:00", "bootstrapped": True}
    batch = source.fetch_since(cursor, SafeHttpClient(transport=transport, sleeper=lambda _d: None))
    assert batch.next_cursor["start_index"] == 0
    assert batch.notes


def _technique(ext: str, name: str) -> dict:
    return {
        "stix": {
            "type": "attack-pattern",
            "name": name,
            "description": "fixture prose must not select a contract",
            "modified": "2024-01-01T00:00:00.000Z",
            "external_references": [{"source_name": "mitre-atlas", "external_id": ext}],
        },
        "source_version": "2026.09",
        "upstream_url": "https://example.com/stix",
    }


def test_list_exposes_mapped_contracts_and_pages_unmapped_records(tmp_path):
    service, _policy, _engine = _service(tmp_path, facts=InstallationFacts())
    raws = [
        _technique("AML.T0051", "LLM Prompt Injection"),
        _technique("AML.T0054", "LLM Jailbreak"),
        {"weakness": {"id": "CWE-269", "name": "Improper Privilege Management", "description": "bound weakness", "hash": "cwe-269"}},
        {"weakness": {"id": "CWE-918", "name": "SSRF", "description": "review only", "hash": "cwe-918"}},
    ]
    raws.extend(_technique(f"AML.T9{index:03d}", f"Unmapped {index}") for index in range(30))
    service.ingest_raw("atlas", [row for row in raws if "stix" in row])
    service.ingest_raw("cwe", [row for row in raws if "weakness" in row])

    status = service.status()
    assert status["counts"]["mapped"] == 3
    assert status["counts"]["unmapped"] == 31
    assert status["actionable_empty_reason"] == "NO_ATTESTED_CAPABILITY"
    assert "not attested the capabilities" in status["actionable_empty_message"]
    assert status["counts"]["actionable"] == 0

    mapped = service.list_items(mapping="mapped", sort="source_id", order="asc")
    assert mapped["total"] == 3
    by_id = {row["source_id"]: row for row in mapped["items"]}
    assert by_id["AML.T0051"]["contract_id"] == "untrusted-instruction-execution"
    assert by_id["AML.T0051"]["has_contract"] is True
    assert by_id["AML.T0051"]["contract_version"] == "1"
    assert by_id["AML.T0054"]["contract_id"] == "untrusted-instruction-execution"
    assert by_id["CWE-269"]["contract_id"] == "privilege-amplification"
    assert by_id["AML.T0051"]["review_only"] is False

    unmapped = service.list_items(mapping="unmapped", q="AML.T9000")
    assert unmapped["total"] == 1
    row = unmapped["items"][0]
    assert row["has_contract"] is False
    assert row["review_only"] is True
    assert "No deterministic Varden contract" in row["review_reason"]

    review_only = service.list_items(q="CWE-918")["items"][0]
    assert review_only["has_contract"] is False
    assert "Server-side request forgery" in review_only["review_reason"]

    page = service.list_items(limit=10, offset=10, sort="source_id", order="asc")
    assert page["total"] == 34
    assert page["limit"] == 10
    assert len(page["items"]) == 10
    assert service.list_items(view="actionable")["total"] == 0

    service.store.save_source(
        "atlas",
        {"source_id": "atlas", "health": "degraded", "last_success": 10, "next_due": 20, "cursor": {"technique_ids": ["AML.T0051", "AML.T0054"]}},
    )
    service.store.save_source("cwe", {"source_id": "cwe", "health": "healthy", "cursor": {"index": {"CWE-269": "a", "CWE-918": "b", "CWE-1": "c"}}})
    views = {row["source_id"]: row for row in service.source_views()}
    assert views["atlas"]["health"] == "degraded"
    assert views["atlas"]["records_indexed"] == 2
    assert views["atlas"]["records_indexed_scope"] == "techniques_in_upstream_document"
    assert views["cwe"]["records_indexed"] == 3
    assert views["cwe"]["records_mapped"] == 1
    assert views["owasp"]["unsupported"] is True
    assert views["owasp"]["records_indexed_scope"] == "unsupported"
