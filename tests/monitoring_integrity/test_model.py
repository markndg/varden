"""Asset identity, invariant catalogue, and approval scope."""

from __future__ import annotations

import json

import pytest

from varden.monitoring_integrity.approvals import ApprovalStore
from varden.monitoring_integrity.assets import AssetRegistry, VerificationState
from varden.monitoring_integrity.evidence import EvidenceLog
from varden.monitoring_integrity.invariants import INVARIANTS
from varden.monitoring_integrity.service import enable_monitoring_integrity, validate_section


def _section(path):
    return {
        "enabled": True,
        "mode": "guarded",
        "protected_agents": ["agent"],
        "assets": [
            {
                "id": "monitor.config",
                "type": "enforcement_config",
                "owner": "operator",
                "protected": True,
                "path": str(path),
                "permitted_operations": ["read"],
            },
            {
                "id": "notes",
                "type": "application",
                "owner": "app",
                "protected": False,
                "path": str(path) + ".notes",
            },
        ],
    }


def test_catalogue_covers_eight_invariants():
    assert set(INVARIANTS) == {f"INV-00{i}" for i in range(1, 9)}
    for spec in INVARIANTS.values():
        assert spec.definition
        assert spec.surfaces
        assert spec.limitations


def test_unprotected_asset_is_not_implicitly_protected(tmp_path):
    target = tmp_path / "monitoring.json"
    target.write_text("{}", encoding="utf-8")
    registry = AssetRegistry()
    registry.load_section(_section(target))
    protected = {asset.id: asset.protected for asset in registry.assets()}
    assert protected["monitor.config"] is True
    assert protected["notes"] is False
    assert registry.get("notes").verification == VerificationState.UNPROTECTED


def test_symlink_and_traversal_resolve_to_the_same_asset(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text(json.dumps({"audit": {"enabled": True}}), encoding="utf-8")
    link = tmp_path / "alias.json"
    link.symlink_to(live)
    nested = tmp_path / "sub"
    nested.mkdir()
    registry = AssetRegistry()
    registry.load_section(_section(live))
    via_link = registry.match_path(str(link))
    via_dotdot = registry.match_path(str(nested / ".." / "monitoring.json"))
    assert via_link and via_link[0].asset.id == "monitor.config"
    assert via_link[0].via in {"inode", "inode_via_other_path", "effective", "symlink_or_traversal"}
    assert via_dotdot and via_dotdot[0].asset.id == "monitor.config"


def test_temp_file_in_the_same_directory_is_not_the_asset(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    other = tmp_path / "monitoring.json.tmp"
    other.write_text("{}", encoding="utf-8")
    registry = AssetRegistry()
    registry.load_section(_section(live))
    assert registry.match_path(str(other)) == []


def test_digest_mismatch_is_not_verified(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text('{"audit": {"enabled": true}}', encoding="utf-8")
    registry = AssetRegistry()
    registry.load_section(_section(live))
    assert registry.refresh_verification("monitor.config") == VerificationState.VERIFIED
    live.write_text('{"audit": {"enabled": false}}', encoding="utf-8")
    assert registry.refresh_verification("monitor.config") == VerificationState.MISMATCHED


def test_approval_is_single_use_and_not_self_issued():
    store = ApprovalStore()
    with pytest.raises(ValueError):
        store.issue(asset_id="monitor.config", invariant_id="INV-001", operation="write", subject_agent="agent", issuer="agent")
    record = store.issue(
        asset_id="monitor.config",
        invariant_id="INV-001",
        operation="write",
        subject_agent="agent",
        issuer="operator",
    )
    presented = record.to_dict() | {"digest": record.digest}
    ok, why = store.consume(presented, asset_id="monitor.config", invariant_id="INV-001", operation="write", subject_agent="agent")
    assert ok and why == "approval_consumed"
    again, reason = store.consume(presented, asset_id="monitor.config", invariant_id="INV-001", operation="write", subject_agent="agent")
    assert not again and reason == "approval_replay"
    other = store.issue(
        asset_id="monitor.config",
        invariant_id="INV-001",
        operation="write",
        subject_agent="agent",
        issuer="operator",
    )
    scoped = other.to_dict() | {"digest": other.digest}
    ok, why = store.consume(scoped, asset_id="other", invariant_id="INV-001", operation="write", subject_agent="agent")
    assert not ok and why == "approval_scope_mismatch"


def test_evidence_chain_detects_a_tampered_record(tmp_path):
    path = tmp_path / "evidence.jsonl"
    log = EvidenceLog(str(path))
    log.append({"outcome": "DENY"})
    log.append({"outcome": "ALLOW"})
    assert log.verify_chain()["ok"] is True
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["event"]["outcome"] = "ALLOW"
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    reloaded = EvidenceLog(str(path))
    assert reloaded.verify_chain()["ok"] is False


def test_sealed_registry_rejects_a_second_enable_without_the_token(tmp_path):
    live = tmp_path / "monitoring.json"
    live.write_text("{}", encoding="utf-8")
    token = enable_monitoring_integrity(_section(live))
    with pytest.raises(RuntimeError):
        enable_monitoring_integrity({"enabled": False, "mode": "observe", "assets": []})
    assert token


def test_policy_section_validation_rejects_a_protected_asset_without_identity():
    errors = validate_section({"enabled": True, "assets": [{"id": "x", "type": "policy", "protected": True}]})
    assert errors
