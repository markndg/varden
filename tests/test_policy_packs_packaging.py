"""Ensure package-data policy packs stay synchronized with the repo catalogue."""

from __future__ import annotations

from pathlib import Path


def test_packaged_policy_packs_match_repo_catalogue():
    root = Path(__file__).resolve().parents[1]
    repo = {p.name for p in (root / "policy-packs").glob("*.json")}
    packaged = {p.name for p in (root / "varden" / "policy-packs").glob("*.json")}
    assert repo, "repo policy-packs/ must contain JSON packs"
    assert packaged == repo, (
        "varden/policy-packs must mirror policy-packs/ for wheel packaging; "
        f"missing={sorted(repo - packaged)} extra={sorted(packaged - repo)}"
    )
