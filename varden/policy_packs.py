from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Any

RULE_BUCKETS = ("block", "require_approval", "sanitise", "warn", "monitor", "allow")
_PACK_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _pack_dirs() -> list[Path]:
    dirs: list[Path] = []
    try:
        pkg = resources.files("varden").joinpath("policy-packs")
        if pkg.is_dir():
            dirs.append(Path(str(pkg)))
    except Exception:
        pass
    repo = Path(__file__).resolve().parent.parent / "policy-packs"
    if repo.is_dir():
        dirs.append(repo)
    return dirs


def _safe_pack_filename(pack_id: str) -> bool:
    return bool(pack_id) and bool(_PACK_ID_RE.fullmatch(pack_id))


def _rule_fingerprint(rule: dict[str, Any]) -> str:
    return json.dumps(rule, sort_keys=True, default=str)


def _read_pack_file(path: Path) -> dict[str, Any] | None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    return doc


def list_policy_packs() -> list[dict[str, Any]]:
    packs: dict[str, dict[str, Any]] = {}
    for directory in _pack_dirs():
        for path in sorted(directory.glob("*.json")):
            doc = _read_pack_file(path)
            if not doc:
                continue
            pack_id = str(doc.get("name") or path.stem)
            template = doc.get("template") if isinstance(doc.get("template"), dict) else doc
            counts = {bucket: len(template.get(bucket) or []) for bucket in RULE_BUCKETS}
            budget_count = len(template.get("budget_rules") or [])
            packs[pack_id] = {
                "id": pack_id,
                "name": doc.get("name") or path.stem,
                "description": doc.get("description") or "",
                "filename": path.name,
                "counts": counts,
                "budget_rules": budget_count,
                "total_rules": sum(counts.values()) + budget_count,
            }
    return sorted(packs.values(), key=lambda row: row["name"])


def _pack_path_in_directory(directory: Path, pack_id: str) -> Path | None:
    if not _safe_pack_filename(pack_id):
        return None
    root = directory.resolve()
    candidate = (directory / f"{pack_id}.json").resolve()
    if not str(candidate).startswith(str(root)):
        return None
    return candidate


def load_policy_pack(pack_id: str) -> dict[str, Any] | None:
    if not pack_id:
        return None
    for directory in _pack_dirs():
        candidate = _pack_path_in_directory(directory, pack_id)
        if candidate and candidate.exists():
            return _read_pack_file(candidate)
        for path in directory.glob("*.json"):
            doc = _read_pack_file(path)
            if doc and str(doc.get("name") or path.stem) == pack_id:
                return doc
    return None


def merge_policy_pack(current: dict[str, Any], pack_doc: dict[str, Any], *, mode: str = "merge") -> dict[str, Any]:
    template = pack_doc.get("template") if isinstance(pack_doc.get("template"), dict) else pack_doc
    if mode == "replace":
        base = {key: value for key, value in current.items() if key not in RULE_BUCKETS and key != "budget_rules"}
        for bucket in RULE_BUCKETS:
            base[bucket] = []
        base["budget_rules"] = []
    else:
        base = dict(current)
        for bucket in RULE_BUCKETS:
            base[bucket] = list(current.get(bucket) or [])
        base["budget_rules"] = list(current.get("budget_rules") or [])
    added = {bucket: 0 for bucket in RULE_BUCKETS}
    added["budget_rules"] = 0
    seen = {bucket: {_rule_fingerprint(r) for r in base.get(bucket) or []} for bucket in RULE_BUCKETS}
    seen_budget = {_rule_fingerprint(r) for r in base.get("budget_rules") or []}
    for bucket in RULE_BUCKETS:
        for rule in template.get(bucket) or []:
            if not isinstance(rule, dict):
                continue
            fingerprint = _rule_fingerprint(rule)
            if fingerprint in seen[bucket]:
                continue
            base.setdefault(bucket, []).append(rule)
            seen[bucket].add(fingerprint)
            added[bucket] += 1
    for rule in template.get("budget_rules") or []:
        if not isinstance(rule, dict):
            continue
        fingerprint = _rule_fingerprint(rule)
        if fingerprint in seen_budget:
            continue
        base.setdefault("budget_rules", []).append(rule)
        seen_budget.add(fingerprint)
        added["budget_rules"] += 1
    return {"policy": base, "added": added}
