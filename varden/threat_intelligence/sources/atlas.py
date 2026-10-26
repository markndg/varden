"""MITRE ATLAS via a pinned STIX 2.1 JSON release.

The knowledge base YAML is not scraped. Incremental behaviour is conditional
HTTP plus a local hash diff: the upstream document is a versioned bundle, not
a delta feed. First fetch is a baseline.
"""

from __future__ import annotations

import json
from typing import Any

from ..http_client import IntelHttpError, SafeHttpClient
from ..models import (
    ExternalId,
    ThreatIntelligenceItem,
    bound_text,
    classify_reference,
    content_hash,
    make_item_id,
)
from .base import FetchBatch, SourceMetadata

PARSER_VERSION = "1"
_JSON_TYPES = frozenset({"application/json", "application/octet-stream", "text/plain"})


class AtlasSource:
    def __init__(self, *, url: str, allow_hosts: frozenset[str], interval_seconds: float, max_field_chars: int = 4000) -> None:
        self._url = url
        self._hosts = allow_hosts
        self._interval = interval_seconds
        self._limit = max_field_chars
        self._health: dict[str, Any] = {"state": "unknown", "detail": "not checked"}

    def source_id(self) -> str:
        return "atlas"

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            source_id="atlas",
            title="MITRE ATLAS",
            homepage="https://atlas.mitre.org/",
            fetch_url=self._url,
            machine_readable=True,
            implementation="implemented",
            parser_version=PARSER_VERSION,
            default_interval_seconds=self._interval,
            allow_hosts=self._hosts,
        )

    def health(self) -> dict[str, Any]:
        return dict(self._health)

    def fetch_since(self, cursor: dict[str, Any] | None, client: SafeHttpClient) -> FetchBatch:
        previous = cursor or {}
        try:
            result = client.get(
                self._url,
                allow_hosts=self._hosts,
                etag=previous.get("etag"),
                last_modified=previous.get("last_modified"),
                accept="application/json",
            )
        except IntelHttpError as exc:
            self._health = {"state": "error", "detail": f"{exc.code}: {exc}"}
            raise
        etag = result.headers.get("etag")
        last_modified = result.headers.get("last-modified")
        if result.unchanged:
            self._health = {"state": "healthy", "detail": "not modified"}
            return FetchBatch(
                items=[],
                next_cursor={**previous, "etag": etag or previous.get("etag"), "last_modified": last_modified or previous.get("last_modified")},
                unchanged=True,
                baseline=False,
                source_version=str(previous.get("source_version") or ""),
                etag=etag or previous.get("etag"),
                last_modified=last_modified or previous.get("last_modified"),
                content_hash=str(previous.get("content_hash") or ""),
            )
        mime = (result.headers.get("content-type") or "application/json").split(";", 1)[0].strip().lower()
        if mime and mime not in _JSON_TYPES:
            self._health = {"state": "error", "detail": f"unexpected mime {mime}"}
            raise IntelHttpError("mime_rejected", f"ATLAS response content-type {mime}")
        try:
            text = result.body.decode("utf-8")
            bundle = json.loads(text)
        except UnicodeDecodeError as exc:
            self._health = {"state": "error", "detail": "invalid utf-8"}
            raise IntelHttpError("invalid_utf8", "ATLAS body is not utf-8") from exc
        except json.JSONDecodeError as exc:
            self._health = {"state": "error", "detail": "malformed json"}
            raise IntelHttpError("malformed_json", "ATLAS body is not JSON") from exc
        if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
            self._health = {"state": "error", "detail": "not a STIX bundle"}
            raise IntelHttpError("malformed_json", "ATLAS JSON is not a STIX bundle")
        version = _bundle_version(bundle)
        digest = content_hash({"version": version, "bytes": len(result.body)})
        objects = [obj for obj in bundle["objects"] if isinstance(obj, dict)]
        if len(objects) > 50000:
            raise IntelHttpError("oversized", "ATLAS bundle has too many objects")
        raw_items = []
        seen: set[str] = set()
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            technique_id = _technique_id(obj)
            if not technique_id or technique_id in seen:
                continue
            seen.add(technique_id)
            raw_items.append({"stix": obj, "source_version": version, "upstream_url": self._url})
        known = set(previous.get("technique_ids") or [])
        known_hashes = previous.get("technique_hashes") or {}
        baseline = not previous.get("bootstrapped")
        rollback = False
        notes: list[str] = []
        if previous.get("source_version") and version and _version_tuple(version) < _version_tuple(str(previous.get("source_version"))):
            rollback = True
            notes.append("upstream version moved backwards; stored items were kept")
        emitted = []
        hashes: dict[str, str] = {}
        for raw in raw_items:
            technique_id = _technique_id(raw["stix"])
            item_hash = content_hash(_hash_material(raw["stix"]))
            hashes[technique_id] = item_hash
            if baseline:
                continue
            if technique_id not in known or known_hashes.get(technique_id) != item_hash:
                emitted.append(raw)
        self._health = {"state": "degraded" if rollback else "healthy", "detail": "rollback" if rollback else "ok"}
        return FetchBatch(
            items=emitted if not baseline else raw_items,
            next_cursor={
                "etag": etag,
                "last_modified": last_modified,
                "source_version": version,
                "content_hash": digest,
                "technique_ids": sorted(seen),
                "technique_hashes": hashes,
                "bootstrapped": True,
            },
            unchanged=False,
            baseline=baseline,
            source_version=version,
            etag=etag,
            last_modified=last_modified,
            content_hash=digest,
            notes=notes,
            rollback=rollback,
        )

    def normalize(self, raw: dict[str, Any]) -> ThreatIntelligenceItem | None:
        stix = raw.get("stix") if isinstance(raw.get("stix"), dict) else raw
        if not isinstance(stix, dict):
            return None
        technique_id = _technique_id(stix)
        if not technique_id:
            return None
        title, title_cut = bound_text(stix.get("name") or technique_id, self._limit)
        description, desc_cut = bound_text(stix.get("description") or "", self._limit)
        refs = []
        for ref in stix.get("external_references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(classify_reference(str(ref.get("url"))))
        phases = []
        for phase in stix.get("kill_chain_phases") or []:
            if isinstance(phase, dict) and phase.get("phase_name"):
                phases.append(str(phase.get("phase_name"))[:80])
        published = _epoch(stix.get("created"))
        modified = _epoch(stix.get("modified"))
        anomaly = _clock_anomaly(published, modified)
        withdrawn = bool(stix.get("revoked") or stix.get("x_mitre_deprecated"))
        item_hash = content_hash(_hash_material(stix))
        return ThreatIntelligenceItem(
            id=make_item_id("atlas", technique_id),
            source="atlas",
            source_id=technique_id,
            title=title,
            description=description,
            published_at=published,
            modified_at=modified,
            severity="unknown",
            references=refs,
            techniques=[ExternalId("mitre-atlas", technique_id)],
            weaknesses=[],
            attack_pattern=",".join(phases),
            security_properties=phases,
            raw_content_hash=item_hash,
            upstream_url=str(raw.get("upstream_url") or self._url),
            source_version=str(raw.get("source_version") or ""),
            parser_version=PARSER_VERSION,
            title_truncated=title_cut,
            description_truncated=desc_cut,
            clock_anomaly=anomaly,
            withdrawn=withdrawn,
            provenance={"stix_id": str(stix.get("id") or ""), "parser": "atlas-stix-v1"},
        )


def _technique_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        external = str(ref.get("external_id") or "")
        if external.startswith("AML.T"):
            return external.split()[0][:64]
    return ""


def _hash_material(obj: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _technique_id(obj),
        "name": obj.get("name"),
        "description": obj.get("description"),
        "modified": obj.get("modified"),
        "revoked": obj.get("revoked"),
        "deprecated": obj.get("x_mitre_deprecated"),
    }


def _bundle_version(bundle: dict[str, Any]) -> str:
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") in {"x-mitre-collection", "x-mitre-matrix"} and obj.get("x_mitre_version"):
            return str(obj.get("x_mitre_version"))[:64]
    return str(bundle.get("id") or "")[:64]


def _version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in value.replace("v", "").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            return (0,)
        parts.append(int(digits))
    return tuple(parts) or (0,)


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    from datetime import datetime

    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _clock_anomaly(published: float | None, modified: float | None) -> str | None:
    import time

    now = time.time()
    if published and published > now + 48 * 3600:
        return "published_in_future"
    if modified and modified > now + 48 * 3600:
        return "modified_in_future"
    if published and modified and modified + 3600 < published:
        return "modified_before_published"
    return None
