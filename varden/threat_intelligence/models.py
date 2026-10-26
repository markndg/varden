"""Canonical threat-intelligence records.

External prose is stored as data. It is never a rule, a prompt, or a URL to fetch.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

NORMALIZATION_VERSION = "1"
GENERATION_VERSION = "1"

SEVERITIES = frozenset({"unknown", "none", "low", "medium", "high", "critical"})
APPLICABILITY = frozenset({"PROTECTED", "EXPOSED", "NOT_APPLICABLE", "REVIEW"})

_ID_SAFE = re.compile(r"[^A-Za-z0-9._:-]+")


def bound_text(value: Any, limit: int) -> tuple[str, bool]:
    """Return untrusted text as a bounded plain string. Never interpret it."""
    if value is None:
        return "", False
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    text = text.replace("\x00", "")
    if len(text) > limit:
        return text[:limit], True
    return text, False


def content_hash(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def make_item_id(source: str, source_id: str) -> str:
    safe = _ID_SAFE.sub("_", str(source_id))[:160]
    return f"{source}:{safe}"


@dataclass
class Reference:
    url: str
    source: str = ""
    accepted: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "source": self.source, "accepted": self.accepted, "reason": self.reason}


@dataclass
class ExternalId:
    system: str
    id: str

    def to_dict(self) -> dict[str, str]:
        return {"system": self.system, "id": self.id}


@dataclass
class ThreatIntelligenceItem:
    """Normalized external record. Not a Varden rule."""

    id: str
    source: str
    source_id: str
    title: str
    description: str
    published_at: float | None
    modified_at: float | None
    severity: str
    references: list[Reference] = field(default_factory=list)
    techniques: list[ExternalId] = field(default_factory=list)
    weaknesses: list[ExternalId] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    attack_pattern: str = ""
    security_properties: list[str] = field(default_factory=list)
    raw_content_hash: str = ""
    normalization_version: str = NORMALIZATION_VERSION
    upstream_url: str = ""
    source_version: str = ""
    parser_version: str = ""
    fetched_at: float | None = None
    title_truncated: bool = False
    description_truncated: bool = False
    clock_anomaly: str | None = None
    withdrawn: bool = False
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "description": self.description,
            "published_at": self.published_at,
            "modified_at": self.modified_at,
            "severity": self.severity,
            "references": [r.to_dict() for r in self.references],
            "techniques": [t.to_dict() for t in self.techniques],
            "weaknesses": [w.to_dict() for w in self.weaknesses],
            "affected_components": list(self.affected_components),
            "prerequisites": list(self.prerequisites),
            "attack_pattern": self.attack_pattern,
            "security_properties": list(self.security_properties),
            "raw_content_hash": self.raw_content_hash,
            "normalization_version": self.normalization_version,
            "upstream_url": self.upstream_url,
            "source_version": self.source_version,
            "parser_version": self.parser_version,
            "fetched_at": self.fetched_at,
            "title_truncated": self.title_truncated,
            "description_truncated": self.description_truncated,
            "clock_anomaly": self.clock_anomaly,
            "withdrawn": self.withdrawn,
            "provenance": dict(self.provenance),
        }


def validate_item(doc: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["item must be an object"]
    for key in ("id", "source", "source_id", "title", "raw_content_hash", "normalization_version"):
        if not isinstance(doc.get(key), str) or not doc.get(key):
            errors.append(f"item.{key} must be a non-empty string")
    if doc.get("severity") not in SEVERITIES:
        errors.append("item.severity is not a known severity")
    if not isinstance(doc.get("references"), list):
        errors.append("item.references must be a list")
    if not isinstance(doc.get("techniques"), list) or not isinstance(doc.get("weaknesses"), list):
        errors.append("item techniques and weaknesses must be lists")
    return errors


def classify_reference(url: str) -> Reference:
    """Record a reference without fetching it."""
    from urllib.parse import urlsplit

    text = str(url or "").strip()
    if not text or len(text) > 2000:
        return Reference(url=text[:2000], accepted=False, reason="empty_or_oversized")
    lowered = text.lower()
    if lowered.startswith(("javascript:", "data:", "file:", "ftp:", "gopher:")):
        return Reference(url=text[:2000], accepted=False, reason="scheme_rejected")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        return Reference(url=text[:2000], accepted=False, reason="scheme_rejected")
    if parts.username or parts.password:
        return Reference(url=text[:2000], accepted=False, reason="userinfo_rejected")
    host = (parts.hostname or "").lower()
    if not host:
        return Reference(url=text[:2000], accepted=False, reason="host_missing")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        return Reference(url=text[:2000], accepted=False, reason="non_public_host")
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".internal"):
        return Reference(url=text[:2000], accepted=False, reason="non_public_host")
    return Reference(url=text[:2000], accepted=True, reason="stored_not_fetched")
