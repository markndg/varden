"""OWASP agentic security adapter.

The official OWASP Top 10 for Agentic Applications is published as PDF/HTML.
This adapter does not scrape that. It stays a scaffold unless an operator
pins ``VARDEN_TI_OWASP_URL`` to a versioned JSON document with schema
``owasp-agentic-v1``.
"""

from __future__ import annotations

import json
from typing import Any

from ..http_client import IntelHttpError, SafeHttpClient
from ..models import ThreatIntelligenceItem, bound_text, classify_reference, content_hash, make_item_id
from .base import FetchBatch, SourceMetadata

PARSER_VERSION = "1"
SCHEMA = "owasp-agentic-v1"


class OwaspSource:
    def __init__(self, *, url: str | None, allow_hosts: frozenset[str], interval_seconds: float, max_field_chars: int = 4000) -> None:
        self._url = url
        self._hosts = allow_hosts
        self._interval = interval_seconds
        self._limit = max_field_chars
        if not url:
            self._health: dict[str, Any] = {
                "state": "unsupported",
                "detail": "No stable official machine-readable OWASP agentic feed is pinned. HTML and PDF are not scraped.",
            }
        else:
            self._health = {"state": "unknown", "detail": "not checked"}

    def source_id(self) -> str:
        return "owasp"

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            source_id="owasp",
            title="OWASP Agentic",
            homepage="https://genai.owasp.org/",
            fetch_url=self._url,
            machine_readable=bool(self._url),
            implementation="implemented" if self._url else "scaffold",
            parser_version=PARSER_VERSION,
            default_interval_seconds=self._interval,
            allow_hosts=self._hosts,
        )

    def health(self) -> dict[str, Any]:
        return dict(self._health)

    def fetch_since(self, cursor: dict[str, Any] | None, client: SafeHttpClient) -> FetchBatch:
        if not self._url:
            return FetchBatch(
                items=[],
                next_cursor=dict(cursor or {}),
                unchanged=True,
                notes=["scaffold: official OWASP agentic material is not consumed as HTML or PDF"],
            )
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
        if result.unchanged:
            self._health = {"state": "healthy", "detail": "not modified"}
            return FetchBatch(items=[], next_cursor=dict(previous), unchanged=True, etag=result.headers.get("etag"), last_modified=result.headers.get("last-modified"))
        mime = (result.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if mime and mime not in {"application/json", "application/octet-stream"}:
            self._health = {"state": "degraded", "detail": f"refusing mime {mime}; JSON schema {SCHEMA} is required"}
            raise IntelHttpError("mime_rejected", f"OWASP URL did not return JSON ({mime})")
        try:
            document = json.loads(result.body.decode("utf-8"))
        except UnicodeDecodeError as exc:
            self._health = {"state": "error", "detail": "invalid utf-8"}
            raise IntelHttpError("invalid_utf8", "OWASP body is not utf-8") from exc
        except json.JSONDecodeError as exc:
            self._health = {"state": "error", "detail": "malformed json"}
            raise IntelHttpError("malformed_json", "OWASP body is not JSON") from exc
        if not isinstance(document, dict) or document.get("schema") != SCHEMA or not isinstance(document.get("entries"), list):
            self._health = {"state": "degraded", "detail": f"document is not schema {SCHEMA}"}
            raise IntelHttpError("malformed_json", f"OWASP document must use schema {SCHEMA}")
        version = str(document.get("version") or "")[:64]
        items = []
        for entry in document["entries"]:
            if isinstance(entry, dict) and entry.get("id"):
                items.append({"entry": entry, "source_version": version, "upstream_url": self._url})
        baseline = not previous.get("bootstrapped")
        known = previous.get("hashes") or {}
        hashes = {}
        emitted = []
        for raw in items:
            entry = raw["entry"]
            digest = content_hash({"id": entry.get("id"), "title": entry.get("title"), "summary": entry.get("summary")})
            hashes[str(entry.get("id"))] = digest
            if baseline or known.get(str(entry.get("id"))) != digest:
                emitted.append(raw)
        self._health = {"state": "healthy", "detail": f"schema {SCHEMA}"}
        return FetchBatch(
            items=emitted if not baseline else items,
            next_cursor={"etag": result.headers.get("etag"), "last_modified": result.headers.get("last-modified"), "bootstrapped": True, "hashes": hashes, "source_version": version},
            baseline=baseline,
            source_version=version,
            etag=result.headers.get("etag"),
            last_modified=result.headers.get("last-modified"),
            content_hash=content_hash(hashes),
        )

    def normalize(self, raw: dict[str, Any]) -> ThreatIntelligenceItem | None:
        entry = raw.get("entry") if isinstance(raw.get("entry"), dict) else raw
        if not isinstance(entry, dict):
            return None
        entry_id = str(entry.get("id") or "").strip()
        if not entry_id.startswith("ASI"):
            return None
        title, title_cut = bound_text(entry.get("title") or entry_id, 300)
        description, desc_cut = bound_text(entry.get("summary") or "", self._limit)
        refs = []
        if entry.get("url"):
            refs.append(classify_reference(str(entry.get("url"))))
        return ThreatIntelligenceItem(
            id=make_item_id("owasp", entry_id),
            source="owasp",
            source_id=entry_id,
            title=title,
            description=description,
            published_at=None,
            modified_at=None,
            severity="unknown",
            references=refs,
            raw_content_hash=content_hash({"id": entry_id, "title": title, "summary": description}),
            upstream_url=str(raw.get("upstream_url") or self._url or ""),
            source_version=str(raw.get("source_version") or ""),
            parser_version=PARSER_VERSION,
            title_truncated=title_cut,
            description_truncated=desc_cut,
            provenance={"schema": SCHEMA, "parser": "owasp-agentic-v1"},
        )
