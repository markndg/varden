"""CWE catalog via the official XML zip.

The catalog is not a delta feed. Conditional HTTP plus a local hash index
avoids repeat work. Only weaknesses Varden has an explicit binding for become
threat items. Other ids are indexed so CVE links can be explained, and are
not promoted into threats.
"""

from __future__ import annotations

import io
import json
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

from ..contracts import CWE_MAP, REVIEW_ONLY
from ..http_client import IntelHttpError, SafeHttpClient
from ..models import ExternalId, ThreatIntelligenceItem, bound_text, content_hash, make_item_id
from .base import FetchBatch, SourceMetadata

PARSER_VERSION = "1"
RELEVANT = frozenset(CWE_MAP) | frozenset(key for key in REVIEW_ONLY if key.startswith("CWE-"))
_ZIP_TYPES = frozenset({"application/zip", "application/octet-stream", "application/x-zip-compressed"})


class CweSource:
    def __init__(
        self,
        *,
        url: str,
        allow_hosts: frozenset[str],
        interval_seconds: float,
        max_uncompressed_bytes: int,
        max_field_chars: int = 4000,
    ) -> None:
        self._url = url
        self._hosts = allow_hosts
        self._interval = interval_seconds
        self._max_uncompressed = max_uncompressed_bytes
        self._limit = max_field_chars
        self._health: dict[str, Any] = {"state": "unknown", "detail": "not checked"}

    def source_id(self) -> str:
        return "cwe"

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            source_id="cwe",
            title="CWE",
            homepage="https://cwe.mitre.org/",
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
                accept="application/zip",
                max_bytes=max(client.max_bytes, 16_000_000),
            )
        except IntelHttpError as exc:
            self._health = {"state": "error", "detail": f"{exc.code}: {exc}"}
            raise
        etag = result.headers.get("etag") or previous.get("etag")
        last_modified = result.headers.get("last-modified") or previous.get("last_modified")
        if result.unchanged:
            self._health = {"state": "healthy", "detail": "not modified"}
            return FetchBatch(
                items=[],
                next_cursor=dict(previous),
                unchanged=True,
                etag=etag,
                last_modified=last_modified,
                content_hash=str(previous.get("content_hash") or ""),
                source_version=str(previous.get("source_version") or ""),
            )
        mime = (result.headers.get("content-type") or "application/zip").split(";", 1)[0].strip().lower()
        if mime and mime not in _ZIP_TYPES and not result.body.startswith(b"PK"):
            self._health = {"state": "error", "detail": f"unexpected mime {mime}"}
            raise IntelHttpError("mime_rejected", f"CWE response content-type {mime}")
        try:
            catalog = parse_cwe_zip(result.body, max_uncompressed=self._max_uncompressed)
        except IntelHttpError:
            self._health = {"state": "error", "detail": "catalog rejected"}
            raise
        version = catalog.get("version") or ""
        index = catalog.get("index") or {}
        previous_index = previous.get("index") or {}
        baseline = not previous.get("bootstrapped")
        rollback = bool(previous.get("source_version") and version and str(version) < str(previous.get("source_version")) and previous_index)
        emitted = []
        for cwe_id, row in index.items():
            if cwe_id not in RELEVANT:
                continue
            if baseline or previous_index.get(cwe_id) != row.get("hash"):
                emitted.append({"weakness": row, "source_version": version, "upstream_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"})
        notes = ["upstream version moved backwards; stored items were kept"] if rollback else []
        self._health = {"state": "degraded" if rollback else "healthy", "detail": "rollback" if rollback else "ok"}
        stored_index = {cwe_id: row.get("hash") for cwe_id, row in index.items()}
        return FetchBatch(
            items=emitted,
            next_cursor={
                "etag": etag,
                "last_modified": last_modified,
                "source_version": version,
                "content_hash": catalog.get("content_hash"),
                "index": stored_index,
                "bootstrapped": True,
            },
            unchanged=False,
            baseline=baseline,
            source_version=str(version),
            etag=etag,
            last_modified=last_modified,
            content_hash=str(catalog.get("content_hash") or ""),
            notes=notes,
            rollback=rollback,
        )

    def normalize(self, raw: dict[str, Any]) -> ThreatIntelligenceItem | None:
        row = raw.get("weakness") if isinstance(raw.get("weakness"), dict) else raw
        if not isinstance(row, dict):
            return None
        cwe_id = str(row.get("id") or "")
        if cwe_id not in RELEVANT:
            return None
        title, title_cut = bound_text(row.get("name") or cwe_id, 300)
        description, desc_cut = bound_text(row.get("description") or "", self._limit)
        return ThreatIntelligenceItem(
            id=make_item_id("cwe", cwe_id),
            source="cwe",
            source_id=cwe_id,
            title=title,
            description=description,
            published_at=None,
            modified_at=None,
            severity="unknown",
            references=[],
            techniques=[],
            weaknesses=[ExternalId("cwe", cwe_id)],
            raw_content_hash=str(row.get("hash") or content_hash(row)),
            upstream_url=str(raw.get("upstream_url") or ""),
            source_version=str(raw.get("source_version") or ""),
            parser_version=PARSER_VERSION,
            title_truncated=title_cut,
            description_truncated=desc_cut,
            provenance={"parser": "cwe-xml-v1", "relevant": True},
        )


def inspect_zip_limits(infos: list[Any], *, max_uncompressed: int, max_files: int = 8, max_ratio: float = 100.0) -> None:
    if len(infos) > max_files:
        raise IntelHttpError("decompression_bomb", "archive has too many members")
    total = 0
    for info in infos:
        size = int(getattr(info, "file_size", 0) or 0)
        compressed = int(getattr(info, "compress_size", 0) or 0)
        if size < 0 or size > max_uncompressed:
            raise IntelHttpError("decompression_bomb", "archive member declares an unsafe size")
        total += size
        if total > max_uncompressed:
            raise IntelHttpError("decompression_bomb", "archive uncompressed size exceeds the limit")
        if compressed > 0 and size > 1_000_000 and (size / compressed) > max_ratio:
            raise IntelHttpError("decompression_bomb", "archive compression ratio exceeds the limit")


def parse_cwe_zip(data: bytes, *, max_uncompressed: int) -> dict[str, Any]:
    if not data.startswith(b"PK"):
        raise IntelHttpError("malformed_json", "CWE payload is not a zip archive")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            inspect_zip_limits(archive.infolist(), max_uncompressed=max_uncompressed)
            names = [info.filename for info in archive.infolist() if not info.is_dir()]
            xml_name = next((name for name in names if name.lower().endswith(".xml")), "")
            if not xml_name:
                raise IntelHttpError("malformed_json", "CWE archive has no XML member")
            raw = archive.read(xml_name)
    except zipfile.BadZipFile as exc:
        raise IntelHttpError("malformed_json", "CWE archive is not a valid zip") from exc
    if len(raw) > max_uncompressed:
        raise IntelHttpError("decompression_bomb", "CWE XML exceeds the uncompressed limit")
    return parse_cwe_xml(raw)


def parse_cwe_xml(raw: bytes) -> dict[str, Any]:
    try:
        raw[:200].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntelHttpError("invalid_utf8", "CWE XML is not utf-8") from exc
    # ElementTree expands internal entities. Official CWE XML has no DTD.
    # A DOCTYPE or entity declaration is refused before any expansion.
    head = raw[:8192].lstrip().lower()
    if b"<!doctype" in head or b"<!entity" in raw.lower():
        raise IntelHttpError("malformed_json", "CWE XML with a doctype or entity declaration is refused")
    index: dict[str, dict[str, Any]] = {}
    version = ""
    try:
        for _event, elem in ET.iterparse(io.BytesIO(raw), events=("end",)):
            tag = elem.tag.split("}")[-1]
            if tag in {"Weakness_Catalog", "Catalog"} and not version:
                version = str(elem.attrib.get("Version") or elem.attrib.get("Date") or "")[:64]
            if tag != "Weakness":
                continue
            wid = str(elem.attrib.get("ID") or "").strip()
            if not wid.isdigit():
                elem.clear()
                continue
            cwe_id = f"CWE-{wid}"
            name = str(elem.attrib.get("Name") or "")[:300]
            description = ""
            for child in elem.iter():
                if child.tag.split("}")[-1] in {"Description", "Description_Summary"} and (child.text or "").strip():
                    description = child.text.strip()
                    break
            description, _truncated = bound_text(description, 4000)
            row = {"id": cwe_id, "name": name, "description": description}
            row["hash"] = content_hash({"id": cwe_id, "name": name, "description": description})
            index[cwe_id] = row
            elem.clear()
    except ET.ParseError as exc:
        raise IntelHttpError("malformed_json", "CWE XML is not well formed") from exc
    if not index:
        raise IntelHttpError("malformed_json", "CWE document contained no weaknesses")
    return {
        "version": version,
        "index": index,
        "content_hash": content_hash({"version": version, "count": len(index), "relevant": sorted(cwe_id for cwe_id in index if cwe_id in RELEVANT)}),
    }


def dumps_index(index: dict[str, str]) -> str:
    return json.dumps(index, sort_keys=True)
