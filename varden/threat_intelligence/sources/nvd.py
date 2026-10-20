"""NVD CVE API 2.0.

Incremental via ``lastModStartDate``. The keyword is an operator relevance
filter, not a contract. A keyword match never selects a Varden rule.
The full CVE corpus is not downloaded.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

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
# A hostile totalResults must not page this process forever. The window closes
# and the source records that the remainder was not retrieved.
WINDOW_RECORD_CAP = 2000


class NvdSource:
    def __init__(
        self,
        *,
        url: str,
        allow_hosts: frozenset[str],
        interval_seconds: float,
        keyword: str,
        api_key: str | None,
        results_per_page: int,
        lookback_hours: float,
        min_interval_seconds: float,
        max_field_chars: int = 4000,
    ) -> None:
        self._url = url
        self._hosts = allow_hosts
        self._interval = interval_seconds
        self._keyword = keyword
        self._api_key = api_key
        self._page = results_per_page
        self._lookback_hours = lookback_hours
        self._min_interval = min_interval_seconds
        self._limit = max_field_chars
        self._health: dict[str, Any] = {"state": "unknown", "detail": "not checked"}

    def source_id(self) -> str:
        return "nvd"

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            source_id="nvd",
            title="NVD/CVE",
            homepage="https://nvd.nist.gov/",
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
        previous = dict(cursor or {})
        now = datetime.now(timezone.utc).replace(microsecond=0)
        if previous.get("window_end"):
            start = previous.get("last_mod_start") or previous.get("window_end")
            end = previous.get("window_end") if int(previous.get("start_index") or 0) else _iso(now)
            baseline = False
        else:
            start = _iso(now - timedelta(hours=self._lookback_hours))
            end = _iso(now)
            baseline = True
        start_index = int(previous.get("start_index") or 0) if not baseline else 0
        if not baseline and int(previous.get("start_index") or 0) == 0:
            start = previous.get("window_end") or start
            end = _iso(now)
        query = {
            "lastModStartDate": start,
            "lastModEndDate": end,
            "startIndex": start_index,
            "resultsPerPage": self._page,
        }
        if self._keyword:
            query["keywordSearch"] = self._keyword
        url = _with_query(self._url, query)
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key
        try:
            result = client.get(
                url,
                allow_hosts=self._hosts,
                etag=previous.get("etag") if start_index == 0 else None,
                last_modified=previous.get("last_modified") if start_index == 0 else None,
                accept="application/json",
                extra_headers=headers,
                min_interval=self._min_interval,
            )
        except IntelHttpError as exc:
            self._health = {"state": "error", "detail": f"{exc.code}: {exc}"}
            raise
        if result.unchanged:
            self._health = {"state": "healthy", "detail": "not modified"}
            return FetchBatch(
                items=[],
                next_cursor={**previous, "etag": result.headers.get("etag") or previous.get("etag")},
                unchanged=True,
                baseline=False,
                source_version=str(previous.get("source_version") or ""),
                etag=result.headers.get("etag"),
                last_modified=result.headers.get("last-modified"),
            )
        try:
            payload = json.loads(result.body.decode("utf-8"))
        except UnicodeDecodeError as exc:
            self._health = {"state": "error", "detail": "invalid utf-8"}
            raise IntelHttpError("invalid_utf8", "NVD body is not utf-8") from exc
        except json.JSONDecodeError as exc:
            self._health = {"state": "error", "detail": "malformed json"}
            raise IntelHttpError("malformed_json", "NVD body is not JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            self._health = {"state": "error", "detail": "unexpected nvd document"}
            raise IntelHttpError("malformed_json", "NVD document missing vulnerabilities")
        vulns = [row for row in payload["vulnerabilities"] if isinstance(row, dict)]
        total = int(payload.get("totalResults") or len(vulns))
        next_index = start_index + len(vulns)
        truncated = next_index < total and (not vulns or next_index >= WINDOW_RECORD_CAP)
        if next_index < total and vulns and next_index < WINDOW_RECORD_CAP:
            next_cursor = {
                "last_mod_start": start,
                "window_end": end,
                "start_index": next_index,
                "etag": result.headers.get("etag"),
                "last_modified": result.headers.get("last-modified"),
                "bootstrapped": True,
            }
            page_baseline = False
        else:
            next_cursor = {
                "last_mod_start": end,
                "window_end": end,
                "start_index": 0,
                "etag": result.headers.get("etag"),
                "last_modified": result.headers.get("last-modified"),
                "bootstrapped": True,
            }
            page_baseline = False
        items = []
        for row in vulns:
            cve = row.get("cve") if isinstance(row.get("cve"), dict) else row
            if isinstance(cve, dict) and cve.get("id"):
                items.append({"cve": cve, "upstream_url": "https://nvd.nist.gov/vuln/detail/" + str(cve.get("id"))})
        note = ""
        if truncated:
            note = f"window closed with {next_index} of {total} upstream results retrieved"
            self._health = {"state": "degraded", "detail": note}
        else:
            self._health = {"state": "healthy", "detail": f"{len(items)} records, totalResults {total}"}
        return FetchBatch(
            items=items,
            next_cursor=next_cursor,
            unchanged=False,
            baseline=page_baseline,
            source_version="nvd-2.0",
            etag=result.headers.get("etag"),
            last_modified=result.headers.get("last-modified"),
            content_hash=content_hash([row.get("cve", {}).get("id") for row in items]),
            notes=[note] if note else [],
        )

    def normalize(self, raw: dict[str, Any]) -> ThreatIntelligenceItem | None:
        cve = raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
        if not isinstance(cve, dict):
            return None
        cve_id = str(cve.get("id") or "")
        if not cve_id.startswith("CVE-"):
            return None
        title = cve_id
        description = ""
        for row in cve.get("descriptions") or []:
            if isinstance(row, dict) and str(row.get("lang") or "").lower() == "en":
                description = str(row.get("value") or "")
                break
        title_text, title_cut = bound_text(title, 80)
        description, desc_cut = bound_text(description, self._limit)
        weaknesses = []
        for weakness in cve.get("weaknesses") or []:
            if not isinstance(weakness, dict):
                continue
            for desc in weakness.get("description") or []:
                if isinstance(desc, dict) and str(desc.get("value") or "").startswith("CWE-"):
                    weaknesses.append(ExternalId("cwe", str(desc.get("value")).split()[0][:32]))
        refs = []
        for ref in cve.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(classify_reference(str(ref.get("url"))))
        published = _nvd_epoch(cve.get("published"))
        modified = _nvd_epoch(cve.get("lastModified"))
        severity = _severity(cve)
        anomaly = None
        import time

        now = time.time()
        if published and modified and modified + 3600 < published:
            anomaly = "modified_before_published"
        if (published and published > now + 48 * 3600) or (modified and modified > now + 48 * 3600):
            anomaly = "timestamp_in_future"
        return ThreatIntelligenceItem(
            id=make_item_id("nvd", cve_id),
            source="nvd",
            source_id=cve_id,
            title=title_text,
            description=description,
            published_at=published,
            modified_at=modified,
            severity=severity,
            references=refs,
            techniques=[],
            weaknesses=weaknesses,
            raw_content_hash=content_hash(
                {"id": cve_id, "modified": cve.get("lastModified"), "description": description, "weaknesses": [w.id for w in weaknesses]}
            ),
            upstream_url=str(raw.get("upstream_url") or ""),
            source_version="nvd-2.0",
            parser_version=PARSER_VERSION,
            title_truncated=title_cut,
            description_truncated=desc_cut,
            clock_anomaly=anomaly,
            provenance={"keyword_filter": self._keyword, "parser": "nvd-cve-2.0"},
        )


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _with_query(url: str, query: dict[str, Any]) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _nvd_epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "+" not in text[10:] and "-" not in text[10:]:
        text += "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows or not isinstance(rows[0], dict):
            continue
        data = rows[0].get("cvssData") if isinstance(rows[0].get("cvssData"), dict) else {}
        label = str(data.get("baseSeverity") or rows[0].get("baseSeverity") or "").lower()
        if label in {"none", "low", "medium", "high", "critical"}:
            return label
    return "unknown"
