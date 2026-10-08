"""Source adapter contract.

``fetch_since`` receives only the adapter's configured URL. Normalised items
are data. They do not carry instructions for the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..http_client import SafeHttpClient
from ..models import ThreatIntelligenceItem


@dataclass
class SourceMetadata:
    source_id: str
    title: str
    homepage: str
    fetch_url: str | None
    machine_readable: bool
    implementation: str
    parser_version: str
    default_interval_seconds: float
    allow_hosts: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "title": self.title,
            "homepage": self.homepage,
            "fetch_url": self.fetch_url,
            "machine_readable": self.machine_readable,
            "implementation": self.implementation,
            "parser_version": self.parser_version,
            "default_interval_seconds": self.default_interval_seconds,
            "allow_hosts": sorted(self.allow_hosts),
        }


@dataclass
class FetchBatch:
    items: list[dict[str, Any]]
    next_cursor: dict[str, Any]
    unchanged: bool = False
    baseline: bool = False
    source_version: str = ""
    etag: str | None = None
    last_modified: str | None = None
    content_hash: str = ""
    notes: list[str] = field(default_factory=list)
    rollback: bool = False


class ThreatSource(Protocol):
    def source_id(self) -> str: ...

    def metadata(self) -> SourceMetadata: ...

    def fetch_since(self, cursor: dict[str, Any] | None, client: SafeHttpClient) -> FetchBatch: ...

    def normalize(self, raw: dict[str, Any]) -> ThreatIntelligenceItem | None: ...

    def health(self) -> dict[str, Any]: ...
