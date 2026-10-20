"""Threat Intelligence configuration.

Polling intervals are per source. Nothing here assumes a single global period.
The feature is disabled unless ``VARDEN_TI_ENABLED`` is set. Disabling it does
not change firewall behaviour.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    return float(raw)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    return int(raw)


# Pinned ATLAS STIX release. Operators can point at a newer release asset.
# The YAML knowledge base is not parsed: this adapter consumes STIX JSON only.
DEFAULT_ATLAS_URL = (
    "https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/stix-atlas.json"
)
DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

ATLAS_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "raw.githubusercontent.com",
    }
)
NVD_HOSTS = frozenset({"services.nvd.nist.gov"})
CWE_HOSTS = frozenset({"cwe.mitre.org"})


@dataclass
class ThreatIntelConfig:
    enabled: bool = False
    db_path: str = "varden.db"
    policy_file: str = "policy.json"
    retention_items: int = 5000
    replay_max_events: int = 20000
    max_response_bytes: int = 8_000_000
    cwe_max_response_bytes: int = 16_000_000
    cwe_max_uncompressed_bytes: int = 64_000_000
    max_field_chars: int = 4000
    request_timeout_seconds: float = 20.0
    max_attempts: int = 3
    backoff_base_seconds: float = 1.0
    backoff_cap_seconds: float = 300.0
    jitter_ratio: float = 0.2
    suppress_baseline_notifications: bool = True
    user_agent: str = "VardenThreatIntelligence/1 (+https://github.com/markndg/varden)"

    atlas_url: str = DEFAULT_ATLAS_URL
    atlas_interval_seconds: float = 86_400.0
    atlas_hosts: frozenset[str] = field(default_factory=lambda: ATLAS_HOSTS)

    nvd_url: str = DEFAULT_NVD_URL
    nvd_interval_seconds: float = 21_600.0
    nvd_keyword: str = "artificial intelligence"
    nvd_api_key: str | None = None
    nvd_results_per_page: int = 50
    nvd_lookback_hours: float = 24.0
    nvd_min_interval_seconds: float = 6.5
    nvd_hosts: frozenset[str] = field(default_factory=lambda: NVD_HOSTS)

    cwe_url: str = DEFAULT_CWE_URL
    cwe_interval_seconds: float = 604_800.0
    cwe_hosts: frozenset[str] = field(default_factory=lambda: CWE_HOSTS)

    # Empty URL means the OWASP adapter stays a scaffold and does not fetch.
    owasp_url: str | None = None
    owasp_interval_seconds: float = 86_400.0
    owasp_hosts: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls, *, enabled: bool | None = None, db_path: str | None = None, policy_file: str | None = None) -> "ThreatIntelConfig":
        owasp_url = (os.getenv("VARDEN_TI_OWASP_URL") or "").strip() or None
        owasp_hosts: frozenset[str] = frozenset()
        if owasp_url:
            from urllib.parse import urlsplit

            host = (urlsplit(owasp_url).hostname or "").lower()
            extra = {
                part.strip().lower()
                for part in (os.getenv("VARDEN_TI_OWASP_ALLOW_HOSTS") or "").split(",")
                if part.strip()
            }
            if host:
                extra.add(host)
            owasp_hosts = frozenset(extra)
        nvd_key = (os.getenv("VARDEN_TI_NVD_API_KEY") or "").strip() or None
        nvd_interval = 0.7 if nvd_key else _env_float("VARDEN_TI_NVD_MIN_INTERVAL_SECONDS", 6.5)
        return cls(
            enabled=_env_bool("VARDEN_TI_ENABLED", False) if enabled is None else enabled,
            db_path=db_path or os.getenv("VARDEN_DB_PATH", "varden.db"),
            policy_file=policy_file or os.getenv("VARDEN_POLICY_FILE", "policy.json"),
            retention_items=_env_int("VARDEN_TI_RETENTION_ITEMS", 5000),
            replay_max_events=_env_int("VARDEN_TI_REPLAY_MAX_EVENTS", 20000),
            max_response_bytes=_env_int("VARDEN_TI_MAX_RESPONSE_BYTES", 8_000_000),
            cwe_max_response_bytes=_env_int("VARDEN_TI_CWE_MAX_RESPONSE_BYTES", 16_000_000),
            cwe_max_uncompressed_bytes=_env_int("VARDEN_TI_CWE_MAX_UNCOMPRESSED_BYTES", 64_000_000),
            max_field_chars=_env_int("VARDEN_TI_MAX_FIELD_CHARS", 4000),
            request_timeout_seconds=_env_float("VARDEN_TI_TIMEOUT_SECONDS", 20.0),
            max_attempts=_env_int("VARDEN_TI_MAX_ATTEMPTS", 3),
            backoff_base_seconds=_env_float("VARDEN_TI_BACKOFF_BASE_SECONDS", 1.0),
            backoff_cap_seconds=_env_float("VARDEN_TI_BACKOFF_CAP_SECONDS", 300.0),
            jitter_ratio=_env_float("VARDEN_TI_JITTER_RATIO", 0.2),
            suppress_baseline_notifications=_env_bool("VARDEN_TI_SUPPRESS_BASELINE", True),
            atlas_url=os.getenv("VARDEN_TI_ATLAS_URL", DEFAULT_ATLAS_URL),
            atlas_interval_seconds=_env_float("VARDEN_TI_ATLAS_INTERVAL_SECONDS", 86_400.0),
            nvd_url=os.getenv("VARDEN_TI_NVD_URL", DEFAULT_NVD_URL),
            nvd_interval_seconds=_env_float("VARDEN_TI_NVD_INTERVAL_SECONDS", 21_600.0),
            nvd_keyword=os.getenv("VARDEN_TI_NVD_KEYWORD", "artificial intelligence"),
            nvd_api_key=nvd_key,
            nvd_results_per_page=min(200, max(1, _env_int("VARDEN_TI_NVD_PAGE_SIZE", 50))),
            nvd_lookback_hours=_env_float("VARDEN_TI_NVD_LOOKBACK_HOURS", 24.0),
            nvd_min_interval_seconds=nvd_interval,
            cwe_url=os.getenv("VARDEN_TI_CWE_URL", DEFAULT_CWE_URL),
            cwe_interval_seconds=_env_float("VARDEN_TI_CWE_INTERVAL_SECONDS", 604_800.0),
            owasp_url=owasp_url,
            owasp_interval_seconds=_env_float("VARDEN_TI_OWASP_INTERVAL_SECONDS", 86_400.0),
            owasp_hosts=owasp_hosts,
        )

    def interval_for(self, source_id: str) -> float:
        return {
            "atlas": self.atlas_interval_seconds,
            "nvd": self.nvd_interval_seconds,
            "cwe": self.cwe_interval_seconds,
            "owasp": self.owasp_interval_seconds,
        }.get(source_id, self.atlas_interval_seconds)
