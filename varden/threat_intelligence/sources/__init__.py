"""Construct the configured source adapters."""

from __future__ import annotations

from ..config import ThreatIntelConfig
from .atlas import AtlasSource
from .cwe import CweSource
from .nvd import NvdSource
from .owasp import OwaspSource


def build_sources(config: ThreatIntelConfig) -> dict[str, object]:
    return {
        "atlas": AtlasSource(
            url=config.atlas_url,
            allow_hosts=config.atlas_hosts,
            interval_seconds=config.atlas_interval_seconds,
            max_field_chars=config.max_field_chars,
        ),
        "nvd": NvdSource(
            url=config.nvd_url,
            allow_hosts=config.nvd_hosts,
            interval_seconds=config.nvd_interval_seconds,
            keyword=config.nvd_keyword,
            api_key=config.nvd_api_key,
            results_per_page=config.nvd_results_per_page,
            lookback_hours=config.nvd_lookback_hours,
            min_interval_seconds=config.nvd_min_interval_seconds,
            max_field_chars=config.max_field_chars,
        ),
        "cwe": CweSource(
            url=config.cwe_url,
            allow_hosts=config.cwe_hosts,
            interval_seconds=config.cwe_interval_seconds,
            max_uncompressed_bytes=config.cwe_max_uncompressed_bytes,
            max_field_chars=config.max_field_chars,
        ),
        "owasp": OwaspSource(
            url=config.owasp_url,
            allow_hosts=config.owasp_hosts,
            interval_seconds=config.owasp_interval_seconds,
            max_field_chars=config.max_field_chars,
        ),
    }
