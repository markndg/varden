"""Varden Enforced Runtime Boundary.

This package implements the shared pre-execution enforcement surface used by
HTTP, subprocess, filesystem, MCP gateway, and tool adapters. All adapters
feed the same PolicyEngine via ``/sdk/guard`` — they do not invent separate
policy engines.
"""

from .approvals import ApprovalStore, hash_action_scope
from .boundary import BoundaryDecision, enrich_action_runtime_metadata
from .coverage import (
    ENFORCED,
    NOT_ROUTED,
    OBSERVATIONAL,
    PARTIAL,
    UNCOVERED,
    UNSUPPORTED,
    CoverageRegistry,
    CoverageSurface,
    format_startup_attestation,
    get_coverage_registry,
)
from .modes import GUARDED, OBSERVE, STRICT, describe_mode, is_enforcing, normalize_mode

__all__ = [
    "ApprovalStore",
    "BoundaryDecision",
    "CoverageRegistry",
    "CoverageSurface",
    "ENFORCED",
    "GUARDED",
    "NOT_ROUTED",
    "OBSERVE",
    "OBSERVATIONAL",
    "PARTIAL",
    "STRICT",
    "UNCOVERED",
    "UNSUPPORTED",
    "describe_mode",
    "enrich_action_runtime_metadata",
    "format_startup_attestation",
    "get_coverage_registry",
    "hash_action_scope",
    "is_enforcing",
    "normalize_mode",
]
