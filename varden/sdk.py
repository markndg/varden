"""Compatibility shim for SDK symbols.

The Python SDK source of truth lives in `varden_sdk.sdk`.
This module keeps `varden.sdk` imports stable for existing users.
"""

from varden_sdk.sdk import (
    GuardResult,
    TaggedData,
    VardenBlockedError,
    VardenClient,
    VardenGuard,
    current_guard,
    current_provenance_sources,
    observe_provenance,
    protect,
    protect_from_env,
    provenance_scope,
    register_tool,
    tagged,
    tool,
    trace_agent,
    unpatch_runtime,
)

__all__ = [
    "GuardResult",
    "TaggedData",
    "VardenBlockedError",
    "VardenClient",
    "VardenGuard",
    "current_guard",
    "current_provenance_sources",
    "observe_provenance",
    "protect",
    "protect_from_env",
    "provenance_scope",
    "register_tool",
    "tagged",
    "tool",
    "trace_agent",
    "unpatch_runtime",
]
