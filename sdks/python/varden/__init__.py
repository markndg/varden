"""Public import surface for the published Python SDK package.

`pip install varden` exposes this package so users can do:

    import varden
    varden.protect()
"""

from varden_sdk import (
    GuardResult,
    TaggedData,
    VardenBlockedError,
    VardenClient,
    VardenGuard,
    current_guard,
    protect,
    protect_from_env,
    tagged,
    tool,
    trace_agent,
    unpatch_runtime,
)

tagged_data = tagged

__all__ = [
    "GuardResult",
    "TaggedData",
    "VardenBlockedError",
    "VardenClient",
    "VardenGuard",
    "current_guard",
    "protect",
    "protect_from_env",
    "tagged",
    "tagged_data",
    "tool",
    "trace_agent",
    "unpatch_runtime",
]
