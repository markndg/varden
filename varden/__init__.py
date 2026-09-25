"""Varden public API.

SDK symbols are resolved lazily (PEP 562). ``varden_sdk.sdk`` imports
``varden.runtime``; importing ``varden.sdk`` eagerly here created a cycle that
made ``import varden_sdk`` fail whenever it was the first import.
"""

from __future__ import annotations

from typing import Any

_SDK_EXPORTS = (
    'GuardResult',
    'VardenBlockedError',
    'VardenClient',
    'VardenGuard',
    'TaggedData',
    'current_guard',
    'observe_provenance',
    'protect',
    'protect_from_env',
    'provenance_scope',
    'register_tool',
    'tagged',
    'tool',
    'trace_agent',
    'unpatch_runtime',
)

__all__ = [
    'VardenGuard', 'VardenBlockedError', 'GuardResult', 'TaggedData', 'VardenClient',
    'protect', 'protect_from_env', 'tool', 'register_tool', 'trace_agent', 'tagged', 'tagged_data',
    'observe_provenance', 'provenance_scope', 'current_guard', 'unpatch_runtime'
]


def __getattr__(name: str) -> Any:
    if name == 'tagged_data':
        name = 'tagged'
    if name in _SDK_EXPORTS:
        from . import sdk as _sdk

        value = getattr(_sdk, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module 'varden' has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
