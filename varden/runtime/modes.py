"""Runtime protection modes for the enforced runtime boundary.

Terminology (product-facing):

* OBSERVE  — record evidence; do not prevent side effects
* GUARDED  — enforce supported intercepted operations; report coverage gaps
* STRICT   — fail closed for missing critical coverage; refuse silent downgrade

Legacy aliases kept for compatibility:

* ``enforce`` → ``guarded``
* ``monitor`` → ``observe``
"""

from __future__ import annotations

from typing import Any

OBSERVE = "observe"
GUARDED = "guarded"
STRICT = "strict"

MODE_ALIASES = {
    "enforce": GUARDED,
    "monitor": OBSERVE,
    "observation": OBSERVE,
    "observational": OBSERVE,
    "guard": GUARDED,
}

VALID_MODES = frozenset({OBSERVE, GUARDED, STRICT})


def normalize_mode(mode: str | None, *, default: str = GUARDED) -> str:
    text = str(mode or default).strip().lower()
    text = MODE_ALIASES.get(text, text)
    if text not in VALID_MODES:
        raise ValueError(f"unsupported runtime mode: {mode!r} (expected observe|guarded|strict)")
    return text


def is_enforcing(mode: str | None) -> bool:
    """True when policy decisions may prevent side effects."""
    try:
        return normalize_mode(mode) in {GUARDED, STRICT}
    except ValueError:
        return False


def default_fail_mode(mode: str | None) -> str:
    """Control-plane outage semantics."""
    m = normalize_mode(mode)
    if m in {GUARDED, STRICT}:
        return "closed"
    return "open"


def mode_label(mode: str | None) -> str:
    return normalize_mode(mode).upper()


def enforce_compat_mode(mode: str | None) -> str:
    """Map product modes to the historical SDK ``mode`` string used in patches.

    Existing patch sites check ``mode == 'enforce'``. We keep that internal
    flag for enforcing modes while exposing observe/guarded/strict publicly.
    """
    m = normalize_mode(mode)
    return "enforce" if m in {GUARDED, STRICT} else "observe"


def describe_mode(mode: str | None) -> dict[str, Any]:
    m = normalize_mode(mode)
    return {
        "mode": m,
        "label": m.upper(),
        "enforcing": m in {GUARDED, STRICT},
        "fail_mode_default": default_fail_mode(m),
        "strict": m == STRICT,
        "observational": m == OBSERVE,
    }
