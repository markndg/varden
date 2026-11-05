"""Marks integrity-component I/O so asset hashing does not re-enter the guard.

An in-process caller that can import this module can also set the flag.
That is the same trust limit as every other Python monkeypatch.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Iterator

_INTERNAL = contextvars.ContextVar("varden_mip_internal_io", default=False)


def internal_io_active() -> bool:
    return bool(_INTERNAL.get())


@contextmanager
def internal_io() -> Iterator[None]:
    token = _INTERNAL.set(True)
    try:
        yield
    finally:
        _INTERNAL.reset(token)
