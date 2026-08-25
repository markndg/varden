"""Runtime test fixtures."""

from __future__ import annotations

import pytest

import varden


@pytest.fixture(autouse=True)
def _unpatch_varden_runtime():
    varden.unpatch_runtime()
    yield
    varden.unpatch_runtime()
