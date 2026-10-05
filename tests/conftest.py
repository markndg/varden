import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _declare_pa_single_worker_for_tests(monkeypatch):
    """Unit/integration tests run in one process; declare the supported topology.

    Gauntlet tests that exercise *undeclared* deployment must
    ``monkeypatch.delenv("VARDEN_PA_DEPLOYMENT", raising=False)``.
    """
    monkeypatch.setenv("VARDEN_PA_DEPLOYMENT", "single_worker")
