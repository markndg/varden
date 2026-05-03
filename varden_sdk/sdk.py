"""Compatibility shim for the Python SDK.

The canonical implementation lives in ``sdks/python/varden_sdk`` so SDK sources
stay grouped under ``sdks/``. This module preserves ``import varden_sdk`` and
loads the implementation without requiring ``sdks`` to be import-discoverable
as a Python package.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_sdk_module():
    try:
        # Fast path when the namespace is importable (typical in this repo).
        from sdks.python.varden_sdk import sdk as module  # type: ignore

        return module
    except ModuleNotFoundError:
        pass

    # Fallback for environments where ``sdks`` is not package-discoverable.
    sdk_path = Path(__file__).resolve().parents[1] / "sdks" / "python" / "varden_sdk" / "sdk.py"
    if not sdk_path.exists():
        raise ModuleNotFoundError(
            "Could not locate the canonical SDK implementation at "
            f"{sdk_path}. If you are running from a packaged distribution, "
            "install the standalone SDK package from sdks/python."
        )

    spec = importlib.util.spec_from_file_location("varden_sdk._canonical_sdk", sdk_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load SDK module spec from {sdk_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_sdk = _load_sdk_module()
globals().update({name: getattr(_sdk, name) for name in dir(_sdk) if not name.startswith("__")})
