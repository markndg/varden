from __future__ import annotations

import os

import httpx


def get_client() -> httpx.Client:
    base_url = os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.environ.get("VARDEN_API_KEY", "admin-demo-key")
    timeout = float(os.environ.get("VARDEN_TIMEOUT", "10.0"))
    return httpx.Client(
        base_url=base_url,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    )
