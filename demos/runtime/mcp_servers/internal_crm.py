"""Deterministic internal-crm MCP mock — in-memory only, no Varden code."""

from __future__ import annotations

_CUSTOMERS = {
    "123": {"id": "123", "name": "Ada Example", "status": "active"},
    "456": {"id": "456", "name": "Ben Example", "status": "active"},
}


def handle(tool: str, arguments: dict) -> dict:
    args = arguments or {}
    if tool == "get_customer":
        cid = str(args.get("id") or "")
        row = _CUSTOMERS.get(cid)
        if not row:
            return {"content": [{"type": "text", "text": "not found"}]}
        return {"content": [{"type": "text", "text": str(row)}]}
    if tool == "delete_user":
        cid = str(args.get("id") or "")
        if cid in _CUSTOMERS:
            del _CUSTOMERS[cid]
            return {"content": [{"type": "text", "text": f"deleted {cid}"}]}
        return {"content": [{"type": "text", "text": "not found"}]}
    raise ValueError(f"unknown tool {tool}")


def customer_exists(cid: str) -> bool:
    return cid in _CUSTOMERS


def reset() -> None:
    _CUSTOMERS.clear()
    _CUSTOMERS.update(
        {
            "123": {"id": "123", "name": "Ada Example", "status": "active"},
            "456": {"id": "456", "name": "Ben Example", "status": "active"},
        }
    )
