"""Varden MCP integration (requires ``pip install varden[mcp]`` or ``varden[test]`` for imports)."""


def __getattr__(name: str):
    if name == "mcp":
        from varden_mcp.server import mcp as _mcp

        return _mcp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["mcp"]
