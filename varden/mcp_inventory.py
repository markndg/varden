from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .db import connect, init_db
from .redaction import redact_mcp_server


def default_mcp_config_paths() -> list[Path]:
    paths: list[Path] = []
    home = Path.home()
    for candidate in (
        home / ".cursor" / "mcp.json",
        home / ".config" / "cursor" / "mcp.json",
        Path.cwd() / ".cursor" / "mcp.json",
        Path.cwd() / "mcp.json",
    ):
        if candidate.exists():
            paths.append(candidate)
    extra = os.getenv("VARDEN_MCP_CONFIG_PATHS", "")
    for chunk in extra.split(os.pathsep):
        chunk = chunk.strip()
        if chunk:
            p = Path(chunk).expanduser()
            if p.exists():
                paths.append(p)
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve())
        if key not in seen:
            deduped.append(path)
            seen.add(key)
    return deduped


def resolve_mcp_scan_paths(payload: dict[str, Any] | None = None, *, paths: list[Path] | None = None) -> list[Path]:
    if paths is not None:
        return [path.expanduser() for path in paths]
    raw: list[str] = []
    doc = payload or {}
    single = doc.get("path")
    if isinstance(single, str) and single.strip():
        raw.append(single.strip())
    many = doc.get("paths")
    if isinstance(many, list):
        raw.extend(str(item).strip() for item in many if str(item).strip())
    if raw:
        deduped: list[Path] = []
        seen: set[str] = set()
        for chunk in raw:
            path = Path(chunk).expanduser()
            key = str(path)
            if key not in seen:
                deduped.append(path)
                seen.add(key)
        return deduped
    return default_mcp_config_paths()


def parse_mcp_config(path: Path) -> list[dict[str, Any]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    servers = doc.get("mcpServers") or doc.get("mcp_servers") or {}
    if not isinstance(servers, dict):
        return []
    rows: list[dict[str, Any]] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        command = cfg.get("command")
        args = cfg.get("args") or []
        rows.append(
            {
                "name": str(name),
                "config_path": str(path),
                "transport": cfg.get("transport") or ("stdio" if command else "unknown"),
                "command": command,
                "args": args if isinstance(args, list) else [str(args)],
                "url": cfg.get("url"),
            }
        )
    return rows


def _policy_tool_names(policy: dict[str, Any] | None) -> set[str]:
    names: set[str] = set()
    for bucket in ("block", "require_approval", "sanitise", "warn", "monitor", "allow"):
        for rule in (policy or {}).get(bucket) or []:
            tool = rule.get("tool")
            if tool:
                names.add(str(tool).lower())
    return names


class McpInventoryStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_db(db_path)

    def scan(self, paths: list[Path] | None = None, policy: dict[str, Any] | None = None) -> dict[str, Any]:
        paths = paths or default_mcp_config_paths()
        now = time.time()
        discovered_servers = 0
        discovered_tools = 0
        with connect(self.db_path) as conn:
            for path in paths:
                path_str = str(path)
                active_server_ids: set[int] = set()
                for server in parse_mcp_config(path):
                    conn.execute(
                        """
                        INSERT INTO mcp_servers(name, config_path, transport, command, args_json, discovered_at, last_scanned_at)
                        VALUES (?,?,?,?,?,?,?)
                        ON CONFLICT(name, config_path) DO UPDATE SET
                          transport=excluded.transport,
                          command=excluded.command,
                          args_json=excluded.args_json,
                          last_scanned_at=excluded.last_scanned_at
                        """,
                        (
                            server["name"],
                            server["config_path"],
                            server.get("transport"),
                            server.get("command"),
                            json.dumps(server.get("args") or []),
                            now,
                            now,
                        ),
                    )
                    discovered_servers += 1
                    row = conn.execute(
                        "SELECT id FROM mcp_servers WHERE name = ? AND config_path = ?",
                        (server["name"], server["config_path"]),
                    ).fetchone()
                    if not row:
                        continue
                    server_id = int(row["id"])
                    active_server_ids.add(server_id)
                    tools = self._infer_tools(server)
                    active_tool_names: set[str] = set()
                    for tool in tools:
                        conn.execute(
                            """
                            INSERT INTO mcp_tools(server_id, tool_name, description, input_schema_json, discovered_at)
                            VALUES (?,?,?,?,?)
                            ON CONFLICT(server_id, tool_name) DO UPDATE SET
                              description=excluded.description,
                              input_schema_json=excluded.input_schema_json,
                              discovered_at=excluded.discovered_at
                            """,
                            (
                                server_id,
                                tool["name"],
                                tool.get("description"),
                                json.dumps(tool.get("input_schema") or {}),
                                now,
                            ),
                        )
                        active_tool_names.add(tool["name"])
                        discovered_tools += 1
                    if active_tool_names:
                        placeholders = ",".join("?" for _ in active_tool_names)
                        conn.execute(
                            f"""
                            DELETE FROM mcp_tools
                            WHERE server_id = ? AND tool_name NOT IN ({placeholders})
                            """,
                            (server_id, *sorted(active_tool_names)),
                        )
                    else:
                        conn.execute("DELETE FROM mcp_tools WHERE server_id = ?", (server_id,))
                if active_server_ids:
                    placeholders = ",".join("?" for _ in active_server_ids)
                    stale = conn.execute(
                        f"""
                        SELECT id FROM mcp_servers
                        WHERE config_path = ? AND id NOT IN ({placeholders})
                        """,
                        (path_str, *sorted(active_server_ids)),
                    ).fetchall()
                    for stale_row in stale:
                        conn.execute("DELETE FROM mcp_tools WHERE server_id = ?", (int(stale_row["id"]),))
                    conn.execute(
                        f"DELETE FROM mcp_servers WHERE config_path = ? AND id NOT IN ({placeholders})",
                        (path_str, *sorted(active_server_ids)),
                    )
                else:
                    stale = conn.execute(
                        "SELECT id FROM mcp_servers WHERE config_path = ?",
                        (path_str,),
                    ).fetchall()
                    for stale_row in stale:
                        conn.execute("DELETE FROM mcp_tools WHERE server_id = ?", (int(stale_row["id"]),))
                    conn.execute("DELETE FROM mcp_servers WHERE config_path = ?", (path_str,))
            conn.commit()
        return self.inventory(policy=policy, scanned_paths=[str(p) for p in paths], discovered_servers=discovered_servers, discovered_tools=discovered_tools)

    def _infer_tools(self, server: dict[str, Any]) -> list[dict[str, Any]]:
        name = str(server.get("name") or "").lower()
        command = str(server.get("command") or "").lower()
        inferred: list[dict[str, Any]] = []
        if "varden" in name or "varden-mcp" in command or "varden_mcp" in command:
            for tool_name in (
                "varden_health",
                "varden_guard",
                "varden_log_event",
                "varden_get_policy",
                "varden_put_policy",
                "varden_validate_policy",
                "varden_get_events",
                "varden_get_alerts",
                "varden_get_dashboard",
            ):
                inferred.append({"name": tool_name, "description": "Bundled Varden MCP tool"})
            return inferred
        inferred.append(
            {
                "name": f"{server.get('name') or 'mcp'}::*",
                "description": "MCP server registered; run deep scan when MCP client is available",
            }
        )
        return inferred

    def inventory(self, *, policy: dict[str, Any] | None = None, **meta: Any) -> dict[str, Any]:
        policy_tools = _policy_tool_names(policy)
        with connect(self.db_path) as conn:
            servers = [redact_mcp_server(dict(r)) for r in conn.execute("SELECT * FROM mcp_servers ORDER BY name").fetchall()]
            tools = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT t.*, s.name AS server_name, s.config_path
                    FROM mcp_tools t
                    JOIN mcp_servers s ON s.id = t.server_id
                    ORDER BY s.name, t.tool_name
                    """
                ).fetchall()
            ]
        gaps: list[dict[str, Any]] = []
        for tool in tools:
            tool_name = str(tool.get("tool_name") or "")
            covered = any(
                tool_name.lower() == covered_name
                or tool_name.lower().startswith(covered_name.rstrip("*"))
                for covered_name in policy_tools
            )
            if not covered:
                gaps.append(
                    {
                        "server_name": tool.get("server_name"),
                        "tool_name": tool_name,
                        "config_path": tool.get("config_path"),
                        "description": tool.get("description"),
                    }
                )
        return {
            "servers": servers,
            "tools": tools,
            "gaps": gaps,
            "summary": {
                "server_count": len(servers),
                "tool_count": len(tools),
                "uncovered_tool_count": len(gaps),
            },
            **meta,
        }
