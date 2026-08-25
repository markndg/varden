"""Local safe demo of provenance-aware authority-flow protection."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from ..cli import _bootstrap_policy, _post_json, _wait_for
from ..db import init_db
from ..policy_packs import load_policy_pack, merge_policy_pack
from ..fsutil import atomic_write_json


def _get_json(url: str, api_key: str = "admin-demo-key") -> dict:
    req = urllib.request.Request(url, headers={"x-api-key": api_key})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ensure_pack(policy_path: Path) -> str:
    current = json.loads(policy_path.read_text(encoding="utf-8")) if policy_path.exists() else {
        "block": [], "warn": [], "monitor": [], "allow": [], "require_approval": [], "sanitise": []
    }
    pack = load_policy_pack("provenance-authority-defense")
    if not pack:
        return "Provenance policy pack not found."
    merged = merge_policy_pack(current, pack, mode="merge")
    atomic_write_json(policy_path, merged["policy"])
    total = sum(merged["added"].values())
    return f"Merged provenance-authority-defense pack ({total} rules added)."


def _guard(base: str, payload: dict, api_key: str = "admin-demo-key") -> dict:
    """POST /sdk/guard. Block/require_approval (HTTP 403) is a successful demo outcome."""
    try:
        return _post_json(f"{base}/sdk/guard", payload, api_key=api_key)
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise
        raw = exc.read().decode("utf-8")
        body = json.loads(raw) if raw else {}
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, dict) and ("decision" in detail or "action" in detail):
            return detail
        if isinstance(body, dict) and "decision" in body:
            return body
        return {"decision": {"action": "block", "reason": raw or "forbidden"}, "action": {}}


def _fingerprint(base: str, server_id: str, tool_name: str, fingerprint: str, api_key: str = "admin-demo-key") -> None:
    _post_json(
        f"{base}/mcp/security/fingerprint",
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "fingerprint": fingerprint,
            "fields": {"demo": True},
        },
        api_key=api_key,
    )


def run_provenance_demo(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> int:
    _bootstrap_policy()
    policy_path = Path("policy.json")
    pack_msg = _ensure_pack(policy_path)
    print(pack_msg)

    env = os.environ.copy()
    env.setdefault("VARDEN_API_KEY", "admin-demo-key")
    base = f"http://{host}:{port}"
    env.setdefault("VARDEN_BASE_URL", base)
    demo_db = Path(".varden-provenance-demo.db")
    if demo_db.exists():
        demo_db.unlink()
    env["VARDEN_DB_PATH"] = str(demo_db)
    init_db(str(demo_db))

    cmd = [sys.executable, "-m", "uvicorn", "varden.api:app", "--host", host, "--port", str(port)]
    proc = subprocess.Popen(cmd, env=env)
    try:
        if not _wait_for(f"{base}/health"):
            print("Varden did not become healthy in time.", file=sys.stderr)
            return 1

        _fingerprint(base, "search.example", "search_web", "fp-search-v1")
        _fingerprint(base, "crm.internal", "customer_lookup", "fp-crm-v1")
        _fingerprint(base, "crm.internal", "admin_delete_user", "fp-crm-admin-v1")

        scenarios = []
        home = str(Path.home())
        workspace = "/tmp/varden-workspace"

        # 1) Flagship confused deputy — untrusted search MCP → privileged CRM delete → BLOCKED
        r1 = _guard(base, {
            "action": {
                "type": "mcp_call",
                "tool": "admin_delete_user",
                "agent_name": "demo-agent",
                "trace_id": "demo-confused-deputy",
                "metadata": {
                    "mcp_server": "crm.internal",
                    "mcp_privileged": True,
                    "description": "delete user admin",
                    "provenance_sources": [{
                        "source_id": "a",
                        "source_type": "mcp_tool_response",
                        "origin": "mcp://search.example/search_web",
                        "principal": "search.example",
                        "trust_level": "untrusted",
                    }],
                },
            },
            "payload": {"user_id": "u-123"},
        })
        scenarios.append(("1 confused deputy: untrusted search → CRM admin delete", r1.get("decision", {}).get("action"), "block"))

        # 2) Exfiltration — untrusted issue → secret → public HTTP → BLOCKED
        r2 = _guard(base, {
            "action": {
                "type": "http_request",
                "method": "POST",
                "url": "https://evil.example/upload",
                "agent_name": "demo-agent",
                "trace_id": "demo-exfil",
                "classifiers": {"secrets": True},
                "metadata": {
                    "lineage": {"sources": ["https://github.com/evil/issue/1"], "classifications": ["secrets"]},
                    "provenance_sources": [{
                        "source_id": "issue1",
                        "source_type": "email",
                        "origin": "https://github.com/evil/issue/1",
                        "trust_level": "untrusted",
                    }],
                    "_prior_taints": {"tags": ["secret", "credential", "external_input"]},
                },
            },
            "payload": {"note": "redacted"},
        })
        scenarios.append(("2 exfiltration: issue → secret → public HTTP", r2.get("decision", {}).get("action"), "block"))

        # 3) Private file — untrusted WebMCP/MCP → private notes → BLOCKED
        r3 = _guard(base, {
            "action": {
                "type": "file_read",
                "tool": "read_file",
                "args": {"path": f"{home}/Documents/notes.txt"},
                "agent_name": "demo-agent",
                "trace_id": "demo-private-file",
                "metadata": {
                    "mcp_server": "search.example",
                    "mcp_trust": "untrusted",
                    "is_tool_result": True,
                    "lineage": {"sources": ["mcp://search.example/search_web"]},
                    "provenance_sources": [{
                        "source_id": "mcp-search",
                        "source_type": "mcp_tool_response",
                        "origin": "mcp://search.example/search_web",
                        "principal": "search.example",
                        "trust_level": "untrusted",
                    }],
                },
            },
            "payload": {"path": f"{home}/Documents/notes.txt"},
        })
        scenarios.append(("3 private file: untrusted MCP → home documents", r3.get("decision", {}).get("action"), "block/require_approval"))

        # 4) Allowed workspace read
        r4 = _guard(base, {
            "action": {
                "type": "file_read",
                "tool": "read_file",
                "args": {"path": f"{workspace}/README.md"},
                "agent_name": "demo-agent",
                "trace_id": "demo-safe-workspace",
                "metadata": {
                    "workspace": workspace,
                },
            },
            "payload": {"path": f"{workspace}/README.md"},
        })
        scenarios.append(("4 allowed: workspace README under default delegation", r4.get("decision", {}).get("action"), "allow/monitor/warn"))

        # 5) Sanitised weather API — same-origin after typed sanitiser (not cross-origin warn theatre)
        r5 = _guard(base, {
            "action": {
                "type": "http_request",
                "method": "GET",
                "url": "https://api.weather.example/temp?code=21",
                "agent_name": "demo-agent",
                "trace_id": "demo-sanitised",
                "metadata": {
                    "sanitiser": "strict_integer_parser@1",
                    "provenance_sources": [{
                        "source_id": "api",
                        "source_type": "http_response",
                        "origin": "https://api.weather.example/feed",
                        "trust_level": "untrusted",
                    }],
                },
            },
            "payload": {"temp": 21},
        })
        scenarios.append(("5 sanitised: weather API integer parse → public GET", r5.get("decision", {}).get("action"), "allow/monitor"))

        print("\nProvenance authority-flow demo results:")
        for label, actual, expected in scenarios:
            print(f"  - {label}: decision={actual} (expected {expected})")

        # Assert classifier hygiene on the flagship CRM tool (no invented READ_SECRETS).
        auth = ((r1.get("action") or {}).get("metadata") or {}).get("authority") or {}
        required = auth.get("required") or []
        if "READ_SECRETS" in required:
            print("WARNING: admin_delete_user unexpectedly required READ_SECRETS:", required, file=sys.stderr)
        else:
            print(f"  classifier check: admin_delete_user required={required}")

        summary = _get_json(f"{base}/provenance/summary")
        incidents = _get_json(f"{base}/provenance/incidents?limit=20")
        print("\nIncident overview (not raw findings):")
        print(f"  incidents_total={summary.get('incidents_total')}  blocked={summary.get('blocked_incidents')}  "
              f"findings_on_incidents={summary.get('findings_on_incidents')}  store_findings={summary.get('findings_total')}")
        for item in (incidents.get("items") or [])[:8]:
            print(f"  - [{item.get('decision')}/{item.get('severity')}] {item.get('title')} "
                  f"({item.get('finding_count')} findings)")

        ui = f"{base}/ui/authority"
        print(f"\nDashboard: {ui}")
        print("Note: open Authority & Provenance (Overview → Incidents → Attack Paths → Authority Map).")
        print("  Web Shield stays empty until you run `varden web-shield demo` or connect the browser extension.")
        if open_browser:
            webbrowser.open(ui)
        print("Demo server running. Press Ctrl+C to stop.")
        proc.wait()
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
