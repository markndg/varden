"""CLI helpers for runtime coverage, approvals, MCP wrap, and self-test."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


def _api(method: str, path: str, *, payload: dict | None = None, api_key: str | None = None, base_url: str | None = None) -> Any:
    base = (base_url or os.environ.get("VARDEN_BASE_URL") or "http://127.0.0.1:8000").rstrip("/")
    key = api_key or os.environ.get("VARDEN_API_KEY") or "admin-demo-key"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers={"content-type": "application/json", "x-api-key": key},
    )
    with urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def print_coverage(data: dict[str, Any]) -> None:
    live = data.get("live") or data
    print("PROTECTION COVERAGE")
    print("")
    for row in live.get("categories") or []:
        print(f"{row.get('label', row.get('category')):<16} {row.get('status')}")
    print("")
    ready = (live.get("strict_readiness") or {})
    print("STRICT MODE READINESS")
    print(ready.get("status") or "UNKNOWN")
    missing = ready.get("required_coverage_missing") or []
    if missing:
        print("")
        print("Required coverage missing:")
        for item in missing:
            print(f"- {item}")
    bypass = live.get("known_bypass_surfaces") or []
    if bypass:
        print("")
        print("Known bypass / uncovered surfaces:")
        for s in bypass:
            print(f"- {s.get('name')}: {s.get('status')}")


def run_self_test(*, base_url: str | None = None, api_key: str | None = None) -> int:
    """Harmless local checks that interceptors are active after protect()."""
    import varden
    from varden.runtime.coverage import get_coverage_registry
    from varden.runtime.modes import is_enforcing

    results: list[tuple[str, str]] = []
    guard = varden.protect(
        base_url=base_url or os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000"),
        api_key=api_key or os.environ.get("VARDEN_API_KEY"),
        mode="guarded",
        auto_instrument=True,
        emit_attestation=False,
    )
    try:
        reg = get_coverage_registry()
        verify = reg.verify()
        results.append(("Coverage verify", "ok" if verify.get("ok") else f"tamper:{verify.get('changes')}"))
        att = reg.attestation()
        for cat in att.get("categories") or []:
            results.append((str(cat["label"]), str(cat["status"])))

        # HTTP intercept probe — control-plane URL is excluded; use example.invalid
        intercepted = False
        try:
            import requests

            requests.get("http://127.0.0.1:9/", timeout=0.2)
        except varden.VardenBlockedError:
            intercepted = True
            results.append(("HTTP block path", "enforced"))
        except Exception:
            # Connection errors mean request was attempted — check if guard ran via coverage
            http_surf = reg.get("http.requests")
            if http_surf and http_surf.active:
                results.append(("HTTP interceptor", "active"))
            else:
                results.append(("HTTP interceptor", "unknown"))
        if intercepted:
            pass

        # Subprocess intercept
        try:
            import subprocess

            subprocess.run(["/usr/bin/true"], check=False, capture_output=True)
            sub = reg.get("subprocess")
            results.append(("Subprocess interceptor", "active" if sub and sub.active else "unknown"))
        except varden.VardenBlockedError:
            results.append(("Subprocess interceptor", "enforced"))
        except Exception as exc:
            results.append(("Subprocess interceptor", f"error:{exc}"))

        # Filesystem intercept
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=True) as fh:
                fh.write("varden-self-test")
            fs = reg.get("filesystem")
            results.append(("Filesystem interceptor", "active" if fs and fs.active else "partial/unknown"))
        except varden.VardenBlockedError:
            results.append(("Filesystem interceptor", "enforced"))
        except Exception as exc:
            results.append(("Filesystem interceptor", f"error:{exc}"))

        results.append(("Mode enforcing", "yes" if is_enforcing(guard.product_mode) else "no"))
    finally:
        varden.unpatch_runtime()

    print("Varden runtime self-test")
    print("")
    for name, status in results:
        print(f"{name:<28} {status}")
    return 0


def runtime_argv(args: argparse.Namespace) -> int:
    cmd = getattr(args, "runtime_command", None)
    if cmd == "status":
        data = _api("GET", "/runtime/status")
        print(json.dumps(data, indent=2))
        return 0
    if cmd == "readiness":
        data = _api("GET", "/runtime/readiness")
        print("STRICT MODE READINESS:", data.get("status") or "UNKNOWN")
        print("")
        blocking = data.get("discovered_blocking") or []
        if blocking:
            print("Discovered relevant surfaces:")
            for item in blocking:
                print(f"\n{item.get('surface')}")
                print(f"  state: {item.get('state')}")
                print(f"  reason: {item.get('reason')}")
        missing = data.get("required_coverage_missing") or []
        if missing:
            print("Required coverage missing:")
            for item in missing:
                print(f"- {item}")
        accepted = data.get("accepted_exceptions") or []
        if accepted:
            print("")
            print("Accepted exceptions:")
            for item in accepted:
                print(f"- {item}")
        if getattr(args, "json", False):
            print(json.dumps(data, indent=2))
        return 0
    if cmd == "explain":
        event_id = args.event_id
        data = _api("GET", f"/events/{event_id}")
        print(json.dumps(data, indent=2))
        return 0
    if cmd == "self-test":
        return run_self_test()
    print("usage: varden runtime [status|readiness|explain|self-test]", file=sys.stderr)
    return 2


def coverage_argv(args: argparse.Namespace) -> int:
    data = _api("GET", "/runtime/coverage")
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
    else:
        print_coverage(data)
    return 0


def approvals_argv(args: argparse.Namespace) -> int:
    cmd = getattr(args, "approvals_command", None)
    if cmd == "pending":
        data = _api("GET", "/approvals/pending")
        if getattr(args, "json", False):
            print(json.dumps(data, indent=2))
        else:
            items = data.get("items") or []
            if not items:
                print("No pending approvals.")
                return 0
            for item in items:
                print(f"{item.get('approval_id')}  {item.get('tool') or item.get('action_type')}  {item.get('reason')}")
        return 0
    if cmd == "approve":
        data = _api("POST", f"/approvals/{args.approval_id}/approve")
        print(json.dumps(data, indent=2))
        return 0
    if cmd == "deny":
        data = _api("POST", f"/approvals/{args.approval_id}/deny")
        print(json.dumps(data, indent=2))
        return 0
    print("usage: varden approvals [pending|approve|deny]", file=sys.stderr)
    return 2


def mcp_argv(args: argparse.Namespace) -> int:
    from .mcp_gateway import load_mcp_config, wrap_mcp_config

    cmd = getattr(args, "mcp_command", None)
    if cmd == "wrap" or cmd == "patch-config":
        src = Path(args.config)
        cfg = load_mcp_config(src)
        wrapped, changes = wrap_mcp_config(cfg)
        out_path = Path(args.output) if getattr(args, "output", None) else None
        print("MCP config wrap changes:")
        for change in changes:
            print(json.dumps(change, indent=2))
        if out_path:
            out_path.write_text(json.dumps(wrapped, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {out_path}")
        else:
            print("")
            print(json.dumps(wrapped, indent=2))
        return 0
    if cmd == "gateway":
        # Launch note: gateway is typically invoked per-server via wrapped config.
        print(
            "Use `varden mcp wrap <config> --output <out>` then point your MCP host at the wrapped config.\n"
            "Per-server gateway process: python -m varden.runtime.mcp_gateway --server-id NAME --downstream-json '...'",
            file=sys.stderr,
        )
        return 0
    print("usage: varden mcp [wrap|patch-config|gateway]", file=sys.stderr)
    return 2
