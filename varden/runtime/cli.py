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


def _print_readiness_human(data: dict[str, Any]) -> None:
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


_FAIL_VERDICTS = frozenset({
    "tamper",
    "unknown",
    "error",
    "not_invoked",
    "unexpected_bypass",
    "fail",
})


def _probe_result(
    *,
    surface: str,
    probe_executed: bool,
    interceptor_invoked: bool,
    guard_invoked: bool,
    decision: str,
    verification: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "surface": surface,
        "probe_executed": probe_executed,
        "interceptor_invoked": interceptor_invoked,
        "guard_invoked": guard_invoked,
        "decision": decision,
        "verification": verification,
        "reason": reason,
    }


def _execute_self_test(*, base_url: str | None = None, api_key: str | None = None) -> tuple[int, dict[str, Any]]:
    """Internal: return (exit_code, payload) without printing."""
    import varden
    from varden.runtime.coverage import ENFORCED, PARTIAL, get_coverage_registry
    from varden.runtime.modes import is_enforcing

    probes: list[dict[str, Any]] = []
    guard = varden.protect(
        base_url=base_url or os.environ.get("VARDEN_BASE_URL", "http://127.0.0.1:8000"),
        api_key=api_key or os.environ.get("VARDEN_API_KEY"),
        mode="guarded",
        auto_instrument=True,
        emit_attestation=False,
    )

    guard_calls: list[dict[str, Any]] = []
    original_guarded = guard.guarded_action

    def _spy_guarded_action(*args: Any, **kwargs: Any):
        meta = {
            "type": kwargs.get("type"),
            "tool": kwargs.get("tool"),
            "url": kwargs.get("url"),
        }
        if meta["type"] is None and args:
            meta["type"] = args[0]
        guard_calls.append({k: (str(v) if v is not None else None) for k, v in meta.items()})
        return original_guarded(*args, **kwargs)

    guard.guarded_action = _spy_guarded_action  # type: ignore[method-assign]

    try:
        reg = get_coverage_registry()
        verify = reg.verify()
        if verify.get("ok"):
            probes.append(
                _probe_result(
                    surface="coverage.verify",
                    probe_executed=True,
                    interceptor_invoked=True,
                    guard_invoked=False,
                    decision="ok",
                    verification="pass",
                    reason="Interceptor live-checks reported no tamper",
                )
            )
        else:
            probes.append(
                _probe_result(
                    surface="coverage.verify",
                    probe_executed=True,
                    interceptor_invoked=False,
                    guard_invoked=False,
                    decision="tamper",
                    verification="tamper",
                    reason=f"Interceptor tamper detected: {verify.get('changes')}",
                )
            )

        before_http = len(guard_calls)
        http_decision = "error"
        http_exc: BaseException | None = None
        try:
            # Prefer stdlib urllib — patched at protect() time without importing
            # optional clients. requests may not be present until first import.
            import urllib.request

            urllib.request.urlopen("http://127.0.0.1:9/", timeout=0.2)
            http_decision = "allowed_completed"
        except varden.VardenBlockedError:
            http_decision = "blocked"
        except Exception as exc:
            http_exc = exc
            http_decision = "network_error_after_guard"
        http_calls = guard_calls[before_http:]
        http_guard = any(str(c.get("type") or "").lower() in {"http_request", "http"} for c in http_calls)
        http_surf = reg.get("http.urllib") or reg.get("http.httpx") or reg.get("http.requests")
        interceptor_on = bool(http_surf and http_surf.active and http_surf.status == ENFORCED)
        http_surface_name = http_surf.name if http_surf else "http.urllib"
        if http_guard and interceptor_on:
            probes.append(
                _probe_result(
                    surface=http_surface_name,
                    probe_executed=True,
                    interceptor_invoked=True,
                    guard_invoked=True,
                    decision=http_decision,
                    verification="pass",
                    reason=(
                        "Pre-execution guard invoked for local HTTP probe"
                        + (f" ({type(http_exc).__name__})" if http_exc else "")
                    ),
                )
            )
        elif not interceptor_on:
            probes.append(
                _probe_result(
                    surface=http_surface_name,
                    probe_executed=True,
                    interceptor_invoked=False,
                    guard_invoked=http_guard,
                    decision=http_decision,
                    verification="not_invoked",
                    reason="HTTP interceptor not active/ENFORCED after protect()",
                )
            )
        else:
            probes.append(
                _probe_result(
                    surface=http_surface_name,
                    probe_executed=True,
                    interceptor_invoked=True,
                    guard_invoked=False,
                    decision=http_decision,
                    verification="not_invoked",
                    reason="HTTP probe completed without traversing guarded_action",
                )
            )

        before_sub = len(guard_calls)
        sub_decision = "error"
        try:
            import subprocess

            subprocess.run([sys.executable, "-c", "pass"], check=False, capture_output=True)
            sub_decision = "allowed_completed"
        except varden.VardenBlockedError:
            sub_decision = "blocked"
        except Exception as exc:
            sub_decision = f"error:{type(exc).__name__}"
        sub_calls = guard_calls[before_sub:]
        sub_surf = reg.get("subprocess")
        sub_active = bool(sub_surf and sub_surf.active and sub_surf.status == ENFORCED)
        sub_guard = any(
            "subprocess" in str(c.get("type") or "").lower()
            or "subprocess" in str(c.get("tool") or "").lower()
            for c in sub_calls
        )
        if not sub_guard and sub_active and sub_calls:
            sub_guard = True
        if sub_guard and sub_active:
            probes.append(
                _probe_result(
                    surface="subprocess",
                    probe_executed=True,
                    interceptor_invoked=True,
                    guard_invoked=True,
                    decision=sub_decision,
                    verification="pass",
                    reason="Subprocess interceptor invoked guarded_action for local interpreter probe",
                )
            )
        elif not sub_active:
            probes.append(
                _probe_result(
                    surface="subprocess",
                    probe_executed=True,
                    interceptor_invoked=False,
                    guard_invoked=sub_guard,
                    decision=sub_decision,
                    verification="not_invoked",
                    reason="Subprocess interceptor not active/ENFORCED after protect()",
                )
            )
        else:
            probes.append(
                _probe_result(
                    surface="subprocess",
                    probe_executed=True,
                    interceptor_invoked=True,
                    guard_invoked=False,
                    decision=sub_decision,
                    verification="not_invoked",
                    reason="Subprocess probe completed without traversing guarded_action",
                )
            )

        before_fs = len(guard_calls)
        fs_decision = "error"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "varden-self-test.txt"
                # builtins.open is the patched entrypoint (pathlib may not always wrap).
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("varden-self-test")
            fs_decision = "allowed_completed"
        except varden.VardenBlockedError:
            fs_decision = "blocked"
        except Exception as exc:
            fs_decision = f"error:{type(exc).__name__}"
        fs_calls = guard_calls[before_fs:]
        fs_guard = any(
            str(c.get("type") or "").lower() in {"filesystem", "file_write", "file_read", "file"}
            or "open" in str(c.get("tool") or "").lower()
            or "pathlib" in str(c.get("tool") or "").lower()
            for c in fs_calls
        )
        if not fs_guard and fs_calls:
            fs_guard = True
        fs_surf = reg.get("filesystem")
        fs_status = fs_surf.status if fs_surf else "unknown"
        fs_active = bool(fs_surf and fs_surf.active)
        if fs_decision.startswith("error:"):
            verification = "error"
            reason = f"Filesystem probe failed: {fs_decision}"
        elif not fs_active:
            verification = "not_invoked"
            reason = "Filesystem interceptor not active after protect()"
        elif fs_status == ENFORCED and fs_guard:
            verification = "pass"
            reason = "Filesystem interceptor ENFORCED and guard invoked"
        elif fs_status == PARTIAL and fs_guard:
            verification = "partial"
            reason = "Filesystem coverage is PARTIAL (Python APIs only); not claimed as ENFORCED"
        elif fs_status == PARTIAL and fs_active and not fs_guard:
            verification = "partial"
            reason = (
                "Filesystem coverage is PARTIAL; interceptor active but this write path "
                "did not traverse guarded_action (honest non-ENFORCED)"
            )
        elif fs_active and not fs_guard:
            verification = "unknown"
            reason = "Filesystem marked active but probe did not traverse guarded_action"
        else:
            verification = "unknown"
            reason = f"Filesystem status={fs_status}"
        probes.append(
            _probe_result(
                surface="filesystem",
                probe_executed=True,
                interceptor_invoked=fs_active,
                guard_invoked=fs_guard,
                decision=fs_decision,
                verification=verification,
                reason=reason,
            )
        )

        mode_ok = is_enforcing(guard.product_mode)
        probes.append(
            _probe_result(
                surface="mode",
                probe_executed=True,
                interceptor_invoked=True,
                guard_invoked=False,
                decision=str(guard.product_mode),
                verification="pass" if mode_ok else "fail",
                reason="Mode is enforcing" if mode_ok else "Mode is not enforcing",
            )
        )
    finally:
        try:
            guard.guarded_action = original_guarded  # type: ignore[method-assign]
        except Exception:
            pass
        varden.unpatch_runtime()

    failed = [p for p in probes if str(p.get("verification") or "").lower() in _FAIL_VERDICTS]
    payload = {
        "ok": not failed,
        "probes": probes,
        "failed": [p["surface"] for p in failed],
    }
    return (0 if payload["ok"] else 1), payload


def run_self_test(*, base_url: str | None = None, api_key: str | None = None, as_json: bool = False) -> int:
    """Harmless local checks that interceptors traverse the pre-execution guard."""
    code, payload = _execute_self_test(base_url=base_url, api_key=api_key)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return code
    print("Varden runtime self-test")
    print("")
    for probe in payload["probes"]:
        ver = str(probe.get("verification") or "")
        if ver in _FAIL_VERDICTS:
            mark = "FAIL"
        elif ver == "partial":
            mark = "PARTIAL"
        else:
            mark = "PASS"
        print(f"{probe['surface']:<28} {mark:<8} {ver} — {probe['reason']}")
    print("")
    print("Overall:", "PASS" if payload["ok"] else "FAIL")
    return code


def runtime_argv(args: argparse.Namespace) -> int:
    cmd = getattr(args, "runtime_command", None)
    as_json = bool(getattr(args, "json", False))
    if cmd == "status":
        data = _api("GET", "/runtime/status")
        print(json.dumps(data, indent=2))
        return 0
    if cmd == "readiness":
        data = _api("GET", "/runtime/readiness")
        if as_json:
            # Machine-readable: exactly one JSON document on stdout.
            print(json.dumps(data, indent=2, sort_keys=True))
        else:
            _print_readiness_human(data)
        return 0
    if cmd == "explain":
        event_id = args.event_id
        data = _api("GET", f"/events/{event_id}")
        print(json.dumps(data, indent=2))
        return 0
    if cmd == "self-test":
        return run_self_test(as_json=as_json)
    print("usage: varden runtime [status|readiness|explain|self-test]", file=sys.stderr)
    return 2


def coverage_argv(args: argparse.Namespace) -> int:
    data = _api("GET", "/runtime/coverage")
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
    else:
        print_coverage(data)
    return 0


def _local_runtime_active() -> bool:
    from varden.runtime.coverage import get_coverage_registry

    reg = get_coverage_registry()
    att = reg.attestation()
    if att.get("mode_locked"):
        return True
    return any(s.get("active") for s in (att.get("surfaces") or []))


def posture_argv(args: argparse.Namespace) -> int:
    """Side-effect-free posture attestation (observes; does not repair)."""
    from varden.runtime.coverage import get_coverage_registry
    from varden.runtime.posture import evaluate_posture

    as_json = bool(getattr(args, "json", False))
    attestation: dict[str, Any] | None = None
    attestation_valid = True
    source = "local"

    if _local_runtime_active():
        report = evaluate_posture(get_coverage_registry(), self_test="not_run")
    else:
        try:
            data = _api("GET", "/runtime/coverage")
            live = data.get("live") or {}
            if live.get("surfaces") is not None or live.get("categories") is not None:
                attestation = live
                source = "control_plane"
            else:
                attestation_valid = False
                attestation = get_coverage_registry().attestation()
                source = "local_inactive"
        except Exception:
            # Control plane unreachable — report local (usually inactive) state.
            attestation = get_coverage_registry().attestation()
            # Local inactive registry is still a valid determination of "not protected".
            attestation_valid = True
            source = "local_inactive"
        report = evaluate_posture(
            attestation=attestation,
            attestation_valid=attestation_valid,
            self_test="not_run",
        )

    if as_json:
        payload = report.to_dict()
        payload["source"] = source
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        text = report.format_human()
        # Keep human output free of ANSI; optional source note for agents/CI.
        if source == "control_plane":
            text = text.rstrip() + "\n\nSource: control-plane live coverage registry\n"
        elif source == "local_inactive":
            text = text.rstrip() + "\n\nSource: local process registry (runtime not active in this process)\n"
        print(text, end="" if text.endswith("\n") else "\n")
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
        # Decorative copy on stderr so stdout can stay machine-readable when
        # writing the wrapped document to stdout.
        print("MCP config wrap changes:", file=sys.stderr)
        for change in changes:
            print(json.dumps(change, indent=2), file=sys.stderr)
        if out_path:
            out_path.write_text(json.dumps(wrapped, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {out_path}", file=sys.stderr)
        else:
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
