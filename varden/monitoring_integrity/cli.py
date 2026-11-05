"""Local monitoring-integrity commands under ``varden runtime integrity``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load(path: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if "monitoring_integrity" in document:
        return document
    return {"monitoring_integrity": document}


def integrity_argv(args: argparse.Namespace) -> int:
    command = getattr(args, "integrity_command", None)
    as_json = bool(getattr(args, "json", False))
    if command == "status":
        from .service import posture

        policy = _load(args.policy) if getattr(args, "policy", None) else None
        body = posture(policy)
        if as_json or True:
            print(json.dumps(body, indent=2, sort_keys=True, default=str))
        return 0
    if command == "verify":
        from .watchdog import collect_observation, evaluate_observation

        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        verdict = evaluate_observation(collect_observation(manifest))
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0 if verdict["kind"] == "ok" else 1
    if command == "paths":
        from .analysis import analyse, counterfactual
        from .service import registry_for_section

        document = _load(args.policy)
        registry = registry_for_section(document["monitoring_integrity"])
        report = analyse(registry, max_depth=int(getattr(args, "max_depth", None) or 8))
        if getattr(args, "counterfactual", None):
            report = {
                "analysis": report,
                "counterfactual": counterfactual(
                    registry,
                    {"kind": args.counterfactual, "grant_id": getattr(args, "grant_id", None), "surface": getattr(args, "surface", None)},
                    max_depth=int(args.max_depth or 8),
                ),
            }
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 0 if not report.get("analysis_incomplete", report.get("analysis", {}).get("analysis_incomplete")) or report.get("hazard_found", report.get("analysis", {}).get("hazard_found")) else 0
    if command == "boundary":
        import tempfile

        from .gauntlet import run_gauntlet

        root = Path(tempfile.mkdtemp(prefix=".varden-mip-boundary-", dir=str(Path.home())))
        try:
            report = run_gauntlet(root)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
        print(json.dumps({key: report[key] for key in ("mechanism", "tier", "verified", "scope", "failed", "blocked_by_boundary", "positive", "performance", "protected_after")}, indent=2, sort_keys=True))
        return 0 if report["verified"] else 1
    if command == "demo":
        from .demo import run_multistep_demonstration

        result = run_multistep_demonstration()
        print(json.dumps(result, indent=2, sort_keys=True))
        prevented = result["with_mip"]["live_monitoring_disabled"] is False and result["without_mip"]["live_monitoring_disabled"] is True
        return 0 if prevented else 1
    print("usage: varden runtime integrity [status|verify|paths|boundary|demo]", file=sys.stderr)
    return 2


def add_integrity_parser(runtime_sub: argparse._SubParsersAction) -> None:
    integrity = runtime_sub.add_parser("integrity", help="Monitoring integrity protection")
    sub = integrity.add_subparsers(dest="integrity_command")
    status = sub.add_parser("status", help="Show sealed monitoring-integrity posture")
    status.add_argument("--policy", default=None, help="Policy JSON containing monitoring_integrity")
    status.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify", help="Run the out-of-process manifest check")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--json", action="store_true")
    paths = sub.add_parser("paths", help="Show hazardous monitoring paths and interruption points")
    paths.add_argument("--policy", required=True)
    paths.add_argument("--max-depth", default=8)
    paths.add_argument("--counterfactual", choices=["remove_permission", "constrain_tool", "surface_unavailable", "require_approval"])
    paths.add_argument("--grant-id", default=None)
    paths.add_argument("--surface", default=None)
    paths.add_argument("--json", action="store_true")
    boundary = sub.add_parser("boundary", help="Run the OS-boundary gauntlet in a disposable directory")
    boundary.add_argument("--json", action="store_true")
    demo = sub.add_parser("demo", help="Run the multi-step sabotage demonstration in a temporary directory")
    demo.add_argument("--json", action="store_true")
