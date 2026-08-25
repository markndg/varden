#!/usr/bin/env python3
"""Safe local security verification runner for the runtime boundary."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEMOS = Path(__file__).resolve().parent

CHECKS = [
    ("mcp_causal_continuity", "mcp_cross_server_host.py", "blocked_cross_server"),
    ("direct_mcp_bypass_reported", "mcp_direct_bypass.py", "uncovered_reported"),
    ("strict_discovered_surface", "strict_readiness.py", "not_ready_without_exception"),
    ("workspace_persistence", "workspace_persistence_attack.py", "ci_config_blocked"),
    ("approval_race", "approval_race.py", "exactly_one_executes"),
    ("approval_scope", "approval_scope.py", "scope_and_replay"),
    ("interceptor_tamper", "interceptor_tamper.py", "coverage_downgraded"),
    ("saved_reference_limitation", "saved_reference_bypass.py", "bypass_reported"),
    ("raw_socket_uncovered", "raw_socket_bypass.py", "uncovered_reported"),
    ("control_plane_fail_closed", "control_plane_outage.py", "blocked"),
    ("strict_downgrade_locked", "strict_downgrade.py", "downgrade_rejected"),
    ("db_evidence_semantics", "db_evidence_failure.py", "explicit_statuses"),
]

_PASS_LINE = re.compile(r"^RESULT\s+PASS\s*$", re.MULTILINE)


def _passed(returncode: int, out: str) -> bool:
    # Require an explicit final verdict line. Intermediate lines like
    # "RESULT  BLOCKED" must not count as success.
    return returncode == 0 and bool(_PASS_LINE.search(out))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    results = []
    for name, script, expected in CHECKS:
        path = DEMOS / script
        proc = subprocess.run([sys.executable, str(path)], capture_output=True, text=True)
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = _passed(proc.returncode, out)
        results.append(
            {
                "name": name,
                "expected": expected,
                "result": "pass" if ok else "fail",
                "exit_code": proc.returncode,
                "output_tail": "\n".join(out.strip().splitlines()[-20:]),
            }
        )
        status = "PASS" if ok else "FAIL"
        print(f"{name:<34} {status}")
        if not ok and not args.json:
            print("---- output ----")
            print("\n".join(out.strip().splitlines()[-20:]))
            print("----------------")

    if args.json:
        print(json.dumps({"tests": results}, indent=2))
    failed = sum(1 for r in results if r["result"] != "pass")
    print("")
    print(f"{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
