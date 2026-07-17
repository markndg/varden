from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path


def _wait_for(url: str, timeout: float = 25.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def _post_json(url: str, payload: dict | None = None, api_key: str = 'admin-demo-key') -> dict:
    data = json.dumps(payload or {}).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST', headers={'content-type': 'application/json', 'x-api-key': api_key})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode('utf-8'))

def _bootstrap_policy(policy_path: Path = Path("policy.json")) -> None:
    if policy_path.exists():
        return
    # Try package resource first (PyPI install)
    try:
        import importlib.resources as pkg_resources
        resource = pkg_resources.files("varden").joinpath("policy-packs/baseline-operational-safety.json")
        data = json.loads(resource.read_text(encoding="utf-8"))
        policy_path.write_text(json.dumps(data["template"], indent=2) + "\n", encoding="utf-8")
        print(f"Bootstrapped {policy_path} from baseline policy pack.")
        return
    except Exception:
        pass
    # Fallback for source repo layout
    repo_pack = Path(__file__).parent.parent / "policy-packs" / "baseline-operational-safety.json"
    if repo_pack.exists():
        data = json.loads(repo_pack.read_text(encoding="utf-8"))
        policy_path.write_text(json.dumps(data["template"], indent=2) + "\n", encoding="utf-8")
        print(f"Bootstrapped {policy_path} from source policy pack.")
        return
    # Last resort: embed a minimal working policy
    minimal = {
        "block": [
            {"type": "tool_call", "tool": "delete_database"},
            {"type": "tool_call", "field:args.args": {"contains": "delete_database"}},
        ],
        "warn": [
            {"classifier:internal": True},
            {"classifier:secrets": True},
            {"classifier:pii": True},
        ],
        "monitor": [
            {"type": "http_request"},
        ],
        "allow": []
    }
    policy_path.write_text(json.dumps(minimal, indent=2) + "\n", encoding="utf-8")
    print(f"Bootstrapped {policy_path} from embedded baseline.")


def run_demo(host: str = '127.0.0.1', port: int = 8000, open_browser: bool = True) -> int:
    _bootstrap_policy()
    env = os.environ.copy()
    env.setdefault('VARDEN_API_KEY', env.get('VARDEN_API_KEY', 'admin-demo-key'))
    base_url = f'http://{host}:{port}'
    env.setdefault('VARDEN_BASE_URL', env.get('VARDEN_BASE_URL', base_url))
    cmd = [sys.executable, '-m', 'uvicorn', 'varden.api:app', '--host', host, '--port', str(port)]
    proc = subprocess.Popen(cmd, env=env)
    try:
        if not _wait_for(f'{base_url}/health/live', timeout=30.0):
            print('Varden demo failed to start in time.', file=sys.stderr)
            return 1
        seeded = _post_json(f'{base_url}/demo/run')
        if open_browser:
            try:
                webbrowser.open(f'{base_url}/ui', new=2)
            except Exception:
                pass
        print('Varden demo is live.')
        print(f'UI: {base_url}/ui')
        print('Scenarios seeded:', ', '.join(f"{item['name']}={item['status']}" for item in seeded.get('scenarios', [])))
        print('Press Ctrl+C to stop.')
        proc.wait()
        return int(proc.returncode or 0)
    except KeyboardInterrupt:
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _monitor_missing_exit() -> int:
    print(
        "varden monitor/session require the varden_monitor package (bundled with this repo).\n"
        "From the repository root install the platform in editable mode:\n"
        "  pip install -e .",
        file=sys.stderr,
    )
    return 2


def run_budget_status(db_path: str | None = None) -> int:
    from .token_budget import TokenBudgetStore
    import json
    from pathlib import Path

    path = db_path or os.getenv("VARDEN_DB_PATH", "varden.db")
    store = TokenBudgetStore(path)
    rows = store.list_active_budgets()
    policy_path = os.getenv("VARDEN_POLICY_FILE", "policy.json")
    hard_caps: dict[str, bool] = {}
    if Path(policy_path).exists():
        policy_doc = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        for rule in policy_doc.get("budget_rules") or []:
            hard_caps[str(rule.get("id") or "")] = bool(rule.get("hard_cap", True))
    if not rows:
        print("No active token budgets.")
        return 0
    print(f"{'policy_id':<24} {'window':<8} {'trace/workflow':<28} {'spent':>10} {'limit':>10} {'remain':>10} {'reset_at':<12} hard_cap")
    for row in rows:
        key = row.get("trace_id") or row.get("workflow_id") or "-"
        limit_usd = float(row.get("limit_usd") or 0)
        current_usd = float(row.get("current_usd") or 0)
        remain = max(0.0, limit_usd - current_usd)
        reset = "-" if row.get("reset_at") is None else time.strftime("%Y-%m-%d", time.gmtime(float(row["reset_at"])))
        policy_id = str(row.get("policy_id") or "")
        print(
            f"{policy_id:<24} {str(row.get('window')):<8} {str(key)[:28]:<28} "
            f"{current_usd:>10.4f} {limit_usd:>10.4f} {remain:>10.4f} {reset:<12} "
            f"{hard_caps.get(policy_id, True)}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='varden', description='Varden command-line tools')
    sub = parser.add_subparsers(dest='command')
    demo = sub.add_parser('demo', help='Run the demo stack and seed allow/warn/block traces')
    demo.add_argument('--host', default='127.0.0.1')
    demo.add_argument('--port', type=int, default=8000)
    demo.add_argument('--no-browser', action='store_true')
    budget = sub.add_parser('budget', help='Token budget commands')
    budget_sub = budget.add_subparsers(dest='budget_command')
    budget_status = budget_sub.add_parser('status', help='Show active token budget rows')
    budget_status.add_argument('--db-path', default=None)
    web_shield = sub.add_parser('web-shield', help='Varden Web Shield: WebMCP tool-surface security')
    ws_sub = web_shield.add_subparsers(dest='web_shield_command')
    ws_scan = ws_sub.add_parser('scan', help='Statically scan a WebMCP tool definition JSON file')
    ws_scan.add_argument('tool_file')
    ws_scan.add_argument('--human', action='store_true', help='Human-readable output instead of JSON')
    ws_explain = ws_sub.add_parser('explain', help='Explain the scan result for a WebMCP tool definition JSON file')
    ws_explain.add_argument('tool_file')
    ws_evaluate = ws_sub.add_parser('evaluate', help='Run the Web Shield evaluation corpus and report precision/recall/latency')
    ws_evaluate.add_argument('--corpus-version', default='v1')
    ws_evaluate.add_argument('--json', action='store_true', help='Machine-readable JSON output')
    ws_demo = ws_sub.add_parser('demo', help='Run the Web Shield attack-lab demo')
    ws_demo.add_argument('--host', default='127.0.0.1')
    ws_demo.add_argument('--port', type=int, default=8000)
    ws_demo.add_argument('--no-browser', action='store_true')
    ws_ext = ws_sub.add_parser('extension', help='Browser extension build/path helpers')
    ws_ext_sub = ws_ext.add_subparsers(dest='extension_command')
    ws_ext_build = ws_ext_sub.add_parser('build', help='Build a reproducible extension zip')
    ws_ext_build.add_argument('--out', default=None)
    ws_ext_sub.add_parser('path', help='Print the path to the unpacked development extension')
    ws_trust = ws_sub.add_parser('trust', help='Manage local per-origin Web Shield trust decisions')
    ws_trust_sub = ws_trust.add_subparsers(dest='trust_command')
    ws_trust_list = ws_trust_sub.add_parser('list', help='List local trust decisions')
    ws_trust_list.add_argument('--db-path', default=None)
    ws_trust_add = ws_trust_sub.add_parser('add', help='Trust an origin')
    ws_trust_add.add_argument('origin')
    ws_trust_add.add_argument('--db-path', default=None)
    ws_trust_remove = ws_trust_sub.add_parser('remove', help='Remove a trust decision for an origin')
    ws_trust_remove.add_argument('origin')
    ws_trust_remove.add_argument('--db-path', default=None)
    monitor = sub.add_parser('monitor', help='Run host commands through Varden Monitor (guard → exec → log)')
    monitor.add_argument('monitor_args', nargs=argparse.REMAINDER, help="run -- CMD | .  (dot = passive session)")
    session = sub.add_parser('session', help='Start a shell or command with PATH shims (railway, kubectl, …)')
    session.add_argument('session_args', nargs=argparse.REMAINDER, help='[--passive] [DIR] [-- CMD...]')
    args = parser.parse_args(argv)
    if args.command == 'demo':
        return run_demo(host=args.host, port=args.port, open_browser=not args.no_browser)
    if args.command == 'budget' and args.budget_command == 'status':
        return run_budget_status(db_path=getattr(args, 'db_path', None))
    if args.command == 'web-shield':
        from .webshield.cli import webshield_argv
        return webshield_argv(args)
    if args.command == 'monitor':
        try:
            from varden_monitor.cli import monitor_argv
        except ModuleNotFoundError:
            return _monitor_missing_exit()

        ma = getattr(args, 'monitor_args', None) or []
        return monitor_argv(ma)
    if args.command == 'session':
        try:
            from varden_monitor.session import session_argv
        except ModuleNotFoundError:
            return _monitor_missing_exit()

        sa = getattr(args, 'session_args', None) or []
        return session_argv(sa)
    parser.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
