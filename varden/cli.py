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


def run_demo(host: str = '127.0.0.1', port: int = 8000, open_browser: bool = True) -> int:
    env = os.environ.copy()
    env.setdefault('VARDEN_API_KEY', env.get('VARDEN_API_KEY', 'admin-demo-key'))
    env.setdefault('VARDEN_API_KEY', env.get('VARDEN_API_KEY', 'admin-demo-key'))
    base_url = f'http://{host}:{port}'
    env.setdefault('VARDEN_BASE_URL', env.get('VARDEN_BASE_URL', base_url))
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='varden', description='Varden OSS command line tools')
    sub = parser.add_subparsers(dest='command')
    demo = sub.add_parser('demo', help='Run the OSS demo stack and seed allow/warn/block traces')
    demo.add_argument('--host', default='127.0.0.1')
    demo.add_argument('--port', type=int, default=8000)
    demo.add_argument('--no-browser', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'demo':
        return run_demo(host=args.host, port=args.port, open_browser=not args.no_browser)
    parser.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
