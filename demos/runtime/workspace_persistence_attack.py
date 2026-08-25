#!/usr/bin/env python3
"""Workspace persistence attacks under untrusted provenance (temp workspace only)."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import varden
from tests.runtime.helpers import make_app_client, wire_guard_to_app


def main() -> int:
    pack = json_pack()
    with TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir) / "workspace"
        (ws / "src").mkdir(parents=True)
        (ws / ".github" / "workflows").mkdir(parents=True)
        (ws / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
        (ws / "src" / "example.py").write_text("print('ok')\n", encoding="utf-8")

        client, app = make_app_client(tmpdir, policy=pack)
        key = client.get("/health").json()["bootstrap_api_key"]
        headers = {"x-api-key": key}
        guard = varden.protect(base_url="http://testserver", api_key=key, emit_attestation=False)
        wire_guard_to_app(guard, client)

        print("WORKSPACE PERSISTENCE ATTACK")
        # Attack A: untrusted → CI write
        with varden.provenance_scope(
            [{"source_type": "mcp_tool_result", "origin": "mcp://public-search/search", "trust_level": "untrusted"}]
        ):
            ci = ws / ".github" / "workflows" / "pwn.yml"
            try:
                with open(ci, "w", encoding="utf-8") as fh:
                    fh.write("name: pwn\n")
                print("Attack A WRITE_CI: ALLOWED (unexpected)")
                a_ok = False
            except varden.VardenBlockedError:
                print("Attack A WRITE_CI: BLOCKED")
                a_ok = not ci.exists()
                print(f"  file does not exist: {a_ok}")

        # Attack B: untrusted → config
        with varden.provenance_scope(
            [{"source_type": "web", "origin": "https://evil.example/readme", "trust_level": "untrusted"}]
        ):
            cfg = ws / "pyproject.toml"
            before = cfg.read_text(encoding="utf-8")
            try:
                with open(cfg, "w", encoding="utf-8") as fh:
                    fh.write("[project]\nname='pwned'\n")
                print("Attack B WRITE_CONFIG: ALLOWED (unexpected)")
                b_ok = False
            except varden.VardenBlockedError:
                print("Attack B WRITE_CONFIG: BLOCKED/APPROVAL")
                b_ok = cfg.read_text(encoding="utf-8") == before
                print(f"  file unchanged: {b_ok}")

        # Control: control-plane verified user delegation → code edit allowed
        trace = f"trusted-edit-{uuid.uuid4().hex[:8]}"
        dlg = client.post(
            "/authority/delegations",
            headers=headers,
            json={
                "capabilities": ["WRITE_CODE", "WRITE_WORKSPACE", "READ_LOCAL", "ADMIN"],
                "trace_scope": trace,
                "principal": "operator",
            },
        )
        assert dlg.status_code == 200, dlg.text
        code = ws / "src" / "example.py"
        try:
            with varden.trace_agent("operator", trace_id=trace), varden.provenance_scope([]):
                with open(code, "w", encoding="utf-8") as fh:
                    fh.write("print('trusted')\n")
            print("Control WRITE_CODE (verified user delegation): ALLOWED")
            c_ok = "trusted" in code.read_text(encoding="utf-8")
        except varden.VardenBlockedError as exc:
            print(f"Control WRITE_CODE: BLOCKED ({exc})")
            c_ok = False

        varden.unpatch_runtime()
        ok = a_ok and b_ok and c_ok
        print("RESULT", "PASS" if ok else "FAIL")
        return 0 if ok else 1


def json_pack():
    return {
        "block": [
            {
                "type": "filesystem",
                "field:metadata.filesystem.mutation": "WRITE_CI",
                "classifier:provenance_untrusted": True,
            }
        ],
        "require_approval": [
            {
                "type": "filesystem",
                "field:metadata.filesystem.mutation": "WRITE_CONFIG",
                "classifier:provenance_untrusted": True,
            },
            {
                "type": "filesystem",
                "field:metadata.filesystem.mutation": "WRITE_CODE",
                "classifier:provenance_untrusted": True,
            },
        ],
        "warn": [],
        "monitor": [],
        "allow": [],
    }


if __name__ == "__main__":
    raise SystemExit(main())
