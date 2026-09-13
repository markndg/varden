"""Clean-wheel packaging smoke tests (build → install → CLI/resources)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def clean_wheel_env(tmp_path_factory):
    """Build the wheel once and install it into a fresh venv (not editable)."""
    out = tmp_path_factory.mktemp("dist")
    build = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.skip(f"python -m build unavailable or failed: {build.stderr[-800:]}")
    wheels = sorted(out.glob("varden-*.whl"))
    assert wheels, f"no wheel produced:\n{build.stdout}\n{build.stderr}"
    wheel = wheels[-1]

    venv_dir = tmp_path_factory.mktemp("wheelvenv")
    venv.EnvBuilder(with_pip=True).create(venv_dir)
    if sys.platform == "win32":
        python = venv_dir / "Scripts" / "python.exe"
        varden_bin = venv_dir / "Scripts" / "varden.exe"
    else:
        python = venv_dir / "bin" / "python"
        varden_bin = venv_dir / "bin" / "varden"
    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--force-reinstall", str(wheel)],
        capture_output=True,
        text=True,
        cwd=str(venv_dir),
        env={**os.environ, "PYTHONPATH": ""},
    )
    assert install.returncode == 0, install.stderr
    return {"python": python, "varden": varden_bin, "wheel": wheel, "venv": venv_dir}


def _run(cmd, **kwargs):
    env = dict(kwargs.pop("env", None) or os.environ)
    # Prevent the repository checkout from shadowing the installed wheel.
    env["PYTHONPATH"] = ""
    kwargs.setdefault("cwd", str(Path.home()))
    return subprocess.run(cmd, capture_output=True, text=True, env=env, **kwargs)


def test_clean_wheel_cli_help_and_skill(clean_wheel_env, tmp_path):
    varden_bin = clean_wheel_env["varden"]
    help_p = _run([str(varden_bin), "--help"])
    assert help_p.returncode == 0
    assert "posture" in help_p.stdout.lower() or "usage" in help_p.stdout.lower()

    path_p = _run([str(varden_bin), "skill", "path"])
    assert path_p.returncode == 0
    skill_path = Path(path_p.stdout.strip().splitlines()[-1].strip())
    assert skill_path.exists()

    target = tmp_path / "skills"
    install = _run([str(varden_bin), "skill", "install", "--target", str(target)])
    assert install.returncode == 0
    assert any(target.rglob("SKILL.md"))


def test_clean_wheel_packaged_resources(clean_wheel_env):
    python = clean_wheel_env["python"]
    script = r"""
import json
from pathlib import Path
import varden

web = Path(varden.__file__).resolve().parent / "web" / "app"
assert (web / "index.html").is_file(), web
assert (web / "assets" / "app.js").is_file()
assert (web / "assets" / "app.css").is_file()

packs = Path(varden.__file__).resolve().parent / "policy-packs"
assert packs.is_dir() and list(packs.glob("*.json")), packs

ws = Path(varden.__file__).resolve().parent / "webshield" / "corpus"
assert ws.is_dir() and list(ws.glob("*.json")), ws

prov = Path(varden.__file__).resolve().parent / "provenance" / "corpus"
assert prov.is_dir() and list(prov.glob("*.json")), prov

skill = Path(varden.__file__).resolve().parent / "skills" / "varden-security"
assert (skill / "SKILL.md").is_file(), skill
print(json.dumps({"ok": True}))
"""
    proc = _run([str(python), "-c", script])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data["ok"] is True


def test_clean_wheel_posture_json(clean_wheel_env):
    varden_bin = clean_wheel_env["varden"]
    proc = _run([str(varden_bin), "posture", "--json"])
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "result" in data
    assert "STRICT MODE READINESS" not in proc.stdout
