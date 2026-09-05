"""Tests for the shipped Varden Agent Skill."""

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from varden.cli import main as varden_main
from varden.skills.cli import skill_directory

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG_SKILL = REPO_ROOT / "varden" / "skills" / "varden-security"
ROOT_SKILL = REPO_ROOT / "skills" / "varden-security"
REQUIRED_REFS = ("coverage.md", "mcp.md", "provenance.md", "troubleshooting.md")

TOP_LEVEL_COMMANDS = {
    "coverage",
    "posture",
    "runtime",
    "approvals",
    "mcp",
    "provenance",
    "authority",
    "web-shield",
    "skill",
    "session",
    "demo",
    "budget",
    "monitor",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _parse_frontmatter(text: str) -> dict[str, str]:
    assert text.startswith("---\n"), "SKILL.md must start with YAML frontmatter"
    end = text.find("\n---\n", 4)
    assert end != -1, "frontmatter not closed"
    block = text[4:end]
    meta: dict[str, str] = {}
    key = None
    buf: list[str] = []
    for line in block.splitlines():
        if re.match(r"^[a-zA-Z0-9_]+:\s*", line) and not line.startswith(" "):
            if key is not None:
                meta[key] = "\n".join(buf).strip().strip("\"'")
            key, _, rest = line.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest in {">", "|"}:
                buf = []
            else:
                buf = [rest.strip("\"'")] if rest else []
        else:
            buf.append(line.strip())
    if key is not None:
        meta[key] = "\n".join(buf).strip().strip("\"'")
    return meta


def test_skill_trees_exist_and_match():
    assert (PKG_SKILL / "SKILL.md").is_file()
    assert (ROOT_SKILL / "SKILL.md").is_file()
    pkg_files = {p.relative_to(PKG_SKILL): p.read_bytes() for p in PKG_SKILL.rglob("*") if p.is_file()}
    root_files = {p.relative_to(ROOT_SKILL): p.read_bytes() for p in ROOT_SKILL.rglob("*") if p.is_file()}
    assert pkg_files.keys() == root_files.keys()
    for key in pkg_files:
        assert pkg_files[key] == root_files[key], f"skill drift: {key}"


def test_skill_frontmatter_and_references():
    meta = _parse_frontmatter(_read(PKG_SKILL / "SKILL.md"))
    assert meta.get("name") == "varden-security"
    assert meta.get("description")
    body = _read(PKG_SKILL / "SKILL.md").lower()
    assert "not a security boundary" in body
    for name in REQUIRED_REFS:
        assert (PKG_SKILL / "references" / name).is_file()
    for match in re.finditer(r"\]\((references/[^)]+)\)", _read(PKG_SKILL / "SKILL.md")):
        assert (PKG_SKILL / match.group(1)).is_file(), match.group(1)


def test_security_invariants_phrasing():
    text = _read(PKG_SKILL / "SKILL.md").lower()
    assert "not a security boundary" in text
    assert "enforced" in text
    assert "partial" in text
    assert "not_routed" in text
    assert "uncovered" in text
    assert "never bypass" in text
    assert "approval" in text
    assert "manufacture" in text or "fake approval" in text
    assert "raw socket" in text
    assert "full protection" in text
    assert "varden posture" in text
    assert "varden determines posture" in text
    assert "do not upgrade" in text or "without upgrading" in text
    assert "do not invent a `protected`" in text or "do not invent a protected" in text


def test_skill_prefers_posture_json():
    text = _read(PKG_SKILL / "SKILL.md")
    assert "varden posture --json" in text
    # Must not tell agents to invent PROTECTED when posture is missing
    assert "Do not invent a `PROTECTED` result" in text or "Do not invent a PROTECTED result" in text
    cov = _read(PKG_SKILL / "references" / "coverage.md").lower()
    assert "attestation validity" in cov or "verification.attestation" in cov
    assert "applicable" in cov


def test_skill_path_and_install():
    assert varden_main(["skill", "path"]) == 0
    with TemporaryDirectory() as tmp:
        assert varden_main(["skill", "install", "--target", tmp]) == 0
        assert (Path(tmp) / "varden-security" / "SKILL.md").is_file()
        # refuse overwrite
        assert varden_main(["skill", "install", "--target", tmp]) == 1


def test_cli_help_includes_json_and_skill():
    for args in (
        ["coverage", "--help"],
        ["posture", "--help"],
        ["runtime", "readiness", "--help"],
        ["skill", "--help"],
    ):
        out = subprocess.run(
            [sys.executable, "-c", f"from varden.cli import main; raise SystemExit(main({args!r}))"],
            capture_output=True,
            text=True,
        )
        assert out.returncode == 0, out.stderr
        joined = out.stdout + out.stderr
        if args[0] in {"coverage", "posture", "runtime"}:
            assert "--json" in joined
        if args[0] == "skill":
            assert "path" in joined


def test_documented_top_level_commands_registered():
    """Extract `varden …` snippets from the skill and ensure top-level cmds exist."""
    skill = _read(PKG_SKILL / "SKILL.md")
    for ref in REQUIRED_REFS:
        skill += "\n" + _read(PKG_SKILL / "references" / ref)
    found = set()
    for match in re.finditer(r"(?m)^\s*(?:\$\s*)?varden\s+([a-z0-9-]+)", skill):
        found.add(match.group(1))
    assert found, "expected varden commands in skill docs"
    unknown = found - TOP_LEVEL_COMMANDS - {"--help"}
    # allow python -m lines separately
    unknown -= {c for c in unknown if c.startswith("-")}
    assert not unknown, f"skill documents unknown top-level commands: {sorted(unknown)}"


def test_skill_directory_resolves():
    path = skill_directory()
    assert (path / "SKILL.md").is_file()


def test_readme_links_skill():
    readme = _read(REPO_ROOT / "README.md")
    assert "skills/varden-security" in readme
    assert "Tell your agent to secure itself" in readme
    assert "varden skill path" in readme


def test_wheel_includes_skill(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", ".", "-w", str(dist), "--no-deps"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    wheels = list(dist.glob("varden-*.whl"))
    assert wheels, proc.stdout
    with zipfile.ZipFile(wheels[0]) as zf:
        names = zf.namelist()
    assert any(n.endswith("skills/varden-security/SKILL.md") for n in names), names[:40]
    assert any("skills/varden-security/references/coverage.md" in n for n in names)
