"""CLI helpers for the shipped Varden Agent Skill."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


SKILL_NAME = "varden-security"


def skill_directory() -> Path:
    """Return the filesystem path to the packaged (or editable) skill root.

    Resolution order:
    1. ``varden/skills/varden-security`` next to this module (wheel / editable)
    2. Repository root ``skills/varden-security`` when developing from a checkout
    """
    packaged = Path(__file__).resolve().parent / SKILL_NAME
    if (packaged / "SKILL.md").is_file():
        return packaged
    # Editable / source tree: varden/skills/../../skills/varden-security
    repo_skill = Path(__file__).resolve().parents[2] / "skills" / SKILL_NAME
    if (repo_skill / "SKILL.md").is_file():
        return repo_skill
    raise FileNotFoundError(
        f"Varden skill {SKILL_NAME!r} not found. Reinstall the varden package "
        "or run from a full source checkout."
    )


def skill_path_argv(_args: argparse.Namespace) -> int:
    try:
        path = skill_directory()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(path)
    return 0


def skill_install_argv(args: argparse.Namespace) -> int:
    try:
        src = skill_directory()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    target_root = Path(args.target).expanduser().resolve()
    dest = target_root / SKILL_NAME
    if dest.exists():
        print(
            f"Refusing to overwrite existing directory: {dest}\n"
            "Remove it or choose another --target.",
            file=sys.stderr,
        )
        return 1
    target_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest)
    print(f"Installed Varden skill to {dest}")
    print("The skill configures Varden; it is not itself a security boundary.")
    return 0


def skill_argv(args: argparse.Namespace) -> int:
    cmd = getattr(args, "skill_command", None)
    if cmd == "path":
        return skill_path_argv(args)
    if cmd == "install":
        return skill_install_argv(args)
    print("usage: varden skill [path|install]", file=sys.stderr)
    return 2
