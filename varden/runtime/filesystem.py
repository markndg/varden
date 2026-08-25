"""Filesystem path classification for runtime boundary enforcement."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

_SECRET_PATTERNS = (
    re.compile(r"(^|/)\.ssh(/|$)", re.I),
    re.compile(r"(^|/)\.aws(/|$)", re.I),
    re.compile(r"(^|/)\.azure(/|$)", re.I),
    re.compile(r"(^|/)\.config/gcloud(/|$)", re.I),
    re.compile(r"(^|/)\.gnupg(/|$)", re.I),
    re.compile(r"(^|/)\.kube(/|$)", re.I),
    re.compile(r"(^|/)(\.env|\.env\.[^/]+)(/|$)", re.I),
    re.compile(r"(^|/)(id_rsa|id_ed25519|id_ecdsa)(\.pub)?$", re.I),
    re.compile(r"(^|/)(credentials|secrets?)(\.json|\.ya?ml|\.toml)?$", re.I),
    re.compile(r"(^|/)\.git-credentials$", re.I),
    re.compile(r"(^|/)(\.netrc|\.pgpass|\.npmrc)$", re.I),
    re.compile(r"(^|/)(Cookies|Login Data|Local State)$", re.I),
)

_CI_PATTERNS = (
    re.compile(r"(^|/)\.github/workflows/", re.I),
    re.compile(r"(^|/)\.gitlab-ci\.ya?ml$", re.I),
    re.compile(r"(^|/)Jenkinsfile$", re.I),
    re.compile(r"(^|/)\.circleci/", re.I),
    re.compile(r"(^|/)\.azure-pipelines", re.I),
)

_CONFIG_NAMES = {
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "cargo.toml",
    "cargo.lock",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "mcp.json",
    "requirements.txt",
    "requirements-dev.txt",
    "setup.cfg",
    "setup.py",
    "tsconfig.json",
    "vite.config.ts",
    "vite.config.js",
}

_CODE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".java",
    ".rb", ".php", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
}

_CODE_DIRS = ("src/", "lib/", "app/", "pkg/", "cmd/", "internal/")


def _expand(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.expanduser(os.path.expandvars(str(path))))


def canonicalize_path(path: str | os.PathLike[str], *, workspace: str | None = None) -> dict[str, Any]:
    raw = str(path)
    expanded = _expand(path)
    absolute = expanded if expanded.is_absolute() else (Path.cwd() / expanded)
    try:
        real = str(absolute.resolve(strict=False))
    except Exception:
        real = str(absolute)
    workspace_root = None
    if workspace:
        try:
            workspace_root = str(Path(workspace).resolve())
        except Exception:
            workspace_root = str(Path(workspace))
    return {
        "raw": raw,
        "expanded": str(expanded),
        "absolute": str(absolute),
        "real_path": real,
        "workspace": workspace_root,
        "is_relative": not expanded.is_absolute(),
    }


def classify_workspace_mutation(path: str | os.PathLike[str], *, workspace: str | None = None, mode: str = "r") -> dict[str, Any]:
    info = canonicalize_path(path, workspace=workspace)
    writing = any(c in str(mode or "r") for c in "wxa+")
    real = info.get("real_path") or info.get("absolute") or ""
    name = os.path.basename(real).lower()
    rel = real
    ws = info.get("workspace")
    if ws and real.startswith(ws + os.sep):
        rel = real[len(ws) + 1 :]
    rel_l = rel.replace("\\", "/").lower()

    mutation = "READ_WORKSPACE"
    authority = "READ_LOCAL"
    if writing:
        mutation = "WRITE_WORKSPACE"
        authority = "WRITE_WORKSPACE"
        for pat in _CI_PATTERNS:
            if pat.search("/" + rel_l) or pat.search(real):
                mutation = "WRITE_CI"
                authority = "WRITE_CI"
                break
        if mutation == "WRITE_WORKSPACE":
            if name in _CONFIG_NAMES or name.startswith("requirements") or name.endswith(".env") or name.startswith(".env"):
                mutation = "WRITE_CONFIG"
                authority = "WRITE_CONFIG"
            elif any(rel_l.startswith(d) for d in _CODE_DIRS) or Path(name).suffix.lower() in _CODE_EXTS:
                mutation = "WRITE_CODE"
                authority = "WRITE_CODE"
            elif name.endswith((".yml", ".yaml")) and any(tok in rel_l for tok in ("mcp", "agent", "policy", "compose")):
                mutation = "WRITE_CONFIG"
                authority = "WRITE_CONFIG"
    return {**info, "mutation": mutation, "authority": authority, "writing": writing}


def classify_path(path: str | os.PathLike[str], *, workspace: str | None = None, mode: str = "r") -> dict[str, Any]:
    info = canonicalize_path(path, workspace=workspace)
    candidates = [info["raw"], info["expanded"], info["absolute"], info["real_path"] or ""]
    home = str(Path.home())
    classification = "unknown"
    reasons: list[str] = []

    for c in candidates:
        if not c:
            continue
        for pat in _SECRET_PATTERNS:
            if pat.search(c):
                classification = "secrets"
                reasons.append(f"matched secret pattern on {c}")
                break
        if classification == "secrets":
            break

    if classification == "unknown":
        for c in candidates:
            cl = c.lower()
            if "/tmp/" in cl or cl.startswith("/tmp") or "/var/folders/" in cl:
                classification = "temporary"
                reasons.append("temporary path")
                break
            if cl.startswith("/etc/") or cl.startswith("/usr/") or cl.startswith("/bin/") or cl.startswith("/sbin/"):
                classification = "system"
                reasons.append("system path")
                break
            if home and (c == home or c.startswith(home + os.sep)):
                classification = "home"
                reasons.append("home directory path")
                break

    if classification in {"unknown", "home"} and info.get("workspace") and info.get("real_path"):
        ws = info["workspace"]
        real = info["real_path"]
        if real == ws or real.startswith(ws + os.sep):
            if classification != "secrets":
                classification = "workspace"
                reasons.append("inside workspace")

    mutation = classify_workspace_mutation(path, workspace=workspace, mode=mode)
    if classification == "workspace" and str(mutation.get("mutation") or "").startswith("WRITE_"):
        classification = str(mutation["mutation"]).lower()
        reasons.append(f"workspace mutation={mutation['mutation']}")

    sensitivity = {
        "secrets": "secret",
        "home": "private",
        "system": "system",
        "workspace": "workspace",
        "write_ci": "supply_chain",
        "write_config": "supply_chain",
        "write_code": "supply_chain",
        "write_workspace": "workspace",
        "temporary": "temporary",
        "unknown": "unknown",
    }.get(classification, "unknown")

    return {
        **info,
        "classification": classification,
        "sensitivity": sensitivity,
        "reasons": reasons,
        "mutation": mutation.get("mutation"),
        "required_authority": mutation.get("authority"),
        "writing": mutation.get("writing"),
    }
