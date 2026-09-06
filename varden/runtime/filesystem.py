"""Filesystem path classification and containment for runtime boundary enforcement.

Security decisions use the strongest safely established *effective* target.
The caller-supplied path is preserved for audit and explanation.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

ResolutionStatus = Literal["resolution_success", "resolution_partial", "resolution_failed"]

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

_MAX_SYMLINK_DEPTH = 32


@dataclass
class CanonicalTarget:
    """Internal representation of a filesystem target for policy decisions."""

    supplied_path: str
    absolute_lexical: str
    effective_path: str | None
    parent_effective: str | None
    workspace_root: str | None
    exists: bool | None
    symlink_involved: bool
    operation: str
    resolution: ResolutionStatus
    resolution_error: str | None = None
    inside_workspace: bool | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _expand(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.expanduser(os.path.expandvars(str(path))))


def is_path_contained(candidate: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """Return True iff candidate is root or a descendant (path-component aware).

    Never use naïve string-prefix checks: ``/workspace-safe`` is not inside
    ``/workspace``.
    """
    try:
        cand = Path(os.fspath(candidate))
        base = Path(os.fspath(root))
        cand_parts = cand.parts
        base_parts = base.parts
        if len(cand_parts) < len(base_parts):
            return False
        return cand_parts[: len(base_parts)] == base_parts
    except Exception:
        return False


def _lexically_absolute(path: str | os.PathLike[str], *, cwd: Path | None = None) -> Path:
    expanded = _expand(path)
    if expanded.is_absolute():
        return Path(os.path.normpath(str(expanded)))
    base = cwd or Path.cwd()
    return Path(os.path.normpath(str(base / expanded)))


def _symlink_in_chain(path: Path, *, stop_at: Path | None = None) -> bool:
    """True if path or an ancestor at/below stop_at is a symlink.

    Limiting the walk to the workspace (when known) avoids false positives from
    platform prefix links such as macOS ``/var`` → ``/private/var``.
    """
    cur = path
    stop = None
    if stop_at is not None:
        try:
            stop = Path(os.path.realpath(str(stop_at)))
        except Exception:
            stop = Path(os.path.normpath(str(stop_at)))
    for _ in range(_MAX_SYMLINK_DEPTH):
        try:
            if cur.exists() and cur.is_symlink():
                return True
        except OSError:
            return False
        parent = cur.parent
        if parent == cur:
            break
        if stop is not None:
            # Stop once we leave the workspace tree (do not inspect OS prefix links).
            try:
                if cur == stop or not is_path_contained(cur, stop):
                    # Still check `cur` itself above; next iteration would leave workspace.
                    if cur == stop:
                        break
                    if not is_path_contained(parent, stop) and parent != stop:
                        break
            except Exception:
                break
        cur = parent
    return False


def resolve_filesystem_target(
    path: str | os.PathLike[str],
    *,
    workspace: str | None = None,
    operation: str = "open",
    cwd: str | os.PathLike[str] | None = None,
) -> CanonicalTarget:
    """Resolve the effective filesystem target for policy decisions.

    For non-existent create/write targets, resolve the nearest existing parent
    and append the remaining lexical components — never treat unresolved
    ``Path.resolve(strict=False)`` as proof of containment.
    """
    supplied = str(path)
    notes: list[str] = []
    cwd_path = Path(cwd) if cwd is not None else Path.cwd()
    try:
        lexical = _lexically_absolute(path, cwd=cwd_path)
    except Exception as exc:
        return CanonicalTarget(
            supplied_path=supplied,
            absolute_lexical=supplied,
            effective_path=None,
            parent_effective=None,
            workspace_root=None,
            exists=None,
            symlink_involved=False,
            operation=operation,
            resolution="resolution_failed",
            resolution_error=f"lexical_failed:{exc}",
            notes=["failed to compute absolute lexical path"],
        )

    workspace_root: str | None = None
    if workspace:
        try:
            workspace_root = str(Path(workspace).resolve())
        except Exception:
            workspace_root = str(_lexically_absolute(workspace))

    symlink_involved = False
    exists: bool | None = None
    effective: str | None = None
    parent_effective: str | None = None
    resolution: ResolutionStatus = "resolution_partial"
    resolution_error: str | None = None

    try:
        exists = lexical.exists()
    except OSError as exc:
        exists = None
        resolution = "resolution_failed"
        resolution_error = f"exists_check_failed:{exc}"
        notes.append("could not determine existence")

    stop = Path(workspace_root) if workspace_root else None

    if exists is True:
        try:
            real = Path(os.path.realpath(str(lexical)))
            if lexical.is_symlink() or _symlink_in_chain(lexical, stop_at=stop):
                symlink_involved = True
                notes.append("symlink involved in resolution")
            effective = str(real)
            parent_effective = str(real.parent)
            resolution = "resolution_success"
        except Exception as exc:
            resolution = "resolution_failed"
            resolution_error = f"realpath_failed:{exc}"
            notes.append("existing path could not be fully resolved")
    elif exists is False:
        remainder: list[str] = []
        cur = lexical
        found_parent: Path | None = None
        try:
            for _ in range(len(lexical.parts) + 2):
                try:
                    if cur.exists():
                        found_parent = cur
                        break
                except OSError:
                    break
                if cur.parent == cur:
                    break
                remainder.insert(0, cur.name)
                cur = cur.parent
            if found_parent is None:
                resolution = "resolution_failed"
                resolution_error = "no_existing_ancestor"
                notes.append("no existing ancestor for non-existent target")
            else:
                try:
                    parent_real = Path(os.path.realpath(str(found_parent)))
                    if found_parent.is_symlink() or _symlink_in_chain(found_parent, stop_at=stop):
                        symlink_involved = True
                        notes.append("symlink involved in parent resolution")
                    parent_effective = str(parent_real)
                    effective_path = parent_real.joinpath(*remainder) if remainder else parent_real
                    effective = str(Path(os.path.normpath(str(effective_path))))
                    if remainder:
                        resolution = "resolution_partial"
                        notes.append("target does not exist; containment via resolved parent")
                    else:
                        resolution = "resolution_success"
                except Exception as exc:
                    resolution = "resolution_failed"
                    resolution_error = f"parent_resolve_failed:{exc}"
                    notes.append("nearest parent could not be resolved")
        except OSError as exc:
            resolution = "resolution_failed"
            resolution_error = f"ancestor_walk_failed:{exc}"

    inside: bool | None = None
    if workspace_root and effective:
        inside = is_path_contained(effective, workspace_root)

    return CanonicalTarget(
        supplied_path=supplied,
        absolute_lexical=str(lexical),
        effective_path=effective,
        parent_effective=parent_effective,
        workspace_root=workspace_root,
        exists=exists,
        symlink_involved=symlink_involved,
        operation=operation,
        resolution=resolution,
        resolution_error=resolution_error,
        inside_workspace=inside,
        notes=notes,
    )


def canonicalize_path(path: str | os.PathLike[str], *, workspace: str | None = None) -> dict[str, Any]:
    """Backwards-compatible path dict, now backed by CanonicalTarget."""
    target = resolve_filesystem_target(path, workspace=workspace, operation="canonicalize")
    return {
        "raw": target.supplied_path,
        "expanded": str(_expand(path)),
        "absolute": target.absolute_lexical,
        "real_path": target.effective_path or target.absolute_lexical,
        "workspace": target.workspace_root,
        "is_relative": not _expand(path).is_absolute(),
        "canonical_target": target.to_dict(),
        "resolution": target.resolution,
        "symlink_involved": target.symlink_involved,
        "exists": target.exists,
        "parent_effective": target.parent_effective,
    }


def classify_workspace_mutation(
    path: str | os.PathLike[str], *, workspace: str | None = None, mode: str = "r"
) -> dict[str, Any]:
    info = canonicalize_path(path, workspace=workspace)
    writing = any(c in str(mode or "r") for c in "wxa+")
    real = info.get("real_path") or info.get("absolute") or ""
    name = os.path.basename(real).lower()
    rel = real
    ws = info.get("workspace")
    if ws and real and is_path_contained(real, ws):
        try:
            rel = str(Path(real).relative_to(ws))
        except Exception:
            if real.startswith(ws + os.sep):
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
    target = info.get("canonical_target") or {}
    candidates = [
        info["raw"],
        info["expanded"],
        info["absolute"],
        info.get("real_path") or "",
        target.get("effective_path") or "",
        target.get("parent_effective") or "",
    ]
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
            if home and (c == home or is_path_contained(c, home)):
                classification = "home"
                reasons.append("home directory path")
                break

    if classification in {"unknown", "home"} and info.get("workspace") and info.get("real_path"):
        ws = info["workspace"]
        real = info["real_path"]
        if is_path_contained(real, ws):
            if classification != "secrets":
                classification = "workspace"
                reasons.append("inside workspace (effective target)")
        elif target.get("symlink_involved"):
            reasons.append("effective target outside workspace via symlink or traversal")

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
        "resolution": info.get("resolution"),
        "symlink_involved": info.get("symlink_involved"),
    }


def resolution_blocks_under_fail_closed(info: dict[str, Any]) -> bool:
    """True when ambiguous resolution must not silently ALLOW under fail-closed."""
    status = str(info.get("resolution") or "")
    if status == "resolution_failed":
        return True
    if status == "resolution_partial" and not info.get("real_path"):
        return True
    return False
