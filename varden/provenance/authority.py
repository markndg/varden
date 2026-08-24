"""Deterministic authority classification for intercepted actions.

Maps action type / tool / destination / path onto required Authority classes.
No LLM involvement — every mapping is inspectable and deterministic.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import AUTHORITY_CLASSES, AuthorityRequirement

# Path categories → required authority.
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(^|[\\/])\.ssh([\\/]|$)", re.I), "ssh", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.aws([\\/]|$)", re.I), "aws", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.azure([\\/]|$)", re.I), "azure", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.config[\\/]gcloud([\\/]|$)", re.I), "gcloud", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.kube([\\/]|$)", re.I), "kube", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.git-credentials$", re.I), "git_credentials", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.netrc$", re.I), "git_credentials", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.env(\.|$)", re.I), "environment/secrets", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])id_rsa|id_ed25519|id_ecdsa", re.I), "ssh", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.gnupg([\\/]|$)", re.I), "ssh", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])(Cookies|Login Data|Local State)$", re.I), "browser_profiles", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.docker[\\/]config\.json$", re.I), "environment/secrets", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.npmrc$", re.I), "environment/secrets", "READ_SECRETS"),
    (re.compile(r"(^|[\\/])\.pypirc$", re.I), "environment/secrets", "READ_SECRETS"),
]

_SHELL_INTERPRETERS = {
    "sh", "bash", "zsh", "fish", "dash", "ksh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "csh", "tcsh",
}

# Language runtimes that accept inline code evaluation — treat like shells.
_SCRIPT_EVAL_RUNTIMES = {
    "python", "python2", "python3", "pypy", "pypy3",
    "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "lua", "osascript", "tclsh", "wish",
}

_INLINE_EVAL_FLAGS = {
    "-c", "/c", "-Command", "-EncodedCommand",
    "-e", "-r", "--eval", "-p",
}

_PRIVILEGED_CLIS = {
    "aws", "gcloud", "az", "kubectl", "helm", "terraform", "pulumi",
    "docker", "podman", "ssh", "scp", "rsync", "sudo", "doas",
    "mysql", "psql", "mongo", "redis-cli",
}

_DESTRUCTIVE_TOKENS = {"rm", "del", "rmdir", "format", "mkfs", "dd", "shred", "wipe"}

_NETWORK_CLIENTS = {"curl", "wget", "http", "httpie", "nc", "ncat", "fetch"}

_PACKAGE_MANAGERS = {"npm", "pip", "pip3", "yarn", "pnpm", "cargo", "go", "gem", "composer", "apt", "brew"}

_ENV_WRAPPERS = {"env", "nice", "nohup", "stdbuf", "timeout", "time", "ionice"}


def _home_dir() -> Path:
    try:
        return Path.home().resolve()
    except Exception:
        return Path(os.path.expanduser("~"))


def classify_filesystem_path(path: str | None, *, cwd: str | None = None, workspace: str | None = None) -> tuple[str, str]:
    """Return (category, authority) for a filesystem path.

    Resolves ``~``, relative paths and (best-effort) symlinks. Never relies
    solely on substring matching when canonicalisation is possible.
    """
    if not path:
        return "unknown", "READ_LOCAL"

    raw = str(path)
    expanded = os.path.expanduser(raw)
    try:
        base = Path(cwd).resolve() if cwd else Path.cwd()
    except Exception:
        base = Path(".")
    try:
        candidate = Path(expanded)
        resolved = (base / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        text = str(resolved)
    except Exception:
        text = os.path.normpath(expanded)

    for pattern, category, authority in _SENSITIVE_PATH_PATTERNS:
        if pattern.search(text) or pattern.search(raw):
            return category, authority

    home = str(_home_dir())
    if text.startswith(home + os.sep) or text == home:
        # Inside home but not a known secret path.
        if workspace:
            try:
                ws = str(Path(workspace).resolve())
                if text.startswith(ws + os.sep) or text == ws:
                    return "workspace", "READ_LOCAL"
            except Exception:
                pass
        return "user_home", "READ_PRIVATE"

    # System paths
    system_prefixes = ("/etc", "/usr", "/bin", "/sbin", "/System", "C:\\Windows", "C:\\Program Files")
    if any(text.startswith(p) for p in system_prefixes):
        return "system", "READ_PRIVATE"

    if workspace:
        try:
            ws = str(Path(workspace).resolve())
            if text.startswith(ws + os.sep) or text == ws:
                return "workspace", "READ_LOCAL"
        except Exception:
            pass

    # Temporary
    tmp_markers = ("/tmp", "/var/tmp", "\\Temp\\", "/private/var/folders")
    if any(m in text for m in tmp_markers):
        return "temporary", "READ_LOCAL"

    return "unknown", "READ_PRIVATE"


def classify_http(url: str | None, *, method: str | None = None, has_credentials: bool = False) -> AuthorityRequirement:
    required: set[str] = set()
    resource = url or ""
    method_u = (method or "GET").upper()
    try:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
    except Exception:
        host, scheme = "", ""

    internal_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    is_internal = (
        host in internal_hosts
        or host.endswith(".internal")
        or host.endswith(".local")
        or host.endswith(".corp")
        or (host.startswith("10.") or host.startswith("192.168.") or host.startswith("172."))
    )

    if has_credentials or "@" in (url or ""):
        required.add("NETWORK_CREDENTIALLED")
    elif is_internal:
        required.add("NETWORK_INTERNAL")
    else:
        required.add("NETWORK_PUBLIC")

    if method_u in {"POST", "PUT", "PATCH", "DELETE"}:
        if is_internal:
            required.add("WRITE_DATABASE")
        else:
            required.add("WRITE_CLOUD")
    if method_u == "DELETE":
        required.add("DELETE")

    if scheme in {"javascript", "data", "file"}:
        required.add("EXECUTE_LOCAL")

    return AuthorityRequirement(
        required=required,
        resource=resource,
        reason=f"HTTP {method_u} to {host or 'unknown'}",
        action_class="http",
    )


def classify_subprocess(executable: str | None, argv: list[Any] | None = None, *, cwd: str | None = None) -> AuthorityRequirement:
    argv = list(argv or [])
    exe = str(executable or (argv[0] if argv else "") or "")
    base = os.path.basename(exe).lower()
    # Unwrap env/nice/nohup so `env bash -c` / `env python -c` classify as the real interpreter.
    effective_argv = list(argv) if argv else ([exe] if exe else [])
    if base in _ENV_WRAPPERS and len(effective_argv) >= 2:
        # Skip VAR=val assignments after env.
        idx = 1
        while idx < len(effective_argv) and "=" in str(effective_argv[idx]) and not str(effective_argv[idx]).startswith("-"):
            idx += 1
        if idx < len(effective_argv):
            exe = str(effective_argv[idx])
            base = os.path.basename(exe).lower()
            effective_argv = effective_argv[idx:]

    required: set[str] = {"EXECUTE_LOCAL"}
    reason_bits = [f"subprocess {base or 'unknown'}"]

    has_inline_eval = any(str(a) in _INLINE_EVAL_FLAGS for a in effective_argv)
    if (
        base in _SHELL_INTERPRETERS
        or base in _SCRIPT_EVAL_RUNTIMES
        or has_inline_eval
    ):
        required.add("EXECUTE_PRIVILEGED")
        reason_bits.append("shell/script interpreter" if base in _SHELL_INTERPRETERS or base in _SCRIPT_EVAL_RUNTIMES else "inline eval flag")

    if base in _PRIVILEGED_CLIS or base in _PACKAGE_MANAGERS:
        required.add("EXECUTE_PRIVILEGED")
        if base in {"aws", "gcloud", "az", "kubectl"}:
            required.add("WRITE_CLOUD")
            required.add("IDENTITY_USE")
        reason_bits.append("privileged CLI")

    if base in _NETWORK_CLIENTS:
        required.add("NETWORK_PUBLIC")
        reason_bits.append("network client")

    # Nested interpreter after an unknown wrapper → raise uncertainty to privileged.
    nested = {os.path.basename(str(a)).lower() for a in effective_argv[1:]}
    if nested & (_SHELL_INTERPRETERS | _SCRIPT_EVAL_RUNTIMES | _PRIVILEGED_CLIS):
        required.add("EXECUTE_PRIVILEGED")
        reason_bits.append("nested interpreter/cli")

    tokens = {str(a).lower() for a in effective_argv}
    if tokens & _DESTRUCTIVE_TOKENS or base in _DESTRUCTIVE_TOKENS:
        required.add("DELETE")
        reason_bits.append("destructive")

    # Detect credential-path arguments.
    for arg in effective_argv:
        cat, auth = classify_filesystem_path(str(arg), cwd=cwd)
        if auth == "READ_SECRETS":
            required.add("READ_SECRETS")
            reason_bits.append(f"touches {cat}")

    # Unknown executable with no recognised safe profile → increase uncertainty.
    known = (
        _SHELL_INTERPRETERS | _SCRIPT_EVAL_RUNTIMES | _PRIVILEGED_CLIS
        | _NETWORK_CLIENTS | _PACKAGE_MANAGERS | _ENV_WRAPPERS
        | {"ls", "cat", "head", "tail", "echo", "true", "false", "pwd", "whoami", "date", "uname"}
    )
    if base and base not in known and "EXECUTE_PRIVILEGED" not in required:
        required.add("EXECUTE_PRIVILEGED")
        reason_bits.append("unknown executable — elevated uncertainty")

    return AuthorityRequirement(
        required={r for r in required if r in AUTHORITY_CLASSES},
        resource=exe,
        reason="; ".join(reason_bits),
        action_class="subprocess",
    )


def classify_mcp_tool(
    tool: str | None,
    *,
    server: str | None = None,
    description: str | None = None,
    privileged_hint: bool = False,
) -> AuthorityRequirement:
    required: set[str] = set()
    name = (tool or "").lower()
    desc = (description or "").lower()
    blob = f"{name} {desc}"

    secret_tokens = ("secret", "credential", "password", "token", "api_key", "ssh", "aws", "private key")
    write_tokens = ("write", "create", "update", "delete", "drop", "insert", "mutate", "push")
    shell_tokens = ("shell", "exec", "subprocess", "bash", "command")
    payment_tokens = ("payment", "checkout", "wallet", "transfer funds")
    admin_tokens = ("admin", "iam", "role", "privilege")

    if any(t in blob for t in secret_tokens) or privileged_hint:
        required.add("READ_SECRETS")
        required.add("MCP_PRIVILEGED")
    if any(t in blob for t in write_tokens):
        required.add("WRITE_DATABASE")
        required.add("MCP_PRIVILEGED")
    if any(t in blob for t in shell_tokens):
        required.add("EXECUTE_PRIVILEGED")
        required.add("MCP_PRIVILEGED")
    if any(t in blob for t in payment_tokens):
        required.add("PAYMENT")
        required.add("MCP_PRIVILEGED")
    if any(t in blob for t in admin_tokens):
        required.add("ADMIN")
        required.add("MCP_PRIVILEGED")
    if not required:
        required.add("MCP_UNPRIVILEGED")

    return AuthorityRequirement(
        required=required,
        resource=f"mcp://{server or 'unknown'}/{tool or 'unknown'}",
        reason=f"MCP tool {tool or 'unknown'} on {server or 'unknown'}",
        action_class="mcp",
    )


def classify_action(action: dict[str, Any] | Any) -> AuthorityRequirement:
    """Map a Varden Action (dict or dataclass) onto required authorities."""
    if hasattr(action, "to_dict"):
        data = action.to_dict()
    else:
        data = dict(action or {})

    action_type = str(data.get("type") or "")
    tool = data.get("tool")
    method = data.get("method")
    url = data.get("url")
    args = data.get("args") or {}
    metadata = data.get("metadata") or {}

    if action_type in {"http_request", "http_call"} or url:
        has_creds = bool(
            (metadata.get("headers") or {}).get("Authorization")
            or (metadata.get("headers") or {}).get("authorization")
            or metadata.get("has_credentials")
        )
        return classify_http(url, method=method, has_credentials=has_creds)

    if action_type in {"subprocess", "shell", "command"}:
        argv = args.get("argv") or args.get("args") or []
        if isinstance(argv, str):
            argv = [argv]
        executable = tool or (argv[0] if argv else None)
        return classify_subprocess(executable, list(argv), cwd=metadata.get("cwd"))

    # SDK patches send type=tool_call for Popen/run — route to subprocess classifier.
    if action_type == "tool_call" and (
        metadata.get("execution_surface") == "subprocess"
        or str(tool or "").startswith("subprocess.")
    ):
        argv = args.get("argv") or args.get("args") or []
        if isinstance(argv, str):
            argv = [argv]
        executable = (argv[0] if argv else None) or tool
        return classify_subprocess(executable, list(argv), cwd=metadata.get("cwd"))

    if action_type in {"file_read", "file_write", "filesystem"}:
        path = args.get("path") or args.get("file") or tool
        category, auth = classify_filesystem_path(path, cwd=metadata.get("cwd"), workspace=metadata.get("workspace"))
        required = {auth}
        if action_type == "file_write" or method in {"write", "append", "delete"}:
            if auth == "READ_SECRETS":
                required.add("WRITE_LOCAL")
                required.add("DELETE" if method == "delete" else "WRITE_LOCAL")
            else:
                required.add("WRITE_LOCAL")
            if method == "delete":
                required.add("DELETE")
        return AuthorityRequirement(
            required=required,
            resource=str(path or ""),
            reason=f"filesystem {action_type} ({category})",
            action_class="filesystem",
        )

    if action_type.startswith("webmcp") or metadata.get("webmcp"):
        req = classify_mcp_tool(tool, server=metadata.get("owner_origin") or metadata.get("origin"), description=str(metadata.get("description") or ""))
        req.action_class = "webmcp"
        return req

    if action_type in {"mcp_call", "tool_call"} and (metadata.get("mcp_server") or str(tool or "").startswith("mcp:")):
        server = metadata.get("mcp_server") or metadata.get("server")
        return classify_mcp_tool(
            tool,
            server=server,
            description=str(metadata.get("description") or metadata.get("tool_description") or ""),
            privileged_hint=bool(metadata.get("mcp_privileged")),
        )

    if action_type == "llm_call":
        return AuthorityRequirement(required={"NONE"}, reason="llm call", action_class="llm")

    if action_type == "tool_call":
        # Generic tool — classify from name heuristics.
        return classify_mcp_tool(tool, server=metadata.get("server"), description=str(metadata.get("description") or ""))

    return AuthorityRequirement(required={"NONE"}, reason="unclassified", action_class="unknown")
