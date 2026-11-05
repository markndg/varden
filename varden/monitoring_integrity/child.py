"""Child-process and argv classification for monitoring integrity.

Shell text that cannot be bound to concrete paths or process identities is
unobservable. It is not treated as safe.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from typing import Any

from varden.runtime.filesystem import resolve_filesystem_target

from .assets import AssetRegistry, MonitoringAsset, path_key

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"})
INTERPRETERS = frozenset({"python", "python3", "node", "ruby", "perl", "php"})
SERVICE_TOOLS = frozenset({
    "kill",
    "pkill",
    "killall",
    "taskkill",
    "systemctl",
    "launchctl",
    "service",
    "sc",
})
SHELL_META = set("|;&<>`$()\n")
CONSEQUENTIAL_SIGNALS = frozenset({15, 9, 19, 6, 3, 2})  # TERM KILL STOP ABRT QUIT INT


@dataclass
class ArgvIntent:
    argv: tuple[str, ...]
    executable: str
    observable: bool
    coverage: str
    reason: str
    path_tokens: tuple[str, ...] = ()
    service_tool: str | None = None
    service_targets: tuple[str, ...] = ()
    activations: tuple[str, ...] = ()
    unobservable_reason: str | None = None
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "executable": self.executable,
            "observable": self.observable,
            "coverage": self.coverage,
            "reason": self.reason,
            "path_tokens": list(self.path_tokens),
            "service_tool": self.service_tool,
            "service_targets": list(self.service_targets),
            "activations": list(self.activations),
            "unobservable_reason": self.unobservable_reason,
            "limitations": list(self.limitations),
        }


def _basename(token: str) -> str:
    return os.path.basename(token.rstrip("/")).lower()


def quoted_literals(text: str) -> list[str]:
    """Extract quoted string literals without evaluating the program."""
    found: list[str] = []
    index = 0
    while index < len(text):
        quote = text[index]
        if quote not in {"'", '"'}:
            index += 1
            continue
        index += 1
        start = index
        while index < len(text) and text[index] != quote:
            if text[index] == "\\" and quote == '"':
                index += 2
                continue
            index += 1
        literal = text[start:index]
        found.append(literal)
        found.extend(quoted_literals(literal))
        index += 1
    return found


def _flatten_argv(raw: Any) -> list[str] | None:
    if raw is None:
        return None
    if isinstance(raw, (str, bytes)):
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        return [text]
    if isinstance(raw, (list, tuple)):
        if len(raw) == 1 and isinstance(raw[0], (list, tuple)):
            return _flatten_argv(raw[0])
        out: list[str] = []
        for item in raw:
            if isinstance(item, (list, tuple)):
                nested = _flatten_argv(item)
                if nested is None:
                    return None
                # subprocess.call([argv]) is one argument that is a list.
                if out == [] and all(not isinstance(part, (list, tuple)) for part in item):
                    return [str(part) for part in item]
                out.extend(nested)
            else:
                out.append(str(item))
        return out
    return [str(raw)]


def extract_argv(action: dict[str, Any]) -> list[str] | None:
    metadata = action.get("metadata") or {}
    if isinstance(metadata, dict):
        subprocess_meta = metadata.get("subprocess") or {}
        if isinstance(subprocess_meta, dict) and isinstance(subprocess_meta.get("argv"), list):
            return [str(item) for item in subprocess_meta["argv"]]
    args = action.get("args") or {}
    if isinstance(args, dict):
        if "command" in args and isinstance(args["command"], str):
            return ["sh", "-c", args["command"]]
        nested = args.get("args")
        if nested is not None:
            flat = _flatten_argv(nested)
            if flat:
                return flat
        if isinstance(args.get("argv"), list):
            return [str(item) for item in args["argv"]]
    return None


def _coverage_for(*, mediated: bool, interpreter: bool, observable: bool) -> str:
    if not mediated:
        return "absent"
    if not observable:
        return "unknown"
    if interpreter:
        return "partial"
    return "partial"


def classify_argv(argv: list[str] | None, *, registry: AssetRegistry, mediated: bool) -> ArgvIntent:
    if not argv:
        return ArgvIntent(
            argv=(),
            executable="",
            observable=False,
            coverage="unknown" if mediated else "absent",
            reason="argv_missing",
            unobservable_reason="argv_missing",
            limitations=["The launch boundary did not supply a concrete argv."],
        )
    executable = argv[0]
    base = _basename(executable)
    tokens = list(argv)
    limitations = [
        "Mediation of the launch does not prove that descendants stay inside an enforcement boundary."
    ]
    if base in SHELLS and len(argv) >= 3 and argv[1] in {"-c", "/c"}:
        script = argv[2]
        if any(char in script for char in SHELL_META):
            literals = quoted_literals(script)
            rough_tokens = [part for part in script.split() if part]
            service_base = base
            for token in rough_tokens:
                if _basename(token) in SERVICE_TOOLS:
                    service_base = _basename(token)
                    break
            limitations.append(
                "Shell metacharacters make the command unobservable. Quoted path literals and service-tool tokens are still compared."
            )
            return _finish(
                argv,
                executable,
                False,
                "shell_metacharacters",
                tuple(literals),
                registry,
                mediated,
                service_base,
                limitations,
                service_from_tokens=rough_tokens,
            )
        try:
            tokens = shlex.split(script)
        except ValueError:
            return ArgvIntent(
                argv=tuple(argv),
                executable=executable,
                observable=False,
                coverage="unknown",
                reason="shell_parse_failed",
                unobservable_reason="shell_parse_failed",
                limitations=limitations,
            )
        base = _basename(tokens[0]) if tokens else base
        executable = tokens[0] if tokens else executable
    path_tokens = tuple(tokens[1:])
    return _finish(tokens or argv, executable, True, None, path_tokens, registry, mediated, base, limitations)


def _finish(
    argv: list[str],
    executable: str,
    observable: bool,
    unobservable: str | None,
    path_tokens: tuple[str, ...],
    registry: AssetRegistry,
    mediated: bool,
    base: str,
    limitations: list[str],
    service_from_tokens: list[str] | None = None,
) -> ArgvIntent:
    service_tool = base if base in SERVICE_TOOLS else None
    targets: list[str] = []
    scan = list(service_from_tokens or path_tokens)
    if service_tool:
        for token in scan:
            if token.startswith("-"):
                continue
            targets.append(token)
    activations: list[str] = []
    for asset in registry.assets():
        for activation in asset.activations:
            if _prefix_match(list(argv) if argv else [], activation.argv_prefix):
                activations.append(asset.id)
    interpreter = base in INTERPRETERS or base in SHELLS
    coverage = _coverage_for(mediated=mediated, interpreter=interpreter, observable=observable)
    if activations:
        reason = "activation_boundary"
    elif service_tool:
        reason = "service_control"
    elif interpreter and not observable:
        reason = "unobservable_interpreter"
    elif interpreter:
        reason = "interpreter_launch"
    else:
        reason = "exec"
    return ArgvIntent(
        argv=tuple(argv),
        executable=executable,
        observable=observable,
        coverage=coverage,
        reason=reason,
        path_tokens=path_tokens,
        service_tool=service_tool,
        service_targets=tuple(targets),
        activations=tuple(activations),
        unobservable_reason=unobservable,
        limitations=limitations,
    )


def _prefix_match(argv: list[str], prefix: tuple[str, ...]) -> bool:
    if len(argv) < len(prefix):
        return False
    for got, expected in zip(argv, prefix):
        if _basename(expected) in INTERPRETERS or _basename(expected) in SHELLS:
            if _basename(got) != _basename(expected):
                return False
            continue
        got_res = resolve_filesystem_target(got, operation="exec")
        exp_res = resolve_filesystem_target(expected, operation="exec")
        got_key = path_key(got_res.effective_path or got_res.absolute_lexical or got)
        exp_key = path_key(exp_res.effective_path or exp_res.absolute_lexical or expected)
        if got_key != exp_key and _basename(got) != _basename(expected):
            return False
    return True


def paths_from_intent(intent: ArgvIntent) -> list[str]:
    found: list[str] = []
    for token in list(intent.path_tokens) + quoted_literals(" ".join(intent.argv)):
        if not token or token.startswith("-"):
            continue
        if "/" in token or token.startswith(".") or os.path.isabs(token):
            found.append(token)
    return found


def asset_activated(intent: ArgvIntent, asset: MonitoringAsset) -> bool:
    return asset.id in intent.activations
