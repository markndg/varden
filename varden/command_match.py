"""Argv-aware command matching for policy rules.

Substring rules such as ``{"field:args.argv_join": {"contains": "rm -rf"}}`` are
trivially bypassed (``rm -fr``, ``rm -r -f``, ``rm  -rf``, ``/bin/rm -rf``,
``sudo rm -rf``, ``bash -c 'rm -rf /'``). The ``command`` predicate parses the
command the way a shell would and matches on structure instead:

.. code-block:: json

    {"type": "tool_call", "command": {"program": "rm", "flags_all": [["r", "R", "recursive"]]}}

Supported keys (at least one is required; every key given must match):

``program``
    Program name or list of alternatives. Compared on the basename,
    case-insensitively, with ``.exe`` stripped, after unwrapping ``sudo``,
    ``env``, ``nohup``, ``timeout``, ``xargs`` and similar wrappers.
``subcommand``
    A word sequence (``"destroy"``, ``"db reset"``) or list of alternative
    sequences. Matches when the words appear consecutively among the
    positional (non-flag) arguments.
``flags_all``
    List of flag groups; every group must be present. A group is a flag name
    or a list of alternative names (``["r", "R", "recursive"]``). Single-letter
    names are short flags (case-sensitive, combined forms like ``-rf`` are
    expanded); longer names are long flags (``--force``, ``--force=true``).
``flags_any``
    List of flag names; at least one must be present.
``arg_contains``
    Substring or list of substrings; matches when any argument contains one
    (case-insensitive). Useful for sensitive paths (``.env``, ``id_rsa``).

Shell strings are split on ``;``, ``&&``, ``||``, ``|``, ``&`` and newlines,
command substitutions (``$(...)`` and backticks) are parsed as commands too,
and ``sh -c``/``bash -c``/``eval`` payloads are parsed recursively. A rule
matches when any command in the chain matches.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Any, Iterable

COMMAND_SPEC_KEYS = frozenset({"program", "subcommand", "flags_all", "flags_any", "arg_contains"})

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox-sh"})
_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "|&", "\n", ";;"})
_MAX_DEPTH = 5

# Wrapper programs whose real payload is a later argument. Value maps to the
# set of flags that consume a following value.
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D", "-R", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}),
    "nohup": frozenset(),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "--class", "--classdata"}),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": frozenset({"-a"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "chrt": frozenset(),
    "taskset": frozenset(),
    "setsid": frozenset(),
    "unbuffer": frozenset(),
    "xargs": frozenset({"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter",
                        "--max-args", "--max-procs", "--replace"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "watch": frozenset({"-n", "-d", "--interval"}),
}
# Wrappers that take a positional argument before the real command.
_WRAPPER_POSITIONALS = {"timeout": 1, "taskset": 1, "chrt": 1}
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def program_name(token: str) -> str:
    base = re.split(r"[\\/]", str(token))[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _shell_tokens(script: str) -> list[str]:
    lex = shlex.shlex(script.replace("\r", "\n"), posix=True, punctuation_chars=";&|")
    lex.whitespace = " \t"
    lex.whitespace_split = True
    lex.commenters = ""
    tokens: list[str] = []
    for tok in lex:
        tokens.append(tok)
    return tokens


def _substitutions(script: str) -> list[str]:
    """Contents of $(...) and `...` (best effort, handles nesting for $())."""
    found: list[str] = []
    found.extend(m.group(1) for m in re.finditer(r"`([^`]*)`", script))
    i = 0
    while True:
        start = script.find("$(", i)
        if start < 0:
            break
        depth, j = 1, start + 2
        while j < len(script) and depth:
            if script.startswith("$(", j):
                depth += 1
                j += 2
                continue
            if script[j] == "(":
                depth += 1
            elif script[j] == ")":
                depth -= 1
            j += 1
        found.append(script[start + 2: j - 1 if depth == 0 else j])
        i = start + 2
    return [f for f in found if f.strip()]


def split_shell(script: str, depth: int = 0) -> list[list[str]]:
    """Parse a shell string into a list of argv lists."""
    if depth > _MAX_DEPTH or not script or not script.strip():
        return []
    commands: list[list[str]] = []
    try:
        tokens = _shell_tokens(script)
    except ValueError:
        # Unbalanced quotes: fall back to whitespace/operator splitting so a
        # malformed string can't hide a command from matching.
        tokens = re.findall(r"&&|\|\||[;&|\n]|[^\s;&|]+", script)
    current: list[str] = []
    for tok in tokens:
        if tok in _SEPARATORS or (tok and set(tok) <= set(";&|")):
            if current:
                commands.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        commands.append(current)
    out: list[list[str]] = []
    for argv in commands:
        out.extend(unwrap(argv, depth))
    for sub in _substitutions(script):
        out.extend(split_shell(sub, depth + 1))
    return out


def unwrap(argv: list[str], depth: int = 0) -> list[list[str]]:
    """Strip env assignments and wrappers; recurse into ``sh -c`` payloads."""
    if depth > _MAX_DEPTH:
        return []
    argv = [str(a) for a in argv if a is not None and str(a) != ""]
    # Leading redirections / subshell punctuation left by the lexer.
    while argv and argv[0] in {"(", ")", "{", "}", "!"}:
        argv = argv[1:]
    while argv and _ENV_ASSIGN.match(argv[0]):
        argv = argv[1:]
    if not argv:
        return []
    prog = program_name(argv[0])
    if prog in _WRAPPERS:
        value_flags = _WRAPPERS[prog]
        i = 1
        while i < len(argv):
            tok = argv[i]
            if tok == "--":
                i += 1
                break
            if tok.startswith("-") and len(tok) > 1:
                i += 2 if tok in value_flags else 1
                continue
            if prog == "env" and _ENV_ASSIGN.match(tok):
                i += 1
                continue
            break
        i += _WRAPPER_POSITIONALS.get(prog, 0)
        rest = argv[i:]
        # The wrapper itself is also a command in its own right.
        return [argv[:i]] + (unwrap(rest, depth + 1) if rest else [])
    if prog == "eval":
        return [argv] + split_shell(" ".join(argv[1:]), depth + 1)
    if prog in _SHELLS or prog in {"cmd", "powershell", "pwsh"}:
        script = _shell_payload(prog, argv)
        if script is not None:
            return [argv] + split_shell(script, depth + 1)
    return [argv]


def _shell_payload(prog: str, argv: list[str]) -> str | None:
    for i, tok in enumerate(argv[1:], start=1):
        low = tok.lower()
        if prog in {"cmd"} and low in {"/c", "/k"}:
            return " ".join(argv[i + 1:])
        if prog in {"powershell", "pwsh"} and low in {"-c", "-command", "/c"}:
            return " ".join(argv[i + 1:])
        if prog not in {"cmd", "powershell", "pwsh"} and tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:]:
            return argv[i + 1] if i + 1 < len(argv) else None
    return None


def _as_argv_candidates(value: Any) -> list[list[str]]:
    if value is None:
        return []
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return split_shell(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return []
        if all(isinstance(v, (str, bytes, os.PathLike, int, float)) for v in value):
            items = [os.fsdecode(v) if isinstance(v, (bytes, os.PathLike)) else str(v) for v in value]
            if len(items) == 1:
                return split_shell(items[0])
            return unwrap(items)
        first = value[0]
        if isinstance(first, (list, tuple, str, bytes)):
            return _as_argv_candidates(first)
    return []


def extract_commands(action: Any) -> list[list[str]]:
    """Every command an action would execute, as unwrapped argv lists."""
    args = getattr(action, "args", None) or {}
    metadata = getattr(action, "metadata", None) or {}
    if not isinstance(args, dict):
        args = {}
    if not isinstance(metadata, dict):
        metadata = {}
    sources: list[Any] = []
    sub = metadata.get("subprocess")
    if isinstance(sub, dict):
        sources.append(sub.get("argv"))
    for key in ("argv", "command", "cmd", "argv_join"):
        if key in args:
            sources.append(args.get(key))
    raw = args.get("args")
    if isinstance(raw, dict):
        sources.append(raw.get("args"))
        sources.append(raw.get("command"))
    else:
        sources.append(raw)
    seen: set[tuple[str, ...]] = set()
    commands: list[list[str]] = []
    for src in sources:
        for argv in _as_argv_candidates(src):
            key = tuple(argv)
            if argv and key not in seen:
                seen.add(key)
                commands.append(argv)
    return commands


def _flags(argv: list[str]) -> tuple[set[str], set[str], list[str]]:
    short: set[str] = set()
    long: set[str] = set()
    positionals: list[str] = []
    end_of_flags = False
    for tok in argv[1:]:
        if end_of_flags:
            positionals.append(tok)
            continue
        if tok == "--":
            end_of_flags = True
            continue
        if tok.startswith("--") and len(tok) > 2:
            long.add(tok[2:].split("=", 1)[0].lower())
        elif tok.startswith("-") and len(tok) > 1 and not re.fullmatch(r"-\d+(\.\d+)?", tok):
            body = tok[1:].split("=", 1)[0]
            short.update(body)
            # Single-dash long options (`-force`, `-rf` both covered).
            long.add(body.lower())
        else:
            positionals.append(tok)
    return short, long, positionals


def _has_flag(name: str, short: set[str], long: set[str]) -> bool:
    name = str(name).lstrip("-")
    if len(name) == 1:
        return name in short
    return name.lower() in long


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _contiguous(needle: list[str], hay: list[str]) -> bool:
    n = len(needle)
    if n == 0:
        return True
    hay_l = [h.lower() for h in hay]
    return any(hay_l[i:i + n] == needle for i in range(len(hay_l) - n + 1))


def argv_matches(argv: list[str], spec: dict[str, Any]) -> bool:
    if not argv:
        return False
    programs = {program_name(p) for p in _as_list(spec.get("program"))}
    if programs and program_name(argv[0]) not in programs:
        return False
    short, long, positionals = _flags(argv)
    if "subcommand" in spec:
        options = [str(o).lower().split() for o in _as_list(spec["subcommand"])]
        if not any(_contiguous(words, positionals) for words in options):
            return False
    for group in _as_list(spec.get("flags_all")):
        if not any(_has_flag(name, short, long) for name in _as_list(group)):
            return False
    if "flags_any" in spec:
        if not any(_has_flag(name, short, long) for name in _as_list(spec["flags_any"])):
            return False
    if "arg_contains" in spec:
        needles = [str(n).lower() for n in _as_list(spec["arg_contains"])]
        if not any(n in tok.lower() for tok in argv[1:] for n in needles):
            return False
    return True


def action_matches_command(action: Any, spec: dict[str, Any]) -> bool:
    return any(argv_matches(argv, spec) for argv in extract_commands(action))


def validate_command_spec(spec: Any, where: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(spec, dict):
        return [f"{where}: command must be an object"]
    unknown = set(spec) - COMMAND_SPEC_KEYS
    if unknown:
        errors.append(f"{where}: unknown command key(s) {sorted(unknown)}; allowed {sorted(COMMAND_SPEC_KEYS)}")
    if not (set(spec) & COMMAND_SPEC_KEYS):
        errors.append(f"{where}: command needs at least one of {sorted(COMMAND_SPEC_KEYS)}")
    for key in ("program", "subcommand", "flags_any", "arg_contains"):
        if key in spec and (not _as_list(spec[key]) or any(not str(v).strip() for v in _as_list(spec[key]))):
            errors.append(f"{where}: command.{key} must be a non-empty string or list of non-empty strings")
    if "flags_all" in spec:
        groups = _as_list(spec["flags_all"])
        if not groups or any(not _as_list(g) for g in groups):
            errors.append(f"{where}: command.flags_all must be a non-empty list of flag names or alternative lists")
    return errors


def iter_programs(commands: Iterable[list[str]]) -> list[str]:
    return [program_name(c[0]) for c in commands if c]
