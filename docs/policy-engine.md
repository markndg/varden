# Policy engine

Varden policies are JSON documents evaluated in order
`block → require_approval → sanitise → warn → monitor → allow`. The first
matching rule wins. If nothing matches, the **default decision** applies
(see below). By default that is `allow`, so existing policies behave as they
always have.

This page covers three features added in v0.4.2:

1. `command`: argv-aware matching for subprocess and shell actions
2. strict validation, which rejects rules that could never fire
3. `default` / `defaults`: deny-by-default, optionally per surface

## 1. `command`: match commands by structure, not substrings

String rules like `{"field:args.argv_join": {"contains": "rm -rf"}}` are easy to
evade: `rm -fr`, `rm -r -f`, `rm  -rf` (two spaces), `/bin/rm -rf`, `sudo rm -rf`
and `bash -c 'rm -rf /'` all get past them. A `command` predicate parses the
command the way a shell would and matches its structure:

```json
{"type": "tool_call", "command": {"program": "rm", "flags_all": [["r", "R", "recursive"], ["f", "force"]]}}
```

| Key | Meaning |
|-----|---------|
| `program` | Program name or list of alternatives. The basename is compared case-insensitively with `.exe` stripped. |
| `subcommand` | A word sequence (`"destroy"`, `"db reset"`) or a list of alternatives. It matches when the words appear consecutively among the positional (non-flag) arguments. For example, `kubectl -n prod delete namespace x` matches `"delete namespace"`. |
| `flags_all` | Every group must be present. A group is one flag name or a list of alternative names. Single letters are short flags (`-r`, and they're case-sensitive), so combined forms like `-rf` and `-fr` are expanded. Longer names are long flags (`--force`, `--force=true`). |
| `flags_any` | At least one of these flags must be present. |
| `arg_contains` | At least one argument contains one of these substrings (case-insensitive). Useful for sensitive paths such as `.env` or `id_rsa`. |

A spec needs at least one of these keys, and every key you give must match.

The parser handles all of the following before matching:

- **Wrappers:** `sudo`, `doas`, `env` (including `VAR=value`), `nohup`, `nice`, `timeout`, `xargs`, `stdbuf`, `command`, `exec` and similar.
- **Shell operators:** a shell string is split on `;`, `&&`, `||`, `|`, `&` and newlines.
- **Command substitution:** the contents of `$(...)` and `` `...` `` are parsed as commands too.
- **Nested shells:** payloads of `sh -c`, `bash -lc`, `eval`, `cmd /c` and `powershell -Command` are parsed recursively.
- **Every payload shape Varden emits:**
  - `subprocess.run`, `Popen`, `call`, `check_*`, `os.system`, `os.popen`, and asyncio subprocess
  - `varden session` shims (`argv` / `argv_join`)
  - `metadata.subprocess.argv`

A rule matches if **any** command in the chain matches.

> **Use `command` rules as a guardrail, not a boundary.** Static parsing of shell
> text can't be complete: a shell can build the command it runs at runtime in
> ways no matcher can predict from the text. A `command` block rule is much
> harder to evade by accident than a substring rule, but it will not stop a
> determined or injected agent on its own. For real enforcement, use an
> **allowlist**: `"defaults": {"subprocess": "block"}` plus `allow` rules for the
> programs the agent actually needs. Anything the matcher can't recognise then
> falls through to `block`.

The bundled packs now include argv-aware rules alongside the older substring
rules:

- `baseline-operational-safety`
- `host-shell-safety`
- `destructive-tools-and-infra`
- `deployment-cli-safety`

Substring rules are still useful for content matching, such as prompt-injection
wording. Use `command` for anything shaped like a command line.

`command` does not make subprocess interception complete. Anything that runs
outside Python's patched functions is still not covered (see
[runtime-limitations.md](runtime-limitations.md)).

## 2. Validation: no more silent no-ops

### At startup

Outside `VARDEN_ENV=dev` (or with `VARDEN_STRICT_POLICY=true`), the server
**refuses to start** if the policy file:

- is missing (Varden won't run with an implicit allow-everything policy)
- can't be parsed
- fails validation

In plain dev mode, problems are logged as warnings and the server starts.
`deploy/config/policy.json` ships the baseline pack so the docker-compose
setup starts out of the box.

### On every change

Before this release, a misspelled field (`agent_nme`), classifier
(`classifier:secret`), operator (`{"contain": ...}`) or bucket (`"blok"`) was
accepted, and the rule then quietly matched nothing. `PolicyEngine.validate`
now returns errors for:

- **Unknown fields.** Valid fields are:
  - the action's own fields (`type`, `tool`, `url`, `domain`, `risk_score`, `agent_name`, ...)
  - free-form paths under `args.` or `metadata.`
  - `classifier:<known name>`
  - `min_risk_score`
  - `command`
- **Unknown classifiers and operators.** The error suggests the closest valid name.
- **Wrong value types:**
  - `gte` / `lte` need numbers
  - `exists` needs a boolean
  - `in` needs at least one value
  - a bare list is rejected; use `{"in": [...]}`
- **Malformed specs:** bad `command` specs and invalid `default` / `defaults` values.
- **Misspelled top-level keys** that are close to a real bucket name.

These problems produce warnings instead of errors:

- an action `type` that Varden never emits
- other unknown top-level keys

Errors block `PUT /policy`, `POST /policy/import-pack`, `POST /policy/simulate` and
publishing. A policy file loaded at startup is validated too, and each problem
is logged.

`min_risk_score` is now a threshold, not an equality check:
`{"min_risk_score": 60}` matches risk scores 60–100. Before, it matched 60 only.

## 3. Default decisions (deny-by-default)

```json
{
  "default": "allow",
  "defaults": {"subprocess": "block", "http_request": "require_approval"},
  "allow": [
    {"type": "tool_call", "command": {"program": ["ls", "cat", "git", "pytest"]}}
  ],
  "block": [
    {"command": {"program": "git", "subcommand": "push", "flags_any": ["force", "f"]}}
  ]
}
```

When no rule matches, Varden picks the first of these that is set:

1. `defaults[<surface>]`, using `metadata.runtime.surface` or `metadata.execution_surface` (`subprocess`, `http`, `filesystem`, `mcp`, ...)
2. `defaults[<action type>]` (`tool_call`, `http_request`, `llm_call`, ...)
3. `default`
4. `allow`

Valid values are `block`, `require_approval`, `warn`, `monitor` and `allow`.

`block` rules are still evaluated before `allow` rules, so something on an
allowlist can still be blocked. Merging a policy pack never changes your
`default` or `defaults`. The dashboard rules editor now keeps `default`,
`defaults`, `require_approval` and `sanitise` when you save. Before, saving
from the editor silently dropped them.

## Why not Cedar or Rego (yet)

Moving to Cedar or OPA/Rego was considered. For now, the in-house engine stays:

- **Rego needs a separate engine.** It means a Go binary or WASM runtime alongside a Python-first, `pip install` product.
- **Cedar doesn't fit the data.** Its entity/action/resource model suits authorisation of principals. Varden's rules match loosely structured action payloads, and forcing those into entity schemas would cost most of the policy packs' readability.
- **Neither fixes the real failures.** The actual problems were silent no-op rules and substring matching, and the validator and `command` predicate address those directly.

This is worth revisiting if Varden ships a standalone gateway. Cedar's
analysability (proving that one policy is stricter than another) would then
earn its keep. The engine sits behind `PolicyEngine.evaluate`, so a
Cedar-backed engine could be added as an option without changing callers.
