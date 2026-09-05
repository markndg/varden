# Troubleshooting

Diagnose with Varden's own commands first:

```bash
varden posture --json
varden coverage --json
varden runtime readiness --json
varden runtime status
varden runtime self-test
```

## Posture says NOT_PROTECTED

No meaningful active enforcing boundary in the inspected process/registry
(observe mode, never `protect()`'d, or inactive local CLI process). Install /
activate / route, then re-run `varden posture --json`. Do not claim protected
because the package is installed.

## Posture says NOT_READY

Readiness contract failed for reasons other than routing-only `NOT_ROUTED`
(missing required surfaces, uncovered required HTTP/subprocess, etc.). Fix
requirements or instrumentation; do not weaken mode/fail-mode to fake READY.

## Posture says NOT_FULLY_ROUTED

An applicable surface is `NOT_ROUTED` — commonly MCP with discovered/required
config outside the gateway. Wrap and repoint:

```bash
varden mcp wrap <config> --output <out>
```

Then re-attest with `varden posture --json`.

## Posture says PROTECTED_WITH_GAPS

Enforcement is active but applicable surfaces remain PARTIAL / UNCOVERED /
UNSUPPORTED / OBSERVATIONAL. Report the structured gaps honestly; do not
upgrade to PROTECTED.

## Attestation INVALID

Varden could not reliably determine state. Do **not** invent `protected`.
Restore control-plane/local registry visibility, then re-run posture.

## Coverage / readiness disagreement

Coverage lists surface states; readiness answers the configured contract;
posture interprets both. Prefer `varden posture --json` as the overall result.
If they disagree with your expectations, check applicability (especially MCP)
and `require_coverage` / `allow_uncovered`.

## Package installed but CLI missing

* Confirm the same interpreter: `python3 -m pip show varden` then
  `python3 -m varden.cli --help` / ensure scripts dir is on `PATH`.
* Reinstall: `python3 -m pip install --force-reinstall varden`

## Control plane unreachable

Under guarded/strict **fail-closed**, privileged side effects should block.
Check `VARDEN_BASE_URL` / API key. Do not silently switch to fail-open to
"make it work."

## Fail-closed denials

Expected when the plane is down or policy blocks. Review policy and
`varden approvals pending` / `varden authority explain <event_id>` — do not
bypass.

## MCP still NOT_ROUTED

* Host still points at the unwrapped config
* Wrap again: `varden mcp wrap <config> --output <out>` and repoint the host
* Re-check `varden posture --json`

## Filesystem only PARTIAL

Expected for Python-API-only coverage. OS-global isolation is not claimed.
Workspace mutation classes (`WRITE_CI` / `WRITE_CONFIG` / `WRITE_CODE`) still
apply on intercepted Python opens. Posture should remain
`protected_with_gaps` while filesystem is applicable PARTIAL.

## Unsupported / uncovered HTTP client

aiohttp, raw sockets, direct urllib3 may remain `UNCOVERED`/`UNSUPPORTED`.
Do not switch libraries to evade policy. Prefer clients Varden instruments
(`requests`, `httpx`, `urllib`) when building integrations.

## Subprocess gaps

Saved pre-patch references bypass monkeypatches. Child processes may open
raw network outside Python hooks. `varden session` PATH shims help some CLI
paths but are not an OS sandbox.

## Runtime self-test fails

`varden runtime self-test` probes interceptors after a local `protect()`.
Default posture reports `Self-test: NOT_RUN` and does not auto-run self-test.
Failures often mean wrong Python env, missing optional clients, or tampered
patches. Fix environment; do not disable checks.

## Coverage differs: parent vs child process

Parent `protect()` does not automatically instrument a new interpreter.
Session-level wrappers may catch some child CLI/HTTP paths — verify rather
than assume. `varden posture` from a subprocess may show `not_protected` if
that process never activated the runtime.

## Wrong environment / executable

Ensure `which varden`, `which python3`, and `pip` agree on the same venv.

## Conflicting config / missing API key

`VARDEN_BASE_URL` set without `VARDEN_API_KEY` / bearer → auth failures.
Unset stale env vars when switching tenants.

## Agent tries another path after a block

Refuse. Explain the block; offer policy review or scoped approval. Never
recommend raw sockets, alternate HTTP stacks, direct MCP, or unpatching as
workarounds.
