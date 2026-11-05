# Security gauntlet readiness

Branch: `feature/security-gauntlet-readiness`, based on `feature/security-gauntlet` at `66e38c6`.

Decision: **CONDITIONAL**.

The page can show a buyer the released SDK and Predictive Authority results, with baseline, protected, and overall verdicts kept apart. It is not a GO for mandatory operating-system enforcement as a released product. Linux and Windows were not executed. A same-user write outside a Seatbelt profile still completes.

## What changed in the verdict

The prompt-injection summary and the export are different protected steps. The summary is `VERIFIED_ALLOWED`. The export is `VERIFIED_PREVENTED`. The baseline, which never calls Varden, is `OBSERVED_ONLY`. Those three scopes are now the record. The JSON export, the HTML assessment, and the page render the same lines. An overall `VERIFIED_PREVENTED` that does not match a protected leg, or that lacks an independent hash, is sealed to `INCONCLUSIVE` or `EXECUTION_ERROR`.

## Runs on this Mac, integrity root unset

| Scenario | Baseline | Protected claim | Overall |
|---|---|---|---|
| Prompt injection | `OBSERVED_ONLY` | `untrusted_export` `VERIFIED_PREVENTED` | `VERIFIED_PREVENTED` |
| Predictive Authority | `VERIFIED_ALLOWED` | `with_pa:external_post` `VERIFIED_PREVENTED` | `VERIFIED_PREVENTED` |
| Mandatory enforcement | `OBSERVED_ONLY` | `os_supervisor` `UNSUPPORTED` | `UNSUPPORTED` |
| Auditable evidence | same as prompt injection | same | same |
| Coverage gap | `UNSUPPORTED` (file changed) | `INCONCLUSIVE` (no protected leg) | `UNSUPPORTED` |

Predictive Authority, protected trace `gauntlet-pa-on`: ingest `allow`, repository read `monitor`, credential read `require_approval`, external post `require_approval`. The first preventing decision is the credential read. The graph on the page is the live registry after those `/sdk/guard` calls (20 nodes, 8 on hazardous paths, 13 findings). Reachability is not a forecast. The external URL is not contacted.

## Seatbelt probe, integrity root set

`VARDEN_INTEGRITY_ROOT` pointed at a worktree of `feature/monitoring-integrity` at `8fcf94a`. This branch does not contain that code.

Contained `open` under `sandbox-exec -f` (`macos_seatbelt_experimental`) exited 1. Protected hash before and after: `dc70b8c6ac967c4c883f6ad2355596510a0bd5df4fdf5e91ca3a0edfff240f98`. That leg is `VERIFIED_PREVENTED`. The same user wrote a file outside the profile (`OBSERVED_ONLY`). Overall stayed `UNSUPPORTED`. The page header still says OS enforcement is not in this tree.

Linux bubblewrap and the Windows restricted token were not run.

## Checks

- `pytest tests/security_gauntlet`: 15 passed. Playwright smoke passed after Chromium was installed (1 passed). An earlier sandboxed run skipped it when the browser binary was not visible.
- Ruff passed.
- `npm test` and `npm run build` in `demos/security-gauntlet/frontend` passed.
- The buyer page was exercised: Predictive Authority showed the three lines above and a node id `res:credential:1fd0d4d0aef8a582`. Mandatory enforcement, with the integrity root set, showed contained prevention and overall `UNSUPPORTED`.

## Not claimed

- Prevention from a policy sentence without a file hash.
- OS enforcement when only the SDK blocked a tool.
- Equivalent protection on Linux or Windows.
- A forecast that an agent will take a reachable action.
