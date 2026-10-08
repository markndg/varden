# TI-RC-001 — Release readiness

## Baseline

| Item | Value |
| --- | --- |
| Branch | `feature/threat-intelligence` |
| Starting SHA | `e3c58fe5577835b1d13512d9567c22e699140142` |
| Working tree | Uncommitted. Not merged, pushed, tagged, or released. |
| Historical note | An earlier session recorded 792 passed and 7 Playwright errors (Chromium missing), 21 threat-intelligence tests, 27 frontend tests. Those numbers were re-measured rather than trusted. |

Starting measurement this session, before the hardening edits: the tree matched that SHA and the feature files were untracked or modified. `ruff` was available. `mypy` is not installed. Playwright Chromium was not installed.

## Qualification

Live sources, 2026-10-08, isolated database:

| Source | Result |
| --- | --- |
| ATLAS `v2026.09` | 208 techniques. 2 mapped. 206 `REVIEW`. |
| NVD | Catalog probe 403,221 CVEs. Product query examined 1 (`CVE-2025-59146`, `CWE-918`, `REVIEW`). This was not a catalog scan. |
| CWE 4.20 | 969 indexed. 8 mapped. 3 explicit `REVIEW`. 958 not promoted. |
| OWASP | `unsupported`. Upstream page is HTML. Not consumed. |

Cold-start applicability produced **no candidates**. With a controlled `tools=ENFORCED` posture, live `AML.T0051` ran the full path: contract, `EXPOSED`, inactive candidate, approval, `require_approval` from `PolicyEngine`, same decision after process restart, second approval idempotent.

## Security

| Severity | Open before fixes | Fixed | Still open |
| --- | --- | --- | --- |
| Critical | 0 | 0 | 0 |
| High | 4 | 4 | 0 |
| Medium | 5 | 5 | 0 |
| Low | 2 | 1 | 1 (CLI does not pin a previously printed hash) |

Approval revalidates the template, the contract, and current coverage before it writes `policy.json`. A changed upstream record does not rewrite an enforced rule. Details: `data/reports/TI-RC-001-security-audit.md`.

## Runtime

- `PARTIAL` and `NOT_ROUTED` still cannot become `PROTECTED`.
- A stored `PROTECTED` claim is dropped when the proving rule is removed.
- Replay uses `PolicyEngine.evaluate` on a private engine. The secrets-exfiltration case matches the live decision. Missing history stays `INSUFFICIENT_REPLAY_DATA`.
- Threat intelligence is not imported by `varden/policy.py`. Disabling the feature leaves enforcement on the existing policy.

## UI

- `/ui/threat-intelligence` is in the dashboard bundle.
- The watcher line says health is not a protection claim.
- Create Rule posts the hash and candidate id that were on screen. A mismatch is rejected.
- After approval the candidate line says the rule is in policy. Before approval it says the rule is not active.
- A created rule on a host with no applicable surface is reassessed to `NOT_APPLICABLE` rather than left as a stale "nothing proves this" exposure. The rule can exist while the attack path is absent. The page shows both facts.
- Hostile feed text is rendered as text.

## Testing

| Suite | Result |
| --- | --- |
| `python3 -m pytest -q --ignore=tests/browser` | **822 passed**, 2 warnings, 180s |
| `python3 -m pytest tests/threat_intelligence -q` | **31 passed** (included in the 822) |
| `cd frontend && npm test` | **27 passed** |
| `cd frontend && npx tsc --noEmit` | **passed** |
| `cd frontend && npm run build` | **passed** (`varden/web/app/assets/app.js`) |
| `python3 -m ruff check varden/threat_intelligence tests/threat_intelligence --select F,E9` | **passed** |
| `python3 -m pytest tests/browser/test_ui_smoke.py -q` | **9 passed** in 2.36s when the browser can be spawned |
| `mypy` | **not installed** |

Playwright: `python3 -m playwright install chromium` downloaded Chromium 151.0.7922.34. Inside the command sandbox the headless shell fails to spawn (the driver asks for an `mac-x64` path and the spawn returns `EBADARCH` / `SIGSEGV`). The same test file **passes on the host** (`9 passed`, including `/ui/threat-intelligence`). That is an environment block for sandboxed runs, not a product failure.

Security and API authorisation tests are part of the 822. No assertion was weakened to obtain a pass.

## Final verdict

`READY_TO_COMMIT`

The live adapters consume the official ATLAS STIX release, the CWE 4.20 catalog, and a real NVD window without treating feed text as instructions. The one NVD hit stayed in `REVIEW`. Approval is still the only write into policy, and it now refuses a poisoned or stale candidate. The suite above is green. What remains is coverage, not a bypass: 206 of 208 ATLAS techniques and almost all of NVD and CWE are deliberately unsupported, OWASP has no machine-readable feed, and there is no upstream signature beyond TLS. Those limits are stated in the qualification report. They are not a reason to block a commit of this opt-in subsystem.
