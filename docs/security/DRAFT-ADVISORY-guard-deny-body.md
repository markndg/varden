# DRAFT — do not publish

This is a draft GitHub Security Advisory for maintainer review. It has no CVE, no CVSS score, and it has not been published.

## Title

Varden SDK can execute a tool after a non-403 deny decision

## Affected versions

- `v1.0.0`
- `v1.0.1`
- `v1.0.2`

Confirmed by running the same harmless reproduction against detached checkouts of those tags. The protected function incremented a counter when it ran.

## Patched version

1.0.3, prepared on branch `fix/v1.0.2-security-assurance`. Not tagged and not published. It is not in tag `v1.0.2` (commit `aae9041`).

## Summary

`VardenClient.guard` treated a control-plane response as a deny only when the HTTP status was 403, or when a 2xx body had `decision.action` of exactly `block` or `require_approval`. Other deny shapes were either ignored or handled as transport failures.

Under `guarded` with explicit `fail_mode=open`, a 503 response whose body still contains `require_approval` caused the SDK to run the protected call. The stock `/sdk/guard` handler returns that 503 when an approval record cannot be persisted.

Under both `fail_mode=closed` and `fail_mode=open`, an HTTP 200 body with `decision.action` of `approval_required` or `blocked` also ran the protected call. The stock `/sdk/guard` handler does not return that 200 shape. It returns HTTP 403 for those actions. Default `fail_mode` for `guarded` and `strict` is `closed`. `strict` rejects `fail_mode=open`.

Commit `5924532`, which is already in 1.0.2, fixed HTTP 200 `action=block` and locked fail-closed handling of exceptions. The reproduction on tag `v1.0.2` still executed the tool for the two shapes above.

## Impact

An operation that the control plane decided to block or hold can run if either:

- the deployment uses `guarded` and `fail_mode=open`, and the control plane returns a non-403 response that still carries a deny (the approval-persistence 503 is such a response), or
- a client receives HTTP 200 with a deny alias the SDK did not recognise.

The first case needs that explicit fail-open configuration plus a control-plane failure while creating the approval record. It is not shown for the default fail-closed configuration. The second case is shown against the SDK and is not shown against the current server, which uses HTTP 403.

## Mitigation before a patch

- Keep the default `fail_mode=closed` for `guarded` and `strict`.
- Do not set `fail_mode=open` on an enforcing runtime if a held action must not run when approval persistence fails.
- Place nothing in front of `/sdk/guard` that rewrites a 403 into another status while preserving the JSON body, if you are still on 1.0.0–1.0.2.

## Fix

1.0.3 reads a deny only from `decision.action` and `decision.effective_action` on the guard decision object, or that object inside one FastAPI `detail` wrapper. HTTP 403 always denies. A decision slot that is present but not a recognized policy action is not treated as allow. JSON echoed on the action (`args`, `metadata`, nested `decision` or `detail` objects) is not a policy decision. The MCP gateway uses the same check. `fail_mode=open` still proceeds when no decision was delivered. `observe` still does not prevent the side effect. Regression tests require the protected callable's side-effect counter to stay empty.

## Evidence

`docs/security/V1.0.2-ENFORCEMENT-ASSESSMENT.md`

`tests/security/test_guard_response_enforcement.py`
