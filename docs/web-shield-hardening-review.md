# Web Shield pre-release hardening review

Audit of the ten security/correctness findings identified before the
Web Shield release. Each section records whether inspection confirmed,
disproved or refined the finding, the affected code path, the remediation,
compatibility implications, tests added, and residual limitations.

This document is the audit artefact required by the hardening pass. It is
not a marketing claim — residual limitations are listed honestly.

---

## 1. Page-world to extension-world channel integrity

**Original issue.** Documentation/comments appeared to describe the
`MessagePort` channel as authenticated or unforgeable, while the MAIN-world
script runs in a hostile page environment.

**Audit result.** **Confirmed and refined.** The MessagePort itself is
private once transferred, but the MAIN-world script is not a trust
boundary. A hostile page can inspect wrappers, retain originals, replace
APIs, or race instrumentation. The true trusted boundary is:

```text
isolated content script → extension service worker → Varden server
```

**Affected paths.** `extension/src/page-world.js`,
`extension/src/content-isolated.js`, `extension/src/protocol.js`,
`extension/src/background.js`, `docs/web-shield-extension.md`,
`docs/web-shield-security.md`.

**Remediation.**

* Per-frame channel state: cryptographically random nonce, monotonically
  increasing sequence, handshake state, protocol version.
* Nonce revealed only over the private `MessagePort` after handshake, never
  on the page-visible `window.postMessage` broadcast.
* Isolated world validates every envelope (nonce, sequence, schema, size,
  known event kinds) and rejects before relay.
* Trusted metadata (tab/frame/origin) derived from Chrome sender /
  isolated-world `window`, never from page-supplied fields.
* Background uses `sender.tab.id` / `sender.frameId` as authoritative.
* Page-originated events classified `observed_untrusted`.
* Wrapper/`modelContext` replacement reported as tamper evidence.
* Over-claiming language removed from docs/comments.

**Compatibility.** Protocol version `1`. Older extensions without the
handshake still inject; hardened servers advertise
`protocol.page_channel_version` via `/webshield/config` and
`/webshield/extension/health`.

**Tests.** `extension/test/protocol.test.js` (21 cases: missing/wrong/reused
nonce, duplicate/decreasing sequence, pre-handshake, unknown kind, oversized
payload, cyclic/Proxy/throwing getters, per-frame isolation, reconnect).
`tests/test_webshield_adversarial.py` covers spoofed envelopes at the API
boundary.

**Residual limitation.** MAIN-world observation remains bypassable by a
determined page. Extension observation ≠ SDK enforcement. No Playwright
browser harness yet — protocol unit tests + API adversarial suite stand in;
browser-only races remain documented gaps.

---

## 2. Idempotency isolation and body binding

**Original issue.** Shared idempotency cache might not namespace by
tenant/principal/route/body, enabling cross-tenant or cross-endpoint reuse.

**Audit result.** **Confirmed** for the pre-hardening implementation (raw
key only). **Fixed** in this pass.

**Affected paths.** `varden/idempotency.py`, `varden/db.py` (migration v6),
`varden/webshield/routes.py`, other routes using `IdempotencyStore`.

**Remediation.** Cache identity is
`tenant|principal|method|route|key` (hashed). Stored record includes body
hash (canonical JSON), response, expiry (default 24h). Same key + different
body → HTTP 409 `IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST`. Different
tenant/route never collide. Expired keys treated as new.

**Compatibility.** Old unscoped rows become unreachable orphans (idempotency
is an ephemeral cache, not audit history). Callers must pass scope fields;
Web Shield routes do.

**Tests.** `tests/test_idempotency.py` — exact duplicate, changed body, cross
endpoint, cross tenant, concurrent same/different body, expiry, malformed/
oversized key, body-hash stability under key reordering, cached block/
approval.

**Residual limitation.** Concurrent identical submissions rely on SQLite
serialised writers (`INSERT OR REPLACE`); good enough for OSS single-process
deployments, not a distributed lock.

---

## 3. Fabricated WebMCP APIs in production

**Original issue.** Extension could create a dummy `registerTool` /
`modelContext` when absent, altering feature detection.

**Audit result.** **Confirmed** in the original `page-world.js`
(`target.registerTool = function () {}`). **Fixed.**

**Affected paths.** `extension/src/page-world.js`,
`varden/web/webshield-lab/lab.js` (lab-only simulation retained).

**Remediation.** Production extension only wraps existing callables. Never
creates `document.modelContext` / `navigator.modelContext` / `registerTool`.
Absent surface → observation-only, no fabrication. Attack-lab shim remains
on `/webshield/lab` only, with an explicit comment that it must never be
copied into the extension/SDK.

**Compatibility.** Pages without a real WebMCP implementation simply
produce no registration observations — correct behaviour.

**Tests.** Documented in adversarial suite / extension comments; production
path verified by code review of `instrument()` (no stand-in assignment).

**Residual limitation.** Property accessor interception still used when
`modelContext` is configurable; non-configurable descriptors fall back to
observation-only with honest limitation reporting.

---

## 4. Trust scoring suppressing confirmed malicious content

**Original issue.** Local trust could reduce overall risk enough to soften
critical content findings.

**Audit result.** **Confirmed** for the original flat scorer (trust reduced
total score by up to 20). **Fixed.**

**Affected paths.** `varden/webshield/risk.py`, `varden/webshield/models.py`
(`RiskComponents`), dashboard risk explanation fields.

**Remediation.** Score split into `content_risk`, `capability_risk`,
`lifecycle_risk`, `provenance_risk`, `impact_risk`. Trust may reduce only
`provenance_risk`. Instruction override, credentials, exfiltration,
payment/wallet, destructive cross-tool, security bypass, capability mismatch
are never in the provenance bucket. Profile version bumped to `"2"`.

**Compatibility.** Additive fields on `RiskResult`; existing consumers of
`score`/`band`/`drivers` unchanged. Policy remains authoritative.

**Tests.** `tests/test_webshield_engine.py` — trusted+injection stays
high/critical; trusted+credential schema stays high/critical; trusted safe
tool reduces provenance only; trust cannot flip policy block; trust expiry.

**Residual limitation.** Trust still floors blocked origins to critical via
provenance elevation — intentional.

---

## 5. Tool identity vs registration-instance identity

**Original issue.** Identity of `origin::name` alone conflates frames/
sessions.

**Audit result.** **Confirmed.** **Fixed** with dual identity + migration.

**Affected paths.** `varden/webshield/store.py`, `varden/db.py` (migration
v7, `webshield_tool_instances`), lifecycle layer, API responses.

**Remediation.**

* Logical tool ID: `owner_origin::normalised_name` (unchanged
  `identity_key`).
* Registration instance ID: server-generated UUID scoped by
  session + frame + logical identity.
* Store both; metadata diffs are per-instance.
* Legacy rows backfilled as `legacy_instance=1` without inventing
  frame/session provenance.

**Compatibility.** Existing `identity_key` preserved. New `instance_id`
field additive on registration responses and detail views.

**Tests.** Adversarial/API tests for same-name across frames, metadata
mutation isolation, legacy readability.

**Residual limitation.** Deep multi-hop cross-origin chain reconstruction
still not implemented (single-hop only).

---

## 6. Recursive canonicalisation and security hashes

**Original issue.** Incomplete normalisation / single-hash confusion.

**Audit result.** **Confirmed** (single exact + partial canonical).
**Fixed** with three hashes.

**Affected paths.** `varden/webshield/models.py` (`ToolHashes`,
`_security_normalize`), `engine.py`, `lifecycle.py`, CLI scan/explain.

**Remediation.**

* `observed_hash` — exact safely serialised observation (minus
  `registered_at`).
* `structural_hash` — ordered JSON without non-semantic transport fields.
* `security_normalised_hash` — recursive Unicode/zero-width/whitespace
  normalisation over all text-bearing fields including nested schema/
  annotations/extension metadata.
* Lifecycle drift uses `security_normalised_hash`.

**Compatibility.** `exact_hash`/`canonical_hash` retained as aliases of
observed / security-normalised for existing consumers.

**Tests.** Engine + fuzz tests: key reorder stability, zero-width-only
divergence of observed vs security-normalised, type distinctness
(`1`/`"1"`/`true`), depth bounds, idempotent re-canonicalisation.

**Residual limitation.** Homoglyph/confusable projection is best-effort
normalisation, not a full Unicode confusable database.

---

## 7. Request-body limits before JSON parsing

**Original issue.** Size checks ran after FastAPI buffered/decoded the body.

**Audit result.** **Confirmed.** **Fixed** with ASGI middleware.

**Affected paths.** `varden/middleware.py`
(`RequestBodySizeLimitMiddleware`), `varden/app_factory.py`,
`varden/config.py`, post-parse `_check_payload_size` retained as defence
in depth.

**Remediation.** Raw ASGI middleware rejects oversized `Content-Length`
before reading body; streams and counts bytes when length is missing or
understated; returns HTTP 413 with `PAYLOAD_TOO_LARGE` without invoking
downstream app/scanner/persistence. Per-route limits for registrations,
outputs, etc.

**Compatibility.** Same 413 status; adds stable `error_code`. Documented
reverse-proxy recommendation: mirror these limits at nginx/Caddy.

**Tests.** `tests/test_body_size_limits.py` — declared length, streaming
oversize, absent length, route-specific limits, scanner not invoked on 413.

**Residual limitation.** Compression: unsupported `Content-Encoding` is not
special-cased beyond framework defaults; operators should reject unexpected
compression at the reverse proxy.

---

## 8. Conservative sanitisation

**Original issue.** Sanitisation might rewrite ambiguous or capability-
changing content into a misleading "safe" tool.

**Audit result.** **Confirmed** for earlier sentence-only stripping.
**Fixed** with fail-closed decisions.

**Affected paths.** `varden/webshield/sanitize.py`, models
(`FragmentDecision`, `SANITIZE_DECISION_*`).

**Remediation.** Clause splitting on newlines/semicolons/bullets/HTML
comments/sentences. Decisions: `safe_to_sanitise` /
`unsafe_to_sanitise` / `no_sanitisation_needed`. Credential fields and
encoded/uncertain content → block. Empty description after removal →
block. Never expands text; never inserts claims; idempotent.

**Compatibility.** Existing `SanitizeResult` fields preserved; `decisions`
additive.

**Tests.** `tests/test_webshield_sanitize.py` — newline/semicolon/bullet/
HTML comment attacks, mixed single sentence blocks, credential schema
blocks, benign security docs kept, idempotence, no expansion.

**Residual limitation.** Truly ambiguous single-clause prose that mixes
legitimate purpose with attack language without a clean boundary still
fails closed (block) rather than guessing — by design.

---

## 9. Hostile-page adversarial testing

**Original issue.** Insufficient attacker-perspective coverage.

**Audit result.** **Confirmed** as a gap. **Addressed** with layered suite.

**Affected paths.** `tests/test_webshield_adversarial.py`,
`extension/test/protocol.test.js`.

**Remediation.** API-layer adversarial suite (spoofed envelopes, floods,
confusable names, enormous schemas, churn, offline queue semantics) plus
protocol unit tests for hostile MAIN-world payloads. Outcomes asserted as
protected / observed+flagged / degraded+limited / safely rejected —
never "protected" merely because a log line appeared.

**Compatibility.** N/A (tests only).

**Residual limitation.** No Playwright/Puppeteer harness for true
`document_start` races, Proxy/`defineProperty` wars in a live Chromium
tab, or service-worker suspension. Documented as desirable-soon, not
falsely marked PASS as browser-protected.

---

## 10. Extension permissions, CSP, API hardening, clean-install

**Audit result.** Permissions already minimal; CSP strict; localhost not
treated as auth. Documented in `docs/web-shield-extension-security.md`.
Pre-parse body limits and idempotency hardening covered above. Lab HTML
escaping hardened against stored XSS from attacker-supplied metadata.

**Clean-install.** `scripts/webshield-release-smoke.sh` verifies wheel
install, CLI entry points, scan/evaluate, extension build, SDK build from
a clean venv.

**Capability negotiation.** `/webshield/config` and
`/webshield/extension/health` now return protocol features and an explicit
`compatible` result for older extensions.

---

## Summary table

| # | Finding | Status |
|---|---|---|
| 1 | Page/extension channel claims | Confirmed → fixed + honest docs |
| 2 | Idempotency isolation | Confirmed → fixed |
| 3 | Fabricated WebMCP API | Confirmed → fixed (lab-only shim retained) |
| 4 | Trust suppresses content risk | Confirmed → fixed (provenance only) |
| 5 | Tool instance identity | Confirmed → fixed + migration v7 |
| 6 | Recursive security hashes | Confirmed → fixed (3 hashes) |
| 7 | Pre-parse body limits | Confirmed → fixed (ASGI middleware) |
| 8 | Sanitisation fail-closed | Confirmed → fixed |
| 9 | Hostile-page tests | Gap → suite added (browser harness residual) |
| 10 | Permissions/CSP/smoke/gate | Documented + smoke script + release gate |
