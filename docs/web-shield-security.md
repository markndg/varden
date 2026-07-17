# Web Shield security

This document covers the security posture of Web Shield itself: message
authenticity in the browser, API hardening, and the localhost threat model.
For the threats Web Shield *detects*, see `docs/web-shield-threat-model.md`.
For data handling, see `docs/web-shield-privacy.md`.

## Page-to-extension message authenticity

The single biggest spoofing risk in a browser extension like this is a
malicious page pretending to be the extension's own instrumentation — e.g.
sending a fake `window.postMessage` claiming a benign `tool_registered`
event to mask a real malicious registration, or flooding fabricated events
to pollute the dashboard.

Web Shield's page-world/isolated-world split (`docs/web-shield-extension.md`)
is designed specifically against this:

1. `content-isolated.js` creates a `MessageChannel` and transfers one port to
   the page world via `window.postMessage(msg, window.location.origin,
   [channel.port2])`. The **target origin** argument
   (`window.location.origin`, not `"*"`) means the browser itself refuses to
   deliver this message if the page's origin has changed by the time it's
   delivered (irrelevant in practice for same-frame delivery, but it is
   still the correct restrictive default rather than a wildcard).
2. Once transferred, a `MessagePort` cannot be observed or forged by other
   script in the page. Structured-clone message-passing in the DOM has no
   "list all channels" introspection API — a page script that wants to inject
   fake events would need the extension's own `port1`, which it never has
   access to, or would need to intercept `page-world.js`'s wrapped
   `registerTool` calls before `page-world.js` runs, which is impossible
   because the content script runs at `document_start`, before the page's
   own script.
3. `page-world.js` only forwards data through `send()`, which is only ever
   invoked by its own `wrapMethod`/`guardProperty` call sites — a page script
   cannot call `send()` directly because it lives inside the script's IIFE
   closure, not on `window`.
4. `content-isolated.js` never trusts anything the page told it about origin
   or frame identity — `ownerOrigin`, `topOrigin`, and `isThirdPartyFrame`
   are computed from the isolated world's own `window.location`/`window.top`,
   which the page's JS cannot rewrite (a page can navigate itself, but it
   cannot lie to the browser about what origin it's actually running on).
5. `background.js` only accepts messages whose `message.source ===
   'varden-webshield-content'` from its own content script's
   `chrome.runtime.sendMessage` call — this is a `sender.id`-scoped channel;
   an arbitrary page cannot call `chrome.runtime.sendMessage` targeting
   another extension's background listener at all (that's a browser
   platform guarantee, not something Web Shield has to implement).

What this does **not** protect against: a page can still register a
genuinely malicious tool with genuinely malicious content — that's the
threat this whole system exists to *detect*, not something message
authenticity prevents. It also cannot protect against a *browser-level*
compromise (a malicious or compromised extension with broader permissions
could interfere with any other extension); that is outside any content
script's threat model.

## Protecting the local Varden API from browser-based requests

The Varden server the extension/SDK talks to is typically `127.0.0.1` or
`localhost`. Two distinct risks apply here:

1. **An arbitrary website tricking a visitor's browser into calling the
   local Varden API** (the classic "localhost DNS rebinding" / drive-by
   cross-site request class of attack). Mitigations already present in
   Varden and reused as-is by Web Shield:
   - Every write endpoint requires an API key (`require(..., scope=
     "ingest")` for `/webshield/registrations`, `/webshield/lifecycle`,
     `/webshield/invocations`, `/webshield/outputs`, `/webshield/cross-origin`)
     — a same-origin `fetch()` from an arbitrary website has no way to know
     or supply that key. The one automatic-discovery path
     (`ensureApiKey`/`apiKey()` reading `bootstrap_api_key` from `/health`)
     is a **development convenience** intended for the demo/attack-lab flow
     on a machine you already control, not a production credential exchange
     — see the honest caveat in `docs/web-shield-privacy.md`.
   - Rate limiting via the existing `RateLimiter`/`ingest` bucket
     (`varden/app_factory.py`) applies to Web Shield's ingest endpoints
     exactly like every other Varden ingest route.
2. **A malicious extension or script on the same machine hitting the local
   API directly.** Nothing about "localhost" implies trust between
   processes on the same machine — this is a known, documented limitation
   of any local-first tool. Varden's existing auth (`require()`, API keys) is
   the boundary here, same as for every other Varden endpoint; Web Shield
   introduces no new bypass and no new trust assumption.

## API hardening applied to every `/webshield/*` write endpoint

All of the following are the *existing* Varden API conventions
(`varden/app_factory.py`), reused unmodified rather than reimplemented:

- **Authentication**: `require(x_api_key, authorization, role, scope=
  "ingest")` on every ingest route; returns 401/403 on missing or
  insufficient credentials.
- **Payload limits**: `_check_payload_size()` rejects any request body over
  200,000 bytes with `413 Payload Too Large`, before any parsing/scanning
  work is done on it — this bounds the resource cost of a single malicious
  or malformed request regardless of how expensive scanning it would be.
- **Rate limiting**: the `ingest` scope's bucket
  (`config.ingest_rate_limit_per_minute`, burst multiplier 2.0) applies
  uniformly; see `test_rate_limiting_applies_to_ingest_scope` in
  `tests/test_webshield_api.py`.
- **Replay protection**: every mutating endpoint accepts an optional
  `Idempotency-Key` header; `_idempotent()` caches the computed response
  keyed on it and returns the cached result for a repeated key instead of
  re-executing (and re-scoring/re-logging) the same request — the same
  mechanism used elsewhere in Varden (e.g. `PUT /policy`).
- **Schema validation**: `_require_str()` and explicit type/field checks
  reject malformed payloads (missing `session_id`, non-string identity keys,
  etc.) with `400 Bad Request` rather than raising an unhandled exception.
- **No cross-session data access from browser-supplied IDs**: session,
  tab and frame identifiers are opaque strings scoped by the *tenant*
  derived from the caller's own API key (`require()`'s returned `record
  ["tenant_id"]`), never trusted as an authorization boundary by themselves.
  Varden OSS is single-tenant per deployment, so "cross-tenant isolation" in
  the strict SaaS sense doesn't apply; what's tested instead
  (`test_registration_ignores_browser_supplied_tenant_id_and_cannot_forge_it`)
  is that a browser-supplied `tenant_id` field in the request body is simply
  ignored — the server always uses the tenant resolved from the caller's own
  authenticated identity, so a page cannot inject data under a different
  tenant it doesn't control by forging a request field.
- **Untrusted-input treatment**: every field taken from the browser
  (tool name/description/schema, output text, origins) flows entirely
  through the same structural/Unicode/pattern classifiers before touching
  policy or storage; nothing from the browser is trusted, evaluated as code,
  or reflected back without going through redaction (`docs/web-shield-privacy.md`).

## Content Security Policy and code loading

- `extension/manifest.json`'s `content_security_policy.extension_pages` is
  `"script-src 'self'; object-src 'none'"` — the popup and options pages
  load no remote or inline script.
- No part of Web Shield (extension, SDK, or server) ever fetches and
  executes remote code. Regexes and rule tables are compiled once from
  static, checked-in source (`varden/webshield/layers/*.py`,
  `extension/src/fallback-rules.js`); there is no remote rule-download
  mechanism to poison.
- Extension `permissions` are limited to `storage`, `activeTab`, `scripting`;
  `host_permissions` are limited to `127.0.0.1`/`localhost` — the extension
  cannot make network requests to an arbitrary remote host unless you
  deliberately reconfigure the endpoint in Options.

## Non-goals (explicitly out of scope)

- Web Shield is not a sandbox. It cannot stop a browser agent from executing
  a tool call that was never routed through it in the first place (no
  Web Shield integration at all in that agent's page/host).
- It does not attempt browser exploit mitigation, supply-chain verification
  of the extension's own dependencies (there are none — zero runtime
  dependencies in both the extension and the SDK), or protection against a
  fully compromised OS/browser.
- See `docs/web-shield-limitations.md` for the complete, unhedged list.
