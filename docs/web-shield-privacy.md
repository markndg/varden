# Web Shield privacy

Web Shield observes third-party website behaviour (tool metadata and tool
output) on behalf of the browser/agent operator running it. This document
describes exactly what is captured, what is redacted, and what never leaves
the browser or never reaches storage.

## Origins, not URLs

The canonical `WebMCPToolDefinition` model (`varden/webshield/models.py`)
only has `owner_origin` and `top_origin` fields — there is no full-URL field
anywhere in the registration/invocation data path. This isn't a redaction
step applied after the fact; it's a structural property of the data model,
so query strings and paths are never captured for the *identity* of a tool
registration in the first place. (Free-text fields like a tool's
`description` can of course *contain* a URL as part of its content — that
text is still subject to the pattern/structural scanners the same as
anything else, and to `redact_webmcp_output`'s secret-token pass if it
appears in scanned output — but it is not treated as tracking metadata.)

## What is redacted before it is ever persisted

Two dedicated redaction functions in `varden/redaction.py` run before any
Web Shield event is written to the events table:

- **`redact_webmcp_value(value)`** — recursively walks tool arguments/
  schema-derived structures. Any dict key matching
  `SENSITIVE_FIELD_RE` (wallet, private/seed keys, passwords, API/auth/
  session tokens, cookies, card numbers, CVV, SSN, bank/routing numbers,
  IBAN/SWIFT, clipboard) has its **value** replaced with `"[REDACTED]"` —
  not just literal keyword matches in text, but the actual value under a
  sensitive-looking key, which matters because WebMCP schemas use arbitrary
  property names. Lists are capped at 50 entries; long strings are truncated
  at 500 characters. This is what wraps invocation `args` before they are
  stored (`WebShieldStore.record_invocation_request`).
- **`redact_webmcp_output(text, max_chars=2000)`** — applied to tool output
  text before persistence. Replaces `password=...`/`secret=...`/
  `api_key=...`/`private_key=...`/`credit card=...`-shaped tokens with a
  redacted marker, and caps the text at 2,000 characters (with an explicit
  `…[TRUNCATED N chars]` marker so truncation is visible, never silent).

Both functions are shared with, not duplicated from, the classifiers: e.g.
`SENSITIVE_FIELD_RE` is the same pattern `layers/capability.py` uses to
detect credential-shaped schema fields, so redaction and detection can never
silently drift apart on what counts as sensitive.

## What is never persisted

- Raw credentials, API keys, tokens, cookies, private keys, seed phrases,
  card numbers, or full account identifiers — always redacted per the above
  before the event metadata dict is constructed, not after.
- Full tool output beyond 2,000 characters.
- Query strings or paths for owner/top origins (structurally absent, see
  above).
- Anything from a request the size checker (`_check_payload_size`, 200 KB
  cap) rejects outright — an oversized payload never reaches the scanner or
  the database at all.

## What is captured, and why

The events table (shared with the rest of Varden — no separate Web Shield
event store) records, per `webmcp.*` event: session/tab/frame identifiers,
top/owner origin, tool name and normalised identity, exact and canonical
metadata hashes (not the full raw text — see
`docs/web-shield-architecture.md` for the hashing scheme), redacted findings
and evidence excerpts, risk score/band/drivers, policy decision, and
enforcement outcome. This is the minimum needed to answer "what tool did
this site register, has it changed, was it flagged, and what did Varden do
about it" — the operator-facing questions the dashboard exists to answer.

Finding **evidence excerpts** (`Finding.evidence` in `varden/webshield/models.py`)
are short field-scoped snippets (the specific offending phrase/sequence),
not the entire field — evidence is deliberately narrow so the dashboard can
show *why* something was flagged without reproducing an entire (potentially
large, potentially containing unrelated user content) field verbatim.

## Local trust and configuration storage

- Per-origin trust decisions (`varden web-shield trust add/remove/list`) are
  stored in the same local SQLite database as everything else in Varden
  (`webshield_trust` table) — no cloud sync, no external service.
- The browser extension stores its configuration (server endpoint, mode,
  API key) in `chrome.storage.local`, which is sandboxed per-extension by
  the browser and not accessible to web pages. It is **not** additionally
  encrypted by Web Shield beyond what the browser's storage sandboxing
  already provides; this is a known, documented limitation (see
  `docs/web-shield-limitations.md`) rather than an implemented encryption
  layer, since MV3 extensions have no first-party encrypted-storage API
  beyond OS-level disk encryption, which is outside this project's control.
- The offline event queue (also `chrome.storage.local`, capped at 200
  entries) stores the same already-redacted request bodies that would have
  been sent to the server — nothing additional, and nothing raw.

## The `bootstrap_api_key` auto-discovery convenience

The extension's `ensureApiKey()` and the SDK's `apiKey()` will, if no API key
is configured, fetch `${endpoint}/health` and use `bootstrap_api_key` if the
server returns one. This exists purely so the demo/attack-lab flow (`varden
web-shield demo`) works with zero manual configuration on a machine you
already control and trust. It is not a production-appropriate credential
exchange mechanism — a real deployment should configure an explicit,
operator-issued API key via Options (extension) or `config.apiKey` (SDK)
rather than relying on this path. This is called out again in
`docs/web-shield-security.md`.

## Data subject / third-party website considerations

Web Shield's data capture happens on behalf of the browser's operator,
about websites the browser visits — the websites themselves are not Varden
users and have not consented to being scanned. This is the same category of
observation any browser extension performs when it inspects page content,
and is bounded the same way: the extension only observes what the page
itself exposes to `document.modelContext`/`navigator.modelContext` (content
the site chose to put in a browser-agent-facing API), not arbitrary page
content, cookies, form data, or browsing history.
