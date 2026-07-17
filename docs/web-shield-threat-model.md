# Varden Web Shield — Threat Model

Scope: a browser agent that consumes WebMCP tools exposed by web pages. Out of scope: the agent's
own reasoning process, the safety of the underlying LLM, and anything that happens after a tool's
result has already been handed to code Varden cannot observe (see
[`docs/web-shield-limitations.md`](web-shield-limitations.md)).

Each category below names the classifier layer(s) that detect it
(`varden/webshield/layers/*.py`), a corpus case that exercises it
(`varden/webshield/corpus/cases_v1.json`), and an attack-lab case that demonstrates it
(`varden web-shield demo` → `/webshield/lab`).

## 1. Tool framing

**Threat:** malicious instructions embedded in a tool's name, title, description, input-schema
property names/descriptions, examples, annotations, read-only/destructive hints, or arbitrary
extension metadata — anywhere an agent's context window might read text and treat it as an
instruction.

**Detection:** Layer 3 (`layers/patterns.py`) scans every text-bearing field
(`textfields.py::iter_text_fields`) for semantic categories (instruction-hierarchy override,
secrecy demand, forced tool selection, etc.), not just literal phrase matches — patterns are
regex-based but written to catch paraphrases. Layer 1 (`layers/structural.py`) flags suspicious
schema defaults, executable-looking content, and oversized fields.

**Corpus:** `malicious-injection-override`, `malicious-schema-credential`, `malicious-paraphrased-override`.
**Attack lab:** cases 2 (obvious injection), 5 (schema property injection).

## 2. Tool hijacking / lifecycle manipulation

**Threat:** registration after a session has begun, rapid register/unregister churn, repeated
surface changes, tool/method replacement, unexpected `provideContext` calls, confusingly similar
names, race-like registration, third-party-script-introduced tools, metadata changed after trust
was established.

**Detection:** Layer 5 (`layers/lifecycle.py`) compares each registration against per-origin state
kept in `WebShieldStore` (`_existing_tool_names`, `_recent_registration_count`,
`_prior_violation_count`, plus the stored exact/canonical hash of the previous registration).
`page-world.js` in the extension detects `modelContext` property replacement in the browser itself
(`webmcp.extension_tamper_detected` / `webmcp.context_replaced`) — this is inherently forensic: by
the time it's observed, the replacement has already happened, so Varden reports
`achieved_enforcement: "unavailable"` rather than pretending it blocked something after the fact.

**Corpus:** `malicious-late-session-injection`, `malicious-registration-churn`, `malicious-confusing-duplicate-name`, `malicious-metadata-changed-same-identity`.
**Attack lab:** cases 9 (late-session), 10 (churn), 11 (metadata changed), 19 (surface replacement), 20 (confusable name).

## 3. Cross-tool manipulation

**Threat:** one tool's metadata instructing the agent to call another tool automatically — email,
wallet, filesystem, shell or credential tools by name — orchestration language, "must be called
first" claims, instructions to ignore other tool results or agent policy.

**Detection:** Layer 3 pattern rules `WEBMCP-CROSS-TOOL-*` explicitly match "call the wallet/email/
shell/filesystem/credential tool" phrasing and its common paraphrases (e.g. "then call
`send_email`", "always call `wallet_sign` first").

**Corpus:** `malicious-crosstool-subtle`, `malicious-injection-override` (combines both categories).
**Attack lab:** case 3 (subtle cross-tool orchestration).

## 4. Cross-origin data flow

**Threat:** data read on one origin submitted to another; a low-trust origin triggering a
high-impact tool; unrelated origins participating in one action chain; sensitive arguments leaving
an expected origin set; a tool output directing an action on another origin.

**Detection:** Layer 6 (`layers/provenance.py`) flags non-HTTPS origins, third-party-frame
introduction, and known-blocked origins at registration time. `POST /webshield/cross-origin`
(`WebShieldStore.record_cross_origin_flow`) lets an integration report a single observed hop
(`from_origin` → `to_origin`), scored `high` risk when the origins differ. Layer 7
(`layers/output_scan.py`) flags `send/email/post the result to https://...` directives inside tool
output. **Honest limitation:** Varden does not automatically reconstruct a multi-hop chain across
independently-reported events (e.g. "A read the customer's email, then three tools later C sent it
to attacker.example") — only the single-hop signal exists today.

**Corpus:** `malicious-schema-credential` (capability half), plus the two `cross_origin` cases.
**Attack lab:** case 8 (third-party iframe registration); the dashboard's "Cross-Origin Alerts"
metric increments from `POST /webshield/cross-origin` calls.

## 5. Capability mismatch

**Threat:** a weather tool requesting a wallet address and private key; a read-only annotation
paired with a mutating description; benign naming paired with destructive schema parameters;
description inconsistent with schema; excessive permissions relative to stated purpose.

**Detection:** Layer 4 (`layers/capability.py`) infers a `CapabilityProfile` (mutates state,
mentions payment/credential, sensitive schema fields) independently from the name, description,
schema and annotations, then flags disagreement between them — e.g. `readOnlyHint=true` combined
with a description matching an unnegated mutating verb (`delete`, `submit`, `purchase`, ...; a
`_has_unnegated_match` check specifically avoids false-flagging "does not modify"-style
disclaimers).

**Corpus:** `malicious-capability-weather-wallet`, `malicious-false-readonly`, plus
`benign-honest-destructive-tool` (a *hard negative*: a destructive tool that is honestly
described and correctly annotated should not be treated as an attack, even though policy may
reasonably require approval for it — see the evaluation doc's one documented false positive).
**Attack lab:** cases 5, 6, 7 (schema mismatch, capability mismatch, false read-only), 17/18
(honestly-described payment/destructive tools, to show these are *governed*, not falsely flagged).

## 6. Output contamination

**Threat:** a tool's *result* — not its registration metadata — contains indirect instructions,
authority impersonation, instruction-hierarchy attacks, cross-tool directions, secret-exfiltration
requests, encoded/obfuscated instructions, or malicious content that originated in
user-generated/third-party data the tool merely relayed.

**Detection:** Layer 7 (`layers/output_scan.py`) reuses the Layer 2/3 Unicode and pattern analysis
against tool output text, plus output-specific checks: oversized output, embedded secret-shaped
tokens (regex), and cross-origin action directives. `POST /webshield/outputs` returns one of
`allow` / `sanitise` / `truncate` / `quarantine` / `block` depending on the risk band.

**Corpus:** the two `output_contamination` cases (moderate → quarantine, severe multi-category → block).
**Attack lab:** case 13 (contaminated tool output).

## 7. Resource / denial-of-service abuse

**Threat:** excessively large metadata, deeply nested schemas, recursive/pathological structures,
high-frequency registration churn, tool floods, oversized outputs, expensive repeated
classification.

**Detection:** Layer 1 enforces size/depth/property-count limits (`textfields.py::schema_depth`
and property counting) before any regex work runs against a payload. The API layer additionally
enforces hard payload-size limits independent of the classifier
(`routes.py::_check_payload_size`, `MAX_PAYLOAD_BYTES` / a larger cap for `/webshield/outputs`) —
a Layer-1 finding is a *signal*, the API-level cap is the actual DoS backstop, and the two are
intentionally redundant. Layer 5's registration-burst check addresses "tool floods" at the
lifecycle level.

**Corpus:** `malicious-oversized-metadata`.
**Attack lab:** case 12 (oversized metadata).

## Non-goals

- **No global reputation network.** Trust/blocked-origin state (`webshield_trust` table,
  `varden web-shield trust`) is local-only by design, matching the brief's Layer-6 constraint. The
  model is shaped so a future opt-in reputation feed could plug in without a redesign, but none
  exists today.
- **No LLM safety guarantee.** Varden reduces the volume and severity of manipulative content an
  agent sees and gives an operator a policy lever; it cannot guarantee an LLM never acts on
  something it shouldn't.
- **No sandboxing.** This is detection + policy, not a capability-confinement mechanism. Least-
  privilege credential design for the agent itself is still the caller's responsibility.
