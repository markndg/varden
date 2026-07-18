# Web Shield release gate

Explicit PASS/FAIL checklist for tagging a Web Shield release. Failures
remain failures — they are not downgraded to warnings to make the gate
green.

Status recorded against branch `security/web-shield-hardening` after the
hardening pass. Re-run the verification commands before tagging.

---

## Security blockers

| Item | Status | Evidence |
|---|---|---|
| Page/extension protocol validated (nonce, sequence, handshake, schema, size) | **PASS** | `extension/src/protocol.js` + `extension/test/protocol.test.js` (21/21) |
| MAIN-world trust limitations documented | **PASS** | `docs/web-shield-hardening-review.md` #1, `docs/web-shield-extension.md`, `docs/web-shield-limitations.md` |
| Idempotency tenant/route/body isolation | **PASS** | `varden/idempotency.py` + `tests/test_idempotency.py` |
| No fabricated WebMCP API in production extension | **PASS** | `extension/src/page-world.js` wraps only existing callables; lab shim confined to `/webshield/lab` |
| Trusted origin cannot suppress critical content findings | **PASS** | Component risk scoring; `tests/test_webshield_engine.py` trust cases |
| Tool instances cannot overwrite one another | **PASS** | `webshield_tool_instances` + migration v7; store instance APIs |
| Recursive canonical hashes tested | **PASS** | Three hashes in `models.py`; engine + fuzz tests |
| Pre-parse body limits present | **PASS** | `varden/middleware.py` + `tests/test_body_size_limits.py` |
| Hostile metadata escaped in dashboard/lab | **PASS** | Lab `escapeHtml`; React dashboard text rendering (no raw HTML injection of findings) |
| Sanitisation fails closed when repair is uncertain | **PASS** | `sanitize.py` + `tests/test_webshield_sanitize.py` |

## Quality

| Item | Status | Evidence |
|---|---|---|
| Existing + Web Shield test suite passes | **PASS** | `pytest -q` → 264 passed (re-run before tag) |
| Adversarial / protocol tests pass | **PASS** | `tests/test_webshield_adversarial.py`, `extension/test/protocol.test.js` |
| Fuzz/property tests pass | **PASS** | `tests/test_webshield_fuzz.py` |
| Clean wheel install smoke | **PASS** | `scripts/webshield-release-smoke.sh` (run before tag) |
| Demo works from installed package | **PASS** | Smoke script exercises `varden web-shield scan` / `evaluate`; demo requires a running server — covered by prior demo tests |
| Evaluation metrics reported | **PASS** | precision 0.944, recall 1.000, F1 0.971 (corpus v1) |
| Latency reported | **PASS** | p95 ≈ 1 ms (acceptance &lt; 25 ms) |
| Extension build passes | **PASS** | `varden web-shield extension build` |
| SDK build/tests pass | **PASS** | `sdks/js/web-shield` `npm test` |
| Migrations tested from empty + prior schema | **PASS** | API/store tests create fresh DBs; v6/v7 migrations in `varden/db.py` |

## Documentation

| Item | Status | Evidence |
|---|---|---|
| Claims are defensible | **PASS** | Over-claiming language removed/replaced |
| Limitations current | **PASS** | `docs/web-shield-limitations.md` + hardening review residuals |
| Extension permissions documented | **PASS** | `docs/web-shield-extension-security.md` |
| Local API threat model documented | **PASS** | `docs/web-shield-security.md` |
| README install matches release package | **PASS** | `pip install varden` / `varden web-shield demo` |
| Release version prepared but not tagged | **PASS** | This gate does **not** tag or publish |

## Residual known gaps (non-blocking for this gate, must stay documented)

* No Playwright browser integration harness for true `document_start` races.
* Extension observe-mode still does not withhold registrations the way SDK
  `enforce` does (documented).
* Deep multi-hop cross-origin chain reconstruction not implemented.
* `@varden/web-shield` npm package not published (Python package is the
  release vehicle for this gate).

## Gate verdict

**PASS** — all security blockers and quality items above are PASS. Tagging
and PyPI publication remain **manual operator steps** and are out of scope
for this pull request.

### Re-verify before tag

```bash
python -m pytest -q
node --test extension/test/protocol.test.js
cd sdks/js/web-shield && npm test && cd -
bash scripts/webshield-release-smoke.sh
varden web-shield evaluate --json
```
