# TI-RC-001 — Security audit

Scope: the uncommitted Threat Intelligence subsystem on `feature/threat-intelligence`. Assumption: an attacker can influence upstream feed bytes and cannot change Varden's source URL allowlist.

Trust boundary reviewed: feed → parser → normalised item → contract → applicability → candidate → replay → approval → `policy.json` → `PolicyEngine`.

## Findings

### CRITICAL

None remaining.

### HIGH

1. **Stored candidate could publish attacker-chosen predicates.** `approve()` wrote the rule object saved in SQLite. A modified candidate could add an `url` or other predicate and have it validated into `policy.json`. **Fixed.** Approval rebuilds the contract from structured ids, regenerates the template, and refuses the request when the stored predicates, rule id, expected action, or contract proof differ. The published rule is the template, not the stored blob. Regression: `test_approval_rejects_a_poisoned_candidate_rule`.

2. **A `PROTECTED` assessment survived deletion of the proving rule.** The stored result was not recomputed. **Fixed.** `status()` rechecks items marked `PROTECTED` against the live policy and downgrades them. Regression: `test_stale_protected_claim_is_dropped_when_the_rule_disappears`.

3. **Approval ignored a change in coverage.** A candidate generated while a surface was applicable could still be approved after that surface was no longer applicable. **Fixed.** While the item is `AWAITING_APPROVAL`, approval re-runs applicability and refuses anything other than `EXPOSED` with a still-possible candidate. Regression: `test_approval_rejects_a_stale_displayed_hash_and_changed_coverage`.

4. **DNS check and TCP connect were separate lookups.** A name on the allowlist could resolve to a public address for the check and a different address for the connection. **Fixed.** `default_transport` resolves once, rejects any non-global answer, and connects to that address while verifying the certificate for the original hostname. Regression: `test_transport_pins_the_resolved_address`, `test_transport_refuses_a_private_resolution`.

### MEDIUM

5. **CWE XML entity expansion.** `xml.etree` will expand a DTD. **Fixed.** A `<!DOCTYPE` or `<!ENTITY` is refused before parse. Official CWE 4.20 has neither and parsed. Regression: `test_cwe_xml_with_entities_is_refused`.

6. **Gzip `flush()` could allocate past the cap.** **Fixed.** Output is capped with `decompress(max_length=...)`, and leftover input is rejected instead of flushed. Regression: `test_gzip_bomb_is_rejected_at_the_cap`.

7. **A hostile NVD `totalResults` could page without a bound.** **Fixed.** A window closes at 2,000 retrieved records and the source records the truncation. Regression: `test_nvd_window_cap_closes_a_hostile_total`.

8. **Two approvals could drop one rule.** Concurrent publishes read-modify-wrote `policy.json` without a shared lock. **Fixed.** `approve()` and `decide()` hold the service lock, and a regression approves two different candidates together. Both rules remain. Regression: `test_concurrent_approvals_keep_both_rules`.

9. **The investigation page could approve a record that a poll had already replaced.** **Fixed** when the client sends the hash it rendered. The UI now posts `expected_content_hash` and `expected_candidate_id`. A mismatch is HTTP 409 and does not write policy.

### LOW

10. **CLI `approve` does not send a previously displayed hash.** The command approves the current row. The UI race is closed. The CLI still approves whatever is stored at the moment of the command.

11. **`ruff` F541** on an f-string in `cli.py`. **Fixed.**

### INFORMATIONAL

12. **Replay matches `PolicyEngine.evaluate` on the same action and policy** for the secrets HTTP case (`test_replay_matches_live_policy_engine`). Replay uses a private in-memory engine. It does not call tools, open sockets, or write the policy file.

13. **Empty history is `INSUFFICIENT_REPLAY_DATA`.** Stored events do not always carry provenance, authority, classification, and destination together. Replay does not invent those fields. If they are absent, the event is `unknown` or the run is insufficient.

14. **Watcher `LIVE` is not protection.** `status.protection_claim` stays false. A cold live import of 208 ATLAS techniques produced zero candidates.

15. **The firewall path does not import `varden.threat_intelligence`.** `policy.py` has no reference. The feature stays off unless `VARDEN_TI_ENABLED=true`.

16. **An already enforced rule is not rewritten** when upstream content changes, and a second approval is idempotent. The live ATLAS end-to-end confirmed a single copy of the rule after restart and a second approve.

## Outstanding

- No signature check on ATLAS, NVD, or CWE beyond TLS to the allowlisted host.
- CLI approval does not bind a previously printed hash (LOW, above).
- Feed text is still stored for operators to read. It is not copied into rules. A hostile description remains a stored string.
- Coverage of ATLAS and NVD is intentionally narrow. See the qualification report. That is a product gap, not an ingestion bypass.
