# Threat Intelligence

Varden can watch trusted external security intelligence, convert relevant records into security contracts, evaluate those contracts against this installation, and propose a Varden policy rule for a person to approve.

External intelligence does **not** become a rule by itself. Varden does **not** trust feed text, and it does **not** activate generated rules. The firewall keeps enforcing the current policy if every external feed is unreachable.

The feature is off unless `VARDEN_TI_ENABLED=true`. Operators who leave it off see no enforcement change.

```text
External intelligence
        |
Source adapter
        |
Normalization
        |
Threat intelligence item
        |
Security contract
        |
Applicability
        |
   PROTECTED          gap
                         |
                  Candidate rule
                         |
                  Historical replay
                         |
                   User approval
                         |
              Existing Varden policy
                         |
                Runtime enforcement
```

## Trust model

Downloaded bytes are data.

They must not:

- create or edit rules
- change configuration
- run commands or code
- be treated as operator or model instructions
- choose URLs, files, or hosts to contact
- turn enforcement on

Contract selection uses structured identifiers only: ATLAS technique ids, CWE ids, and OWASP ASI ids that Varden has explicitly bound. Titles and descriptions are stored for people to read. They are not copied into rules and they are not prompts. There is no model in this path. The deterministic mapping is the authority.

Every contract and candidate is schema-checked. A candidate rule must also pass `PolicyEngine.validate` before it can be stored as possible. Approval runs the same publish checks as a normal policy update: validation, atomic write of `policy.json`, live engine update, and a policy snapshot.

## Sources

| Source | Implementation | Default document |
| --- | --- | --- |
| MITRE ATLAS | Implemented | Pinned STIX 2.1 JSON release asset |
| NVD/CVE | Implemented | CVE API 2.0, incremental `lastMod` window |
| CWE | Implemented | Official XML catalog zip, conditional GET |
| OWASP Agentic | Scaffold | No fetch until an operator pins JSON |

ATLAS default URL is the `v2026.09` STIX asset from `mitre-atlas/atlas-data`. The YAML knowledge base is not parsed. Set `VARDEN_TI_ATLAS_URL` to a newer release asset when you want it. The host must stay on the ATLAS allowlist (`github.com` and the GitHub release CDN hosts).

NVD uses `lastModStartDate` / `lastModEndDate`. The first window is `VARDEN_TI_NVD_LOOKBACK_HOURS` (default 24). Later checks continue from the stored cursor. `VARDEN_TI_NVD_KEYWORD` (default `artificial intelligence`) is only a retrieval filter. A keyword hit does not select a contract. Without `VARDEN_TI_NVD_API_KEY`, requests are spaced at least 6.5 seconds apart. The key is sent as a header and is not written to the database.

CWE is a full catalog, not a delta feed. Varden sends `If-None-Match` / `If-Modified-Since`, stores a hash index, and opens threat items only for weakness ids in the explicit binding table. Other weaknesses stay in the index so a CVE can point at them, and they are not promoted into threats.

OWASP's Top 10 for Agentic Applications is published as PDF and HTML. Varden does not scrape either. The adapter reports `unsupported` until `VARDEN_TI_OWASP_URL` points at HTTPS JSON with `"schema": "owasp-agentic-v1"`. Redirects must stay on that host.

### Polling

Each source has its own interval. Nothing assumes a 30 minute clock.

| Variable | Default |
| --- | --- |
| `VARDEN_TI_ATLAS_INTERVAL_SECONDS` | 86400 |
| `VARDEN_TI_NVD_INTERVAL_SECONDS` | 21600 |
| `VARDEN_TI_CWE_INTERVAL_SECONDS` | 604800 |
| `VARDEN_TI_OWASP_INTERVAL_SECONDS` | 86400 |

The control-plane poller waits, then checks sources whose `next_due` has passed, then waits again with jitter (`VARDEN_TI_JITTER_RATIO`, default 0.2). Failures use exponential backoff capped by `VARDEN_TI_BACKOFF_CAP_SECONDS`. `varden intelligence check` runs immediately and does not wait for the timer.

Requests set a timeout (`VARDEN_TI_TIMEOUT_SECONDS`), a retry cap (`VARDEN_TI_MAX_ATTEMPTS`), and a body cap (`VARDEN_TI_MAX_RESPONSE_BYTES`). Responses are read only up to that cap. `Content-Type: text/html` is refused. Gzip is decompressed only up to the same cap. CWE zip members are refused when the declared uncompressed size or compression ratio exceeds the configured limit.

Only HTTPS port 443 is used. The URL host must be on that source's allowlist. DNS answers must be global addresses. Redirects are followed only when the next host is also allowlisted, and at most twice. Reference URLs inside a record are stored or rejected. They are never requested.

The client uses `http.client` directly so a feed fetch is not an agent HTTP action and does not recurse through the firewall.

Catalog sources (ATLAS, CWE, pinned OWASP) treat the first successful document as a baseline when `VARDEN_TI_SUPPRESS_BASELINE` is true (the default). Those rows are stored, but they do not count as new notifications. Later hash changes do. NVD lookback rows are new, because that window is already a delta.

## Normalised items

A threat item keeps source, source id, title, description, timestamps, severity, references, technique ids, weakness ids, a content hash, parser version, and provenance. Severity comes from structured CVSS when NVD provides it. Otherwise it stays `unknown`.

Relationships stay structured. A CVE that names `CWE-522` keeps that weakness id and is linked to a stored CWE row when one exists. Identifiers are not folded into a single blob of text.

Clock anomalies (future timestamps, modified-before-published) are flagged. Change detection uses the content hash, so a hash change with the same timestamp is still a change. If an upstream version moves backwards, the source is marked rolled back and existing rows are kept.

If upstream content changes after a rule is already enforced, the live rule is left alone and the item records `upstream_changed_while_enforced`.

## Security contracts

A contract is a typed, versioned statement of an invariant. It lists required observations, unacceptable outcomes, enforcement surfaces, the structured ids that selected it, and a proof predicate. It is not executable.

Shipped bindings:

| Contract | Structured ids | Invariant |
| --- | --- | --- |
| `untrusted-instruction-execution` | `AML.T0051`, `AML.T0054`, `ASI01` | Untrusted content must not gain the agent's authority |
| `credential-exfiltration` | `CWE-200`, `CWE-312`, `CWE-522`, `CWE-798` | Sensitive information must not cross an unauthorised trust boundary |
| `unexpected-code-execution` | `CWE-77`, `CWE-78`, `CWE-94`, `ASI02`, `ASI05` | Untrusted input must not become host execution |
| `privilege-amplification` | `CWE-269`, `ASI03` | An action must not silently expand authority |

Anything else with a structured id, including `CWE-918`, `CWE-287`, `CWE-306`, and OWASP `ASI04` plus `ASI06`–`ASI10`, is `REVIEW`. The reason is stored. Varden does not invent a rule to look decisive.

## Applicability

The engine reads the coverage registry and the current policy. It does not invent a coverage percentage.

| Result | Meaning |
| --- | --- |
| `NOT_APPLICABLE` | No required surface is applicable here |
| `EXPOSED` | A required surface applies, but coverage is not `ENFORCED` or policy does not prove the invariant |
| `REVIEW` | Surfaces look enforced and policy might prove the invariant, but required observability is missing or unknown |
| `PROTECTED` | Every applicable required surface is `ENFORCED` (including `ENFORCED VIA GATEWAY`), an enforcing rule proves the invariant, and required observability was actually seen |

`PARTIAL`, `NOT_ROUTED`, `UNCOVERED`, `UNSUPPORTED`, and `OBSERVATIONAL` are never `PROTECTED`.

Proof means a `block` or `require_approval` rule whose predicates are equal to or broader than the contract proof. A warn-only rule, or a narrower rule with extra predicates, is not proof. Non-applicable surfaces are ignored, matching runtime posture: MCP that was never discovered is not a gap.

## Candidates, replay, approval

A candidate is a normal Varden rule plus an expected bucket, explanation, surfaces, confidence (`high`, `medium`, `low`, or `none`), assumptions, conflicts, generation version, and timestamp. External prose is not part of the rule text.

No candidate is produced when the result is `PROTECTED`, `NOT_APPLICABLE`, or `REVIEW`, or when the gap is coverage rather than a missing predicate. A rule cannot route MCP or close `PARTIAL` coverage. If an `allow` rule has the same predicates, the conflict is reported. Precedence would let `require_approval` win later, but nothing is written until approval.

Replay loads stored audit events and evaluates them with a private `PolicyEngine`. It does not execute tools or write policy. Counts are operations analysed, unaffected, would allow, would challenge (warn), would require approval, would deny, and unknown. Affected event ids are listed.

| Replay status | Meaning |
| --- | --- |
| `COMPLETE` | Every stored event in range was classified |
| `PARTIAL_EVIDENCE` | Some events could not be evaluated |
| `BOUNDED` | The run stopped at `VARDEN_TI_REPLAY_MAX_EVENTS` |
| `INSUFFICIENT_REPLAY_DATA` | No usable history |

Insufficient replay does not become confidence. The operator can still approve, and the UI says the history did not support a claim.

Lifecycle, in order, is `DISCOVERED`, `NORMALIZED`, `CONTRACT_GENERATED`, `ASSESSED`, `CANDIDATE`, `BACKTESTED`, `AWAITING_APPROVAL`, `APPROVED`, then `OBSERVE` or `ENFORCED`. Other states are `NOT_APPLICABLE`, `DISMISSED`, `SUPERSEDED`, `SOURCE_WITHDRAWN`, `ERROR`, and `REVIEW`. Illegal transitions are rejected. Each hop is appended to `ti_audit` with the previous state, new state, actor when a person acted, and references to the threat, contract, and candidate.

`Create Rule` / `varden intelligence approve` inserts the current Varden template into the named bucket of `policy.json` after `validate(..., for_publish=True)`. The bytes stored with the candidate are not published. Approval refuses the request when the contract, the template predicates, the installation assessment, or the content hash the operator was shown no longer match. A second approval finds the same rule id and does not rewrite it. `Dismiss`, `Mark Not Applicable`, and `Keep in Review` do not write the policy file.

`ENFORCED` means the rule is in `block` or `require_approval` in the live policy. `OBSERVE` would mean `warn` or `monitor`. The templates use `require_approval`. The UI says the rule is not active until that transition has happened. After approval, applicability is evaluated again against the live policy and coverage. The lifecycle stays put. `PROTECTED` still requires the invariant to be proven; a written rule on a surface this installation does not use stays `NOT_APPLICABLE`. Watcher `LIVE` only means the poller is healthy.

## Failure modes

If a feed times out, returns HTML, returns malformed JSON or XML, exceeds the size cap, redirects off the allowlist, or rolls back, that source is marked `error` or `degraded`. Other sources still run. Existing policy is not modified. Runtime enforcement does not call this package.

Hostile strings, oversized fields, and non-public reference URLs are stored as bounded data or rejected references. They are not fetched and not interpolated into rules.

## Privacy

Checks run from the control plane to the configured public hosts. Local telemetry is not uploaded. NVD API keys stay in the environment. Raw feed bodies are not retained; the database keeps bounded fields, hashes, cursors, assessments, candidates, replays, and the audit trail. Retention is `VARDEN_TI_RETENTION_ITEMS` (default 5000). Rows waiting on approval or already enforced are not pruned. Schema version lives in `ti_schema`.

## Configuration

```bash
export VARDEN_TI_ENABLED=true
export VARDEN_TI_NVD_API_KEY=...          # optional
export VARDEN_TI_NVD_KEYWORD='AI agent'   # retrieval filter only
export VARDEN_TI_ATLAS_URL=https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/stix-atlas.json
```

Leave `VARDEN_TI_ENABLED` unset to keep the subsystem off.

## CLI

`varden intelligence` supports `status`, `sources`, `check`, `list`, `show`, `contract`, `candidate`, `replay`, `approve`, `dismiss`, `not-applicable`, and `review`.

`--json` prints one JSON document on stdout and nothing else. Human text is the default. Errors in JSON mode are a single JSON object on stdout and a non-zero exit.

`list --status` filters by applicability (`PROTECTED`, `EXPOSED`, `REVIEW`, `NOT_APPLICABLE`). Other filters: `--source`, `--severity`, `--lifecycle`, `--surface`, `--since`, `--until`.

## API

Authenticated with the same API key or bearer token as the rest of the control plane.

| Method | Path | Role |
| --- | --- | --- |
| GET | `/threat-intelligence/status` | viewer |
| GET | `/threat-intelligence/sources` | viewer |
| POST | `/threat-intelligence/check` | analyst |
| GET | `/threat-intelligence/items` | viewer |
| GET | `/threat-intelligence/items/{id}` | viewer |
| GET | `/threat-intelligence/items/{id}/contract` | viewer |
| GET | `/threat-intelligence/items/{id}/candidate` | viewer |
| POST | `/threat-intelligence/items/{id}/replay` | analyst |
| POST | `/threat-intelligence/items/{id}/approve` | admin |
| POST | `/threat-intelligence/items/{id}/dismiss` | analyst |
| POST | `/threat-intelligence/items/{id}/not-applicable` | analyst |
| POST | `/threat-intelligence/items/{id}/review` | analyst |
| POST | `/threat-intelligence/seen` | viewer |

`status.protection_claim` is always false. `status.watcher` is `LIVE`, `CHECKING`, `DEGRADED`, `OFFLINE`, `DISABLED`, or `ERROR`.

## UI

The control plane sidebar shows watcher health, the last successful check, new items, and how many stored records are actionable (a possible candidate or an approved rule). Watcher `LIVE` is feed health. It is not a protection claim, and the indicator is not drawn as a healthy firewall.

`/ui/threat-intelligence` separates mapping coverage from runtime protection. Summary counts are total stored records, contracts mapped, unmapped records, exposed, protected, and candidates awaiting approval. Review and not-applicable stay available as their own counts. Source health shows last success, records indexed, and records mapped. An ATLAS index is techniques in the fetched document. A CWE index is the catalog, not the bound subset. An NVD count is the configured query, not the CVE catalog. OWASP stays labelled unsupported until a JSON document is pinned.

The results table has threat, source, contract, applicability, protection, and an investigate action. A record with no contract id is **Unmapped — no supported Varden contract**, with the stored review reason on the investigation page. Mapped identifiers show the contract name. Protection labels (candidate available, awaiting approval, coverage gap, rule installed, enforced) come from lifecycle, applicability, and whether a candidate is possible. **Enforced** is used only when applicability is `PROTECTED`. **Actionable** lists records that already have a candidate or an installed rule. When that view is empty, the page shows the server's `actionable_empty_message` and does not invent a reason.

Filters are search, source, mapping, applicability, severity, and surface. Results are paged. Opening an item shows the external record, provenance, interpretation, contract or the reason none exists, applicability, candidate, replay, and the approval decision. **Create Rule**, **Dismiss**, **Keep in Review**, and **Mark Not Applicable** are explicit.

## Threat model for ingestion

| Threat | Control |
| --- | --- |
| Feed text smuggles instructions | Text is data. Contracts come from an internal id table. Rules use fixed templates. |
| Feed supplies a URL (SSRF) | Reference URLs are not fetched. Fetch URLs are operator configuration plus a host allowlist. Private and metadata addresses are refused. Redirects are revalidated. |
| Huge or partial body | Hard byte cap. Partial reads are errors. Oversized input is not parsed. |
| Zip or gzip bomb | Declared size and ratio checks before inflate. Decompressed output is capped. |
| Unexpected HTML or MIME | HTML is refused. OWASP accepts only the pinned JSON schema. |
| Invalid UTF-8 or malformed JSON/XML | Parse error, source marked failed, no item, no rule. |
| Duplicate or rewritten ids | Source id is kept. Same hash under another id is linked as duplicate content. Hash changes are new revisions. |
| Clock games | Anomalies are flagged. Hashes, not timestamps, decide that content changed. |
| Source rollback | Flagged. Stored decisions are not deleted. |
| Feed outage | Source error and backoff. Enforcement does not read this subsystem. |
| Silent activation | Approval is a separate admin action. Candidates cannot call the policy writer. |
| False assurance | `PARTIAL` and `NOT_ROUTED` cannot be `PROTECTED`. Missing observability becomes `REVIEW`. Unmapped ids become `REVIEW`. Replay says when history is insufficient. |
| Prompt injection via the UI | React text nodes. No HTML injection of descriptions. Descriptions are not placed in rule fields. |

What this does **not** do: verify an upstream signature beyond TLS to the allowlisted host, translate arbitrary CVE prose, or claim that an approved rule stops an attack on a surface Varden does not enforce.
