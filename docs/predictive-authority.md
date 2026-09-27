# Predictive Authority

Varden Predictive Authority evaluates not only whether an action is allowed, but
what authority and sensitive resources become **reachable** if that action is
permitted.

It performs **deterministic analysis of potential future authority** using
runtime capability / provenance state — not an LLM-based risk classifier, and
not a prediction of what an agent will choose to do next.

```text
User / External Source
        |
        v
     Action
        |
        v
 Existing Varden (normalize → provenance → policy)
        |
        v
 Capability State  S(t)
        |
        +--> Authority Delta
        |
        +--> Bounded Reachability
        |
        +--> Hazardous Paths
        |
        v
 Existing Decision Lattice
 (allow / monitor / warn / sanitise / require_approval / block)
        |
        v
 Tamper-evident audit chain
```

## Prediction contract

Predictive Authority does **not** predict an agent's future intent.

It computes authority and sensitive resources that become reachable under
Varden's current evidence-backed capability model if the proposed transition is
permitted.

The analysis is deterministic for the same state, evidence, action, policy and
configured bounds.

A reachable capability means that the capability is **possible under the model**.
It does **not** mean the agent will exercise it.

## Terminology

| Term | Meaning |
|------|---------|
| **OBSERVED** | Actually observed / executed in the session. |
| **CONFIRMED** | Authority or evidence confirmed under Varden's model. |
| **POTENTIAL** | Authority reachable under current evidence but not confirmed as exercised / acquired. |
| **PREDICTED** | State resulting from evaluating the proposed transition (counterfactual or committed). Not “will happen”. |
| **COUNTERFACTUAL** | What would become reachable if an interrupted action were permitted. |
| **HISTORICAL** | Immutable decision-time snapshot. |
| **LIVE** | Current session state. |

## Why action-by-action policy is insufficient

Individually legitimate steps can compose into a dangerous trajectory:

1. untrusted issue text enters context → often allowed  
2. read repository config → often allowed  
3. read `~/.aws/credentials` → often allowed  
4. HTTP POST to an external host → often allowed  

Together:

```text
untrusted_source → credential → external_sink
```

Predictive Authority detects that structural expansion **before** the final
sink is exercised (within intercepted surfaces), as authority state accumulates
and hazardous paths enter the analysis horizon.

## Modes (safe rollout)

Configured under policy or environment:

```yaml
predictive_authority:
  enabled: false          # default — existing Varden behaviour only
  mode: off | observe | enforce
  max_depth: 3
```

| Mode | Behaviour |
|------|-----------|
| `off` | No analysis. Behaviour equivalent to pre-feature Varden. |
| `observe` | Analyse and record recommendation; **never** changes the decision. |
| `enforce` | May **strengthen** the existing decision; **never** weakens it. |

Environment opt-in examples:

```bash
export VARDEN_PA_MODE=observe
export VARDEN_PA_MAX_DEPTH=3
```

## Confirmed vs potential capabilities

- **Confirmed** — directly observed from an intercepted action (e.g. reading an
  AWS credentials file yields confirmed `credential.aws`).
- **Potential** — evidence-driven but unscoped grants (e.g. AWS credentials
  *may* enable `aws.s3.read` / `aws.iam.modify`). Potential never silently
  becomes confirmed.

## Bounded reachability

Predictive Authority uses **two intentional distance semantics**:

### A. Raw topological reachability (`bounded_reachability`)

Ordinary graph distance: every traversed edge costs one hop.

```text
A → B → C → D   distance = 3
```

This answers a **graph** question for general consumers. Do not change this API
to authority semantics.

### B. Hazardous authority reachability

Security analysis uses **authority-relevant distance**. Security-relevant
arrivals (credentials, sensitive resources, sinks, privileged capabilities,
MCP/trust nodes) consume the depth budget. Pure representational
indirection / aliases **do not consume the authority-depth budget** (they are
still traversed under computational bounds).

```text
credential → alias → alias → alias → privileged
```

must not become “outside the horizon” merely because aliases padded raw
topology. That was the horizon-camping defect; raising `max_depth` is not the
fix.

Authority-relevant distance is **not** unlimited traversal. Work remains
bounded by `max_nodes`, `max_edges`, `max_visits`, `max_paths`, and cycle
detection. Incompleteness is reported fail-safe.

Defaults:

| Bound | Default | Role |
|-------|---------|------|
| `max_depth` | 3 | Hazardous patterns: authority-relevant hops. Raw BFS: topological hops. |
| `max_nodes` | 2048 | Graph construction limit → `TRUNCATED` |
| `max_edges` | 8192 | Graph construction limit → `TRUNCATED` |
| `max_paths` | 16 | Per reachability query |
| `max_visits` | 4096 | Expansion budget for compressed walks |

Cycles are skipped. Sources are sorted for determinism. Incomplete / truncated
analysis is **never** concluded as SAFE. In `enforce`, default `failure_mode`
is `require_approval`.

`TRUNCATED` with a hazardous finding means: at least one hazardous trajectory
was proven, but the complete graph was not exhaustively explored — not “no
useful result”.

`TRUNCATED` / incomplete with **no** finding means: no hazardous trajectory was
**observed** within the completed search. It does **not** mean none exists.
Enforce mode still fails safe (`require_approval` by default).

Graph size and traversal work differ: a 10k-node graph may visit only a tiny
hazardous spine (fast path) or force visits toward `max_visits` (stress path).
See the adversarial validation document for both families.

### Why bounded search can still catch long trajectories

Predictive Authority does not enumerate an agent's complete future plan from
the first action. Authority state is accumulated after each permitted
transition and reachability is re-evaluated. When prerequisite authority
(e.g. a credential) is acquired, privileged sinks typically enter the horizon
immediately because the model wires evidence-backed grants — not because Varden
guessed the agent's plan.

Reachability remains bounded. Varden cannot identify a relationship absent from
its capability / evidence model, and incomplete analysis is reported as
incomplete rather than safe.

Adversarial measurement (including horizon camping, AQ/AR declassification, and
honest large-graph visit accounting) is documented in
[predictive-authority-adversarial-validation.md](predictive-authority-adversarial-validation.md).

## Trusted information-flow declassification

A **trusted information-flow declassification boundary** is a Varden-recognised,
trusted transformation for which Varden has sufficient evidence that a tracked
sensitive / tainted **property** no longer propagates to the resulting value.

Sanitisation is one mechanism that may establish such a boundary. This is
**not**:

- HTML sanitisation
- SQL escaping
- generic input validation
- prompt filtering
- arbitrary tool output transformation
- an untrusted tool claiming it sanitised something

Declassification is **property-specific**:

- Clearing `SECRET` removes secret-exfiltration findings that depend on that
  property (scenario AQ: declassified value to a benign sink stays free of
  unrelated provenance blocks when policy does not require them).
- Retained `UNTRUSTED_PROVENANCE` continues to participate independently when a
  provenance-sensitive rule applies (scenario AR: declassified value into a
  privileged / credentialed trajectory).

Untrusted `claimed_sanitised` claims never create a terminating boundary.
Evidence on trusted boundaries records cleared vs remaining properties, the
trusted mechanism, and input/output nodes — never raw secret material.

## Authority delta

Canonical result is structural:

- added capabilities (confirmed / potential)
- added sensitive resources
- added external write sinks
- hazardous paths
- irreversible actions
- new privilege domains

An optional numeric `structural_units` summary is derived transparently from
those sets (documented in `AuthorityDelta.structural_units`). It is **not** a
learned risk score.

## Authority budget (optional)

```yaml
predictive_authority:
  enabled: true
  mode: enforce
  max_authority_units: 100
```

When enabled, expansion that would exceed the budget can escalate to `block`.
Default: unlimited (disabled).

## Hazardous paths

Extensible deterministic patterns, including:

- untrusted → sensitive → external sink  
- untrusted → credential → privileged action  
- sensitive → subprocess → network  
- cross-MCP trust domain  
- credential → cloud mutation  

## Counterfactual explanation

Explanatory only — never executes tools. Example:

```text
varden authority demo
```

## CLI

```bash
varden authority status --trace-id SESSION
varden authority graph --trace-id SESSION
varden authority paths --trace-id SESSION
varden authority budget --trace-id SESSION
varden authority explain --predictive
varden authority demo
# aliases:
varden predictive status
varden predictive demo
```

## Policy predicates / classifiers

When active, Predictive Authority stamps classifiers such as:

- `authority_expands`
- `credential_acquired`
- `privileged_capability_acquired`
- `new_external_sink_reachable`
- `untrusted_to_external_path`
- `cross_trust_domain_path`
- `irreversible_action_reachable`

Opt-in pack: `policy-packs/predictive-authority.json`.

## Performance

Designed for incremental graph updates and bounded BFS. Disabled mode is a
near-no-op. See `tests/predictive_authority/test_pa_performance.py` and the
adversarial validation document.

## Evidence on edges

Every security-relevant graph edge answers **why Varden believes the
relationship exists**:

| Evidence kind | Can confirm authority? |
|---------------|------------------------|
| `runtime_observed` | yes |
| `varden_configured` | yes |
| `approval_granted` | yes |
| `trusted_discovery` | yes |
| `policy_derived` | yes |
| `interceptor_derived` | observed capability only |
| `untrusted_declared` | **never** |
| `potential` | **never** |

Lifecycle: `unknown → potential → confirmed`, plus `disproven` / `revoked` /
`expired`. Speculative grants can be narrowed by trusted scope discovery.

## Analysis status

`complete` · `incomplete` · `truncated` · `failed` · `off`

Truncation / failure is **never** reported as a safe conclusion. In `enforce`
mode the default `failure_mode` is `require_approval`.

## Durable historical snapshots

When Predictive Authority is active and auditing is enabled, each evaluated
action persists an immutable **PredictiveEventSnapshot** (schema version `1`)
alongside the normal audit event:

| Concern | Behaviour |
|---------|-----------|
| Storage | SQLite table `predictive_snapshots` in the same DB as `events` |
| Identity | Canonical `events.id` (`event_id`) |
| Integrity | `snapshot_content_hash` stamped into `action.metadata.predictive_authority` (hashed on the audit chain); full graph blob verified on read |
| Redaction | Secrets / sentinel material redacted before persistence (reuse of identifier sanitisation) |
| Retention | Follows the events/DB lifecycle — no separate retention subsystem |
| Unknown fields | Extra JSON fields are ignored by older readers; missing required fields fail safely |
| Malformed / tampered | Not shown as trusted historical analysis |

Historical deep links:

```text
/ui/predictive?event_id=<stable-event-id>
```

Decision / Activity / Authority & Provenance surfaces expose **View Predictive
Analysis** when PA metadata exists (including interesting ALLOW / observe
`WOULD …` outcomes). The Predictive page labels **HISTORICAL** vs **LIVE**.

API:

- `GET /predictive/events/{event_id}` — durable reconstruction by audit id
- `GET /predictive/from-event/{event_id}` — same historical payload (UI deep-link)
- `GET /predictive/session/events/{index}` — live process-local session index

Process-local registry remains for live sessions only; historical views do
**not** require it.

## UI

Open **Predictive** in the dashboard (`/ui/predictive`), or:

```bash
# seed a deterministic Scenario A + safe comparison session
curl -X POST -H "x-api-key: $KEY" "$BASE/predictive/demo?mode=enforce"
```

The page shows Before / Predicted / Delta / Trajectory graph modes, evidence
inspector, hazardous trajectories, counterfactual text, authority delta,
analysis bounds, and the enforcement interrupt point. Observed vs predicted
labels are explicit; “predicted” means reachable-under-model, not “will happen”.

API view models: `GET /predictive/status|graph|events`,
`GET /predictive/events/{event_id}`, `GET /predictive/from-event/{id}`.

## Limitations

- Does **not** predict arbitrary future LLM behaviour or plans.
- Does **not** mediate surfaces Varden does not intercept.
- Does **not** roll back external side effects.
- Does **not** eliminate filesystem TOCTOU; filesystem coverage remains PARTIAL.
- Cannot identify relationships absent from the evidence-backed capability model.
- Full credential TTL / automatic revocation is not universal — scoped removal
  is supported; automatic expiry is a documented follow-on.
- Observe mode never blocks; use enforce only after validating recommendations.
- Trajectory deep-linking (`trajectory_id`) is not implemented in this pass.

## Compatibility

- `import varden; varden.protect()` unchanged.
- Feature disabled by default.
- Existing audit hash chain covers predictive metadata on events (including
  `snapshot_content_hash`).
- Failures inside Predictive Authority keep the existing Varden decision unless
  enforce fail-safe truncation applies.
