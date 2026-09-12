# Predictive Authority — Adversarial Validation

Technical review follow-up: semantic precision, determinism, bounded-horizon
evasion, and declassification boundaries.

**Date:** 2026-09-12  
**Branch:** `feature/varden-predicitve-authority`  
**Suite harness:** `tests/predictive_authority/test_pa_horizon_evasion.py`,
`test_pa_determinism.py`, `test_pa_final_review.py` (AQ–AX), `horizon_harness.py`

## Configuration

| Setting | Value |
|---------|-------|
| `max_depth` | 3 |
| Hazardous depth semantics | Authority-relevant hops (credentials, sensitive, sinks, privileged caps, MCP nodes); alias / indirection hops cost 0 |
| Raw `bounded_reachability` | Still 1 cost per edge (unchanged for non-hazardous callers) |
| `max_nodes` | 2048 (production default); adversarial noise graphs raised for experiment |
| `max_edges` | 8192 |
| `max_paths` | 16 |
| `max_visits` | 4096 |
| Mode | `enforce` for interception scenarios; `observe` for determinism |
| Environment | local macOS / CPython 3.x (developer workstation) |

## Prediction contract (under test)

Predictive Authority does not predict agent intent. It deterministically computes
reachable authority under the evidence-backed model for identical
state / graph / evidence / action / policy / bounds.

## Scenarios and results

### Determinism (AA / AB)

| Scenario | Result |
|----------|--------|
| AA replay (12 iterations) | Identical semantic results (findings, delta, recommendation, path order) excluding timing |
| AB insertion-order | Equivalent graphs → identical hazardous findings |

### Long-horizon accumulation (H1 / AC–AF)

Benign fillers deliberately avoid credential-like paths (e.g. no `.env`) so the
experiment measures accumulation rather than accidental early hits.

| Scenario | Length | Depth | First detection | Warning distance | Result |
|----------|--------|-------|-----------------|------------------|--------|
| H1 / AC | 4 | 3 | action 3 (credential) | 1 | Intercepted before sink |
| H2 / AD | 8 | 3 | action 7 (credential) | 1 | Intercepted before sink |
| H3 / AE | 16 | 3 | action 15 (credential) | 1 | Intercepted before sink |
| H4 / AF | 32 | 3 | action 31 (credential) | 1 | Intercepted before sink |

**Interpretation:** Individually legitimate benign steps do not hide the sink.
When credential authority is acquired, evidence-backed grants place privileged
capabilities inside the horizon immediately. The sink action is strengthened to
`require_approval` under enforce.

`warning_distance = sink_action − first_detection_action` (here always 1 for
the credential→external template).

### Horizon camping (AG)

| Attack | Raw BFS (depth 3) | Hazardous analysis |
|--------|-------------------|--------------------|
| Credential → 4 alias nodes → `aws.ec2.modify` | Not reachable | Detected (`credential_to_cloud_mutation`) |

**Finding:** Before this pass, raw hop counting allowed indefinite depth+1
camping via attacker-controlled alias topology.

**Fix:** Hazardous patterns use authority-relevant hop costs. Intermediate
non-authority nodes do not consume the depth budget. `max_depth` was **not**
raised.

### Capability drip (AH)

One low-impact tool action per step, then credential, then external sink.
Escalation at credential acquisition; sink not allowed under enforce.

### Cross-MCP (AI)

Eight-step trajectory across domains A/B/C. Untrusted provenance retained on
the session graph; escalation before / at external sink.

### Noise flooding (AJ) — honest large-graph accounting

Disconnected noise does **not** force the hazardous BFS to walk every node.
Report both total graph size and authority-relevant BFS visits.

| Scenario | Graph nodes | BFS visited | Status | Hazard | detect_hazardous_paths median | BFS median |
|----------|------------:|------------:|--------|--------|------------------------------:|-----------:|
| Noise-100 | 102 | 2 | COMPLETE | yes | ~0.09 ms | ~0.004 ms |
| Noise-1k | 1,002 | 2 | COMPLETE | yes | ~0.76 ms | ~0.006 ms |
| Noise-10k | 10,002 | 2 | COMPLETE | yes | ~8.2 ms | ~0.004 ms |

Configured production limits remain `max_nodes=2048`, `max_edges=8192`,
`max_visits=4096`. These experiments raise construction limits only so a large
in-memory graph can exist; they do **not** claim an exhaustive walk of all
10,000 nodes. `detect_hazardous_paths` median reflects source-index scan cost
over the full node set; BFS visits remain on the hazardous spine.

Truncation / incomplete analysis never yields `safe_conclusion=true`.

### Bounded traversal performance

Graph size and traversal work are **not** the same quantity. Predictive Authority
may operate on a large graph while visiting only a small relevant subset.

#### Fast path (retained)

The existing 10k nearby-hazard benchmark measures large-graph indexing plus
**early** hazard discovery on a short spine:

| Scenario | Graph nodes | BFS visited | Status | Hazard | detect median | BFS median |
|----------|------------:|------------:|--------|--------|--------------:|-----------:|
| Nearby hazard | 10,002 | 2 | COMPLETE | yes | ~8.1 ms | ~0.007 ms |

This must **not** be read as worst-case graph analysis.

#### Stress path (`worst_case_traversal`)

Deterministic fan-out from a credential source: benign `cap:aaa.*` successors
sort before hazardous `cap:zzz.aws.ec2.modify`, so BFS walks early branches
first. Disconnected fillers pad total size to ~10,000 without changing the
reachable frontier.

Configured bounds (unchanged):

| Bound | Value |
|-------|------:|
| max_depth | 3 |
| max_nodes | 2048 |
| max_edges | 8192 |
| max_visits | 4096 |
| max_paths | 16 |

| Scenario | Total nodes | Visited | Status | Hazard | Decision | Median | p95 | Terminating bound |
|----------|------------:|--------:|--------|--------|----------|-------:|----:|-------------------|
| BA near-limit positive | 10,000 | 1,902 | COMPLETE | PROVEN | require_approval | ~15 ms | ~16 ms | — |
| BB bound exhaustion | 10,000 | 4,096 | TRUNCATED | NOT_OBSERVED | require_approval | ~28 ms | ~32 ms | MAX_VISITS |
| BC hazard beyond bound | 10,000 | 4,096 | TRUNCATED | NOT_OBSERVED | require_approval | ~28 ms | ~31 ms | MAX_VISITS |

When traversal bounds are exhausted, Varden reports incomplete analysis and
fails safely rather than interpreting an unfinished negative search as evidence
of safety. For BC, a hazardous node may exist in the graph yet remain
**not observed** within the completed search — that is not reported as “no
hazard exists.”

**Defect closed in this pass:** reachability `MAX_VISITS` truncation is now
propagated through `detect_hazardous_analysis` into engine `analysis_status`,
so enforce-mode fail-safe applies to visit-bound incompleteness (not only
graph construction truncation).

### Branch explosion (AK)

1→10→100 benign fan-out with one leaf to `aws.ec2.modify`: detected.

### Alias / indirection (AL)

`credential → cloud.identity → deployment.identity → infrastructure.writer → aws.ec2.modify`:
detected under authority-hop depth.

### Acquire / revoke / reacquire (AM)

Revocation clears actionable confirmed grants; reacquisition restores hazardous
findings; sink remains strengthened.

### Declassification (AN / AO / AQ / AR)

| Case | SECRET | Provenance | Finding identity | Decision |
|------|--------|------------|------------------|----------|
| AN trusted property-scoped | cleared | retained | sensitive flow terminated | n/a (graph) |
| AO fake `claimed_sanitised` | not cleared | n/a | `untrusted_to_sensitive_to_external` present | escalate |
| **AQ** declass → benign sink | cleared | retained | **no** `secret_exfiltration`; **no** `provenance_specific_hazard` | allow |
| **AR** declass → provenance-sensitive privileged trajectory | cleared | retained | **no** secret_exfiltration; **yes** `untrusted_to_credential_to_privileged` / `provenance_specific_hazard` | require_approval |

Property-specific declassification works both ways: clearing A removes A-based
findings without inventing unrelated blocks; retained B still participates when
policy is B-sensitive.

### Depth semantics regression (AS) + alias resilience (AT / AU)

| Case | Raw topology (depth 3) | Authority-relevant hazard |
|------|------------------------|---------------------------|
| AS credential + 4 aliases → privileged | not reachable | reachable / detected |
| AT 100-hop zero-cost aliases | n/a | detected; visits bounded; path preserves aliases |
| AU alias cycle A→B→C→A + hazard | terminates | detected; deterministic |

### Truncation (AP / AV / AW)

| Case | Hazard | Status | Safe? | Enforce |
|------|--------|--------|-------|---------|
| AP / AW negative truncation | none found before bound | TRUNCATED | never | require_approval |
| AV positive hazard then truncate | retained | TRUNCATED | never | require_approval |

`TRUNCATED` + hazard means a path was proven; analysis was not exhaustive.

### Incomplete analysis (AP)

Graph `max_nodes`/`max_edges` exhaustion → `analysis_status=truncated`,
`safe_conclusion=false`, enforce default `failure_mode=require_approval`.

### Performance: benchmark vs CI smoke (AX)

| Guard | Threshold (loose) | Observed typical |
|-------|-------------------|------------------|
| 1k-node detect | < 500 ms | ~0.8 ms |
| 10k-node detect | < 1500 ms | ~8 ms |
| 32-step accumulation | < 3000 ms | ~100–200 ms |

Guards catch order-of-magnitude regressions only — not laptop-vs-CI variance.
Precise medians come from `python -m varden.predictive_authority.benchmarks`.

## Findings

1. **Horizon camping (real defect):** Alias chains could keep privileged sinks
   at raw `depth+1`. Fixed via authority-relevant depth for hazardous analysis.
2. **Long benign chains:** Do not evade detection when the model eventually
   observes credential / privileged authority — accumulation works as designed.
3. **Direct config default:** `PredictiveAuthorityConfig(mode="enforce")`
   previously defaulted `failure_mode` to `preserve_existing`, allowing truncated
   analysis to remain ALLOW. Default is now `require_approval` (aligned with
   documented parse behaviour).

## Remaining limitations

- Relationships absent from the evidence-backed graph cannot be invented.
- Surfaces Varden does not intercept remain out of scope.
- Authority-hop compression applies to **hazardous** analysis; callers using raw
  `bounded_reachability` still see topological depth (intentional).
- Extremely large zero-cost alias floods are bounded by `max_visits` and report
  incomplete rather than safe.
- This is not plan prediction: Varden will not claim knowledge of an agent’s
  future tool choices beyond reachable authority under the model.

## Performance (representative, this workstation)

| Case | Observation |
|------|-------------|
| 32-step accumulation total | ~126 ms wall for full trajectory |
| Per-step p95 (32-step) | ~5 ms |
| Noise 10k detect | ~9 ms median |
| Normal PA paths | No intentional regression vs prior observe/enforce micros |

Do not treat these as CI gates.

## Security invariant (derived)

For a hazardous trajectory represented in Varden’s capability model, repeated
execution and AuthorityState accumulation cause hazardous sinks to enter the
predictive horizon before the sink is exercised under enforce — unless analysis
is incomplete, in which case fail-safe enforcement applies. Attacker-controlled
non-authority topology must not indefinitely defer hazardous detection via raw
hop padding.
