# Policy Packs

These packs are baseline operational safety controls for agent runtimes. They are designed to be imported through the rules workspace as uploaded policy packs or merged into `policy.json`.

Each JSON file uses the template envelope accepted by the UI:

```json
{
  "name": "pack-id",
  "description": "Short purpose statement",
  "template": {
    "block": [],
    "warn": [],
    "monitor": [],
    "allow": []
  }
}
```

## Packs

- `baseline-operational-safety.json`: one-click baseline combining the crucial controls from the other packs.
- `agent-prompt-injection.json`: indirect prompt injection and tool-output injection indicators.
- `sensitive-data-exfiltration.json`: cardholder and financial HTTP exfiltration stay blocked; generic outbound HTTP with secret-like or source-internal classifiers is warn-tier (matches `demos/flagged_data_agent.py`).
- `destructive-tools-and-infra.json`: destructive shell, filesystem, Kubernetes, Terraform, cloud, package, and database actions.
- `database-safety.json`: destructive SQL, unbounded writes, privilege changes, broad reads, schema enumeration, and obfuscation.
- `network-egress-and-tunnels.json`: cloud metadata, paste sites, tunnels, webhooks, messaging exfil paths, and general HTTP monitoring.
- `excessive-agency-and-workflow-escalation.json`: risky chains, previous warn/block context, high risk scores, and autonomous write/escalation behavior.
- `credential-and-identity-abuse.json`: credential harvesting and token extraction patterns across local files, cloud config, and auth tooling.
- `supply-chain-and-ci-integrity.json`: remote script execution, lockfile tampering indicators, CI token misuse, and workflow-integrity signals.
- `monitoring-foundation.json`: broad monitor coverage for HTTP, LLM, subprocess, SQL, file, package, cloud, and repository tools.

## Recommended starter set

For most teams starting from scratch:

1. Import `baseline-operational-safety.json` first.
2. Add `credential-and-identity-abuse.json` for modern token/secret theft patterns.
3. Add `supply-chain-and-ci-integrity.json` for software supply-chain and CI abuse.
4. Add `database-safety.json` and `network-egress-and-tunnels.json` when your agent touches data systems or outbound integrations.

## Scope

The packs map to current operational risk categories from OWASP LLM 2025 and recent public AI-agent incidents: prompt injection, sensitive information disclosure, excessive agency, system prompt leakage, unsafe tool use, data exfiltration, and credential or cloud metadata harvesting.

They intentionally use only predicates supported by the current policy engine:

- Operators: `eq`, `contains`, `startswith`, `endswith`, `exists`, `gte`, `lte`, `in`.
- Action fields: `type`, `tool`, `url`, `domain`, `risk_score`, `route_target`, `args.*`, and `metadata.*`.
- Classifiers: `secrets`, `internal`, `source_internal`, `pii`, `credit_card`, `financial`, `unsafe_keywords`, and the `sql_*` classifiers from the runtime classifier.

Evaluation is first match wins in this order: `block`, `warn`, `monitor`, `allow`. Import the aggregate baseline for immediate coverage, or import topical packs selectively when you need a narrower rollout.
