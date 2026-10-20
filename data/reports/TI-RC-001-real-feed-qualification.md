# TI-RC-001 — Real feed qualification

Date: 2026-10-08. Branch `feature/threat-intelligence`. HEAD `e3c58fe5577835b1d13512d9567c22e699140142` (uncommitted working tree). Isolated database `/tmp/ti-rc-001/ti.db`. The developer `varden.db` and `policy.json` were not used.

Machine-readable twin: `data/reports/TI-RC-001-real-feed-qualification.json`.

The product adapters fetched the official documents. Fixture files were not used as stand-ins for this run.

## MITRE ATLAS

| Check | Result |
| --- | --- |
| URL | `https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/stix-atlas.json` |
| Redirect | `release-assets.githubusercontent.com` (on the ATLAS allowlist) |
| TLS / pin | Default certificate verification. Connection uses the resolved global address. |
| Status | healthy, 1.111s |
| Version | `2026.09` |
| Techniques in the bundle | 208 |
| Normalised | 208 |
| Rejected | 0 |
| Mapped to a contract | 2 (`AML.T0051` LLM Prompt Injection, `AML.T0054` LLM Jailbreak → `untrusted-instruction-execution`) |
| REVIEW | 206 |
| Applicability on this host | the 2 mapped techniques are `NOT_APPLICABLE` (no agent surface is attested). 206 are `REVIEW`. |
| Candidates | 0 on this host |

206 of 208 techniques have no Varden contract. Examples left in `REVIEW`: `AML.T0010.005` AI Agent Tool, `AML.T0011.002` Poisoned AI Agent Tool, `AML.T0006.003` Probe AI Agent Trigger Channels. Those are real product gaps. They were not mapped in order to raise the count.

## NVD CVE API 2.0

| Denominator | Count | Meaning |
| --- | --- | --- |
| Upstream catalog (`totalResults` with `resultsPerPage=1`, no keyword) | 403,221 | Count probe only. One CVE body was returned by the API and was not ingested. |
| Product query | `keywordSearch=artificial intelligence`, `lastMod` window of 24 hours ending 2026-10-08T19:48:27Z | The configured retrieval filter. Not a scan of the catalog. |
| `totalResults` for that query | 1 | |
| Records retrieved and examined | 1 | `CVE-2025-59146` |
| Mapped to a contract | 0 | Weakness is `CWE-918`. That id is explicitly `REVIEW`. |
| REVIEW | 1 | SSRF is not turned into a blanket HTTP rule. |
| Candidates | 0 | |

`CVE-2025-59146` describes an authenticated SSRF in an LLM gateway. The keyword matched. That is not evidence the record is an agent-runtime technique Varden can enforce. The description was stored as data.

## CWE

| Check | Result |
| --- | --- |
| URL | `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` |
| Content-Type | `application/zip` |
| Catalog version | **4.20** |
| Weaknesses indexed | 969 |
| Promoted to threat items | 11 (the explicit binding table only) |
| Mapped to a contract | 8 |
| Explicit REVIEW | 3 (`CWE-287`, `CWE-306`, `CWE-918`) |
| Left in the index and not promoted | 958 |
| Applicability on this host | 8 `NOT_APPLICABLE`, 3 `REVIEW` |
| Candidates | 0 on this host |

Bound ids: `CWE-77`, `CWE-78`, `CWE-94` → `unexpected-code-execution`; `CWE-200`, `CWE-312`, `CWE-522`, `CWE-798` → `credential-exfiltration`; `CWE-269` → `privilege-amplification`.

## OWASP Agentic

| Check | Result |
| --- | --- |
| Adapter | `unsupported`. No fetch. |
| `https://owasp.org/www-project-top-10-for-large-language-model-applications/` | HTTP 200, `text/html` |
| `https://genai.owasp.org/` | HTTP 403 |

No authoritative machine-readable feed was found. HTML was not scraped. Status: **not consumed**.

## Coverage matrix

Denominators are separate. "Retrieved" is what the product query stored. "Catalog" is the upstream size measured above. Keyword overlap is not treated as confirmed agent relevance.

| Threat category | Source IDs seen | Contract | Runtime surfaces | Actionable on an enforced surface | Gap |
| --- | --- | --- | --- | --- | --- |
| Prompt injection | `AML.T0051`, `AML.T0054` | `untrusted-instruction-execution` | tools, mcp, subprocess, filesystem | Yes, when a required surface is `ENFORCED` and policy does not prove `classifier:provenance_untrusted` | 206 other ATLAS techniques, including agent-tool and supply-chain ids, stay `REVIEW` |
| Credential exposure | `CWE-200`, `CWE-312`, `CWE-522`, `CWE-798` | `credential-exfiltration` | http, mcp, filesystem | Yes, for an HTTP request the secrets classifier marks | Does not prove MCP or filesystem exfiltration. A rule on `http_request` does not cover those surfaces. |
| Command / code injection | `CWE-77`, `CWE-78`, `CWE-94` | `unexpected-code-execution` | subprocess, tools | Yes, for a tool call whose metadata says `execution_surface=subprocess` | Not every code-injection CVE will carry these CWE ids. Unmapped CWEs are not promoted. |
| Privilege management | `CWE-269` | `privilege-amplification` | tools, mcp | Yes, when `classifier:authority_escalation` is present | Authentication weaknesses `CWE-287` and `CWE-306` stay `REVIEW` |
| SSRF | `CWE-918`, and `CVE-2025-59146` which cites it | none (`REVIEW`) | http | No | A blanket HTTP rule would be false confidence |
| Tool misuse / poisoned tool | `AML.T0010.005`, `AML.T0011.002` | none | — | No | No deterministic binding |
| Memory poisoning | not in the ATLAS ids that mapped; OWASP `ASI06` is `REVIEW` only if a pinned JSON feed is configured | none | — | No | No memory surface Varden can prove |
| MCP abuse | no dedicated ATLAS/CWE id in the mapped set | none as its own contract | mcp appears only as a required surface on other contracts | No standalone control | MCP that is `NOT_ROUTED` stays a coverage gap, not a new rule |

On this workstation the live import produced **0 candidates**, because coverage attestation has no applicable agent surface. That is the correct cold-start result. Actionable means "a candidate can be generated when the relevant surface is `ENFORCED`", which the end-to-end run shows for `AML.T0051`.

## End to end

Official record: **AML.T0051**, title "LLM Prompt Injection", ATLAS `2026.09`, retrieved by `AtlasSource` in the live check.

The applicability step used a controlled installation fact (`tools=ENFORCED`, other required surfaces not applicable, observability present, empty policy). This host has no agent coverage attestation, so that posture was not read from a production runtime. The identifier, title, and description came from the live import.

| Step | Result |
| --- | --- |
| Normalised | `atlas:AML.T0051` |
| Contract | `untrusted-instruction-execution`, schema-valid |
| Applicability | `EXPOSED` |
| Candidate | `ti-untrusted-instruction-execution`, `require_approval` |
| Policy before approval | rule absent |
| Approval | admin actor `rc-qualification`, lifecycle `ENFORCED` |
| Live `PolicyEngine` | `tool_call` with `provenance_untrusted` → `require_approval` |
| Restart on the same policy file | same decision |
| Second approval | idempotent, rule count stayed 1 |

## Reproduce

```bash
python3 /tmp/ti-rc-001/qualify.py
```

The script is the one-shot runner used for this report. It writes `/tmp/ti-rc-001/qualification.json`. It needs outbound HTTPS to `github.com`, `release-assets.githubusercontent.com`, `cwe.mitre.org`, and `services.nvd.nist.gov`.
