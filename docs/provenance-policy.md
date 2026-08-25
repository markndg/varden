# Provenance policy

Pack: `policy-packs/provenance-authority-defense.json`

Import via the Rules workspace or API `POST /policy/import-pack` with `pack_id=provenance-authority-defense`.

## Predicates

Enrichment writes fields PolicyEngine already understands:

- `classifier:provenance_untrusted`
- `classifier:provenance_unknown`
- `classifier:authority_violation` / `authority_escalation`
- `classifier:confused_deputy`
- `classifier:exfiltration_chain`
- `classifier:cross_server_flow`
- `classifier:untrusted_to_privileged`
- `metadata.authority.required` / `.granted` / `.missing` / `.violation`
- `metadata.flow.private_to_public` / `.secret_egress` / `.cross_origin` / `.cross_server`
- `metadata.provenance.trust` / `.complete` / `.source_type`

Existing policies remain valid. This pack is opt-in.
