# Changelog

## Unreleased

### Runtime posture attestation

- Added `varden posture` and `varden posture --json`
- Varden now calculates an authoritative overall enforcement posture
- Separates attestation validity from coverage quality
- Reports structured enforcement gaps and available remediation
- MCP applicability: `NOT_ROUTED` only affects posture when MCP is discovered, required, or gateway-enforced
- Agent Security Skill now consumes Varden posture instead of deriving its own result

### Added — Varden Security Agent Skill

- Agent-native Varden installation and verification workflow (`skills/varden-security`)
- Explicit coverage-aware security posture reporting guidance
- MCP routing and verification guidance
- Provenance/authority inspection workflow
- Hard rules preventing agents from bypassing Varden decisions or fabricating approvals
- Packaged with Varden releases (`varden/skills/…` + root `skills/…`)
- CLI: `varden skill path`, `varden skill install --target <dir>`
- CLI: `varden runtime readiness --json` (machine-readable readiness)
- Note: `varden coverage --json` was already supported; the skill prefers `varden posture --json` when available
