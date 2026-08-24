# Provenance threat model

## Attack family

Ghostjacking-style attacks, MCP tool poisoning, indirect prompt injection, confused-deputy, cross-tool privilege escalation, and untrusted-content-triggered privileged actions.

```text
trusted user → agent → reads untrusted content → content influences agent
  → agent invokes privileged capability → sensitive effect
```

Individual calls may each look legitimate. The violation is the **authority flow** across the causal chain.

## Non-goals

- Varden does not claim to prevent all prompt injection.
- Varden does not read the model's mind to decide whether text "really caused" an action.
- Where the host cannot observe full causal context, provenance is marked incomplete / unknown — never trusted by default.

## Trust is not authentication

Authenticated ≠ trusted. Local ≠ trusted. Same-origin ≠ trusted. MCP server ≠ trusted. Tool description ≠ trusted. Tool output ≠ trusted.

## Confused deputy

Principal A influences the agent (deputy) to exercise authority belonging to B without a valid delegation from B.
