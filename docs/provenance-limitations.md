# Provenance limitations

- If Varden cannot observe host causal context, it cannot know exactly which model input caused a tool call. Those actions are marked `provenance_complete=false` / unknown — not trusted.
- Shell command parsing is intentionally imperfect; shell/script interpreters and unknown executables elevate required authority.
- Browser extension observation remains an untrusted sensor (see Web Shield limitations); taint from Web Shield findings does propagate into later guarded actions when they hit `/sdk/guard` or Web Shield `_log_event`.
- LLM transformation never clears provenance or elevates trust.
- Client-supplied delegation / trust / approval / `user_intent_integrity` assertions are not authoritative. Verified user delegation is process-local (`server_verified_user` / store-backed `Delegation`) only.
- `/sdk/log` is observational and does not evaluate policy. Privileged side effects must call `/sdk/guard` first.
- MCP tools outside `varden_guard` are not automatically intercepted — authority-flow cannot protect calls that never reach the control plane.
- `varden session` passive / observe modes and LangChain callback-only installs are observational; they do not stop execution.
- `require_approval` on the SDK guard path currently fails closed (403) until scoped, non-replayable server approval tokens exist. Web Shield has its own approval state machine; blocked/pending registrations are stored as `rejected` / `pending_approval`, not `active`.
- `mode=enforce` defaults to `fail_mode=closed`. Explicit `fail_mode=open` under enforce is supported but emits a warning — it weakens enforcement when the control plane is unreachable.
