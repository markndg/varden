# Provenance limitations

- If Varden cannot observe host causal context, it cannot know exactly which model input caused a tool call. Those actions are marked `provenance_complete=false` / unknown — not trusted.
- Shell command parsing is intentionally imperfect; shell interpreters elevate required authority.
- Browser extension observation remains an untrusted sensor (see Web Shield limitations); taint from Web Shield findings does propagate into later guarded actions.
- LLM transformation never clears provenance or elevates trust.
- Client-supplied delegation / trust / approval assertions are not authoritative.
