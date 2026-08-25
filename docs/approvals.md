# Scoped approvals

When policy returns `require_approval`:

1. Original attempt is **blocked** (no side effect).
2. A pending approval is created (`GET /approvals/pending`).
3. An operator approves (`POST /approvals/{id}/approve`) and receives a
   **single-use**, short-lived, action/resource/authority/trace-bound token.
4. Caller **retries the exact operation** with `metadata.approval_token`.
5. Boundary verifies and **consumes** the token; operation may proceed.
6. Replay of the same token fails.

Tokens are HMAC-signed with the server signing secret. Agents cannot self-mint
approvals. Client-asserted `approved=true` is ignored.

```bash
varden approvals pending
varden approvals approve <id>
varden approvals deny <id>
```
