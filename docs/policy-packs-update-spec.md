# Policy Packs Update Spec (items 1–6)

Implementation spec for merging host-shell into baseline, dual-path shell.execute rules, three new packs, and network/prompt-injection extensions. **Apply these JSON changes in agent mode** (plan mode blocks direct edits to `policy-packs/*.json`).

---

## 1. Baseline — fold in host-shell-safety

Add to `baseline-operational-safety.json` **block** array (after `baseline_block_kubectl_delete`):

```json
{
  "title": "Block recursive delete via host monitor",
  "name": "baseline_host_block_rm_rf",
  "enabled": true,
  "priority": 100,
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "rm -rf" },
  "description": "Blocks rm -rf from varden session/monitor shells."
},
{
  "title": "Block Terraform destroy via host monitor",
  "name": "baseline_host_block_terraform_destroy",
  "enabled": true,
  "priority": 100,
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "terraform destroy" },
  "description": "Blocks terraform destroy from monitored shells."
},
{
  "title": "Block kubectl delete all-namespaces via host monitor",
  "name": "baseline_host_block_kubectl_delete_all_namespaces",
  "enabled": true,
  "priority": 95,
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "kubectl delete" },
  "field:args.argv": { "contains": "--all-namespaces" },
  "description": "Blocks cluster-wide kubectl delete from monitored shells."
}
```

Add to **warn** array:

```json
{
  "title": "Warn on Railway CLI via host monitor",
  "name": "baseline_host_warn_railway_cli",
  "enabled": true,
  "priority": 60,
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "railway" },
  "description": "Warns when Railway CLI is invoked under monitor."
},
{
  "title": "Warn on curl from host monitor",
  "name": "baseline_host_warn_curl",
  "enabled": true,
  "priority": 45,
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "curl " },
  "description": "Warns on outbound curl from monitored shells."
}
```

Add `shell.execute` to `baseline_warn_shell_execution` tool `in` list.

Update description to mention host-shell/monitor coverage.

---

## 2. Dual-path shell.execute mirrors

For each pack below, duplicate key **block** and **warn** rules that use `field:args.args` with a sibling rule:

- `"tool": "shell.execute"`
- `"field:args.argv_join": { "contains": "<same substring>" }`
- `"name": "<original_name>_shell_execute"`

### credential-and-identity-abuse.json

Mirror all 6 block rules + 4 warn rules that use `field:args.args`.

### destructive-tools-and-infra.json

Mirror block rules: rm -rf, format c:, terraform destroy, kubectl delete, helm uninstall, terminate-instances, aws s3 rm, push --force, npm unpublish.

Add `shell.execute` to warn/monitor shell tool lists.

### supply-chain-and-ci-integrity.json

Mirror: curl (pipe sh via argv_join `| sh`), wget (`| bash`), preinstall, package-lock.json, GITHUB_TOKEN, publish+secrets.

For curl-pipe-shell shell variant:

```json
{
  "title": "Block curl-pipe-shell via host monitor",
  "name": "block_curl_pipe_shell_shell_execute",
  "type": "tool_call",
  "tool": "shell.execute",
  "field:args.argv_join": { "contains": "curl" },
  "field:args.argv_join": { "contains": "| sh" }
}
```

Note: duplicate keys invalid in JSON — use single argv_join `{ "contains": "| sh" }` plus separate rule with `{ "contains": "curl" }` OR one rule with argv_join containing `| sh` only (curl pipe patterns usually include both in argv_join string).

---

## 3. NEW: deployment-cli-safety.json

See full file content in agent-mode apply (vercel/fly/supabase/render/railway/docker/terraform/kubectl rules).

---

## 4. NEW: llm-cost-governance.json

Template includes `budget_rules` array with session/daily/monthly caps. Requires TokenBudgetRule engine from `docs/token-budget-plan.md`.

---

## 5. Network + prompt-injection extensions

### network-egress-and-tunnels.json — add blocks:

- Azure metadata: `metadata.azure.com`
- Localhost SSRF: `127.0.0.1`, `localhost`
- Webhook testers: `webhook.site`, `requestbin`, `pipedream`

### agent-prompt-injection.json — add:

**Block:**
- `developer mode` (llm_call)
- `<system>` override
- `disregard all prior`
- `base64` + `decode` injection combo (warn tier if too broad)

**Warn:**
- `DAN mode`
- `<!--` HTML comment injection
- `` ```system `` markdown fence override

Mirror same rules into baseline-operational-safety.json with `baseline_` prefix.

---

## 6. NEW: mcp-server-safety.json

Rules targeting MCP tools: `varden_guard`, `varden_put_policy`, `varden_log_event`, `varden_get_policy`.

Block: destructive guard payloads, secrets classifier on guard, rm -rf in guard args, metadata SSRF in guard args.

Warn: put_policy, log_event bypass, high risk guard, http_request in guard args.

Monitor: all varden_guard and varden_get_policy calls.

---

## Tests to update (tests/test_policy_packs.py)

Add to `expected` set:
- `credential-and-identity-abuse.json` (already missing!)
- `supply-chain-and-ci-integrity.json` (already missing!)
- `deployment-cli-safety.json`
- `llm-cost-governance.json`
- `mcp-server-safety.json`

Add representative cases:

```python
("deployment-cli-safety.json", Action(type="tool_call", tool="shell.execute", args={"argv_join": "supabase db reset --linked"}), "block"),
("mcp-server-safety.json", Action(type="tool_call", tool="varden_put_policy", args={}), "warn"),
("network-egress-and-tunnels.json", Action(type="http_request", url="http://127.0.0.1:8080/admin"), "block"),
```

---

## README update (policy-packs/README.md)

Add entries for deployment-cli-safety, llm-cost-governance, mcp-server-safety. Note baseline now includes host-shell rules. Note dual-path shell.execute coverage.

---

## Apply command

Switch to **agent mode** and ask: "apply policy-packs-update-spec.md"
