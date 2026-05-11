# Contributing to Varden

Thanks for your interest in improving Varden.

## Ground rules
- Open an issue before large feature work.
- Keep pull requests focused and reviewable.
- Include tests for behavior changes.
- Do not remove existing OSS functionality without discussion.
- Preserve the self-hosted developer experience.

## Development
1. Create a virtual environment.
2. Install the package in editable mode.
3. Run the API locally.
4. Run the test suite before opening a pull request.

## Security

Do not file public issues for exploitable vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## GitHub settings (maintainers)

Use the [GitHub CLI](https://cli.github.com/) (`gh auth login`) for repeatable setup. Replace `REPO` if you fork under another owner.

### Bootstrap commands (idempotent)

```bash
REPO=markndg/varden

gh api -X PUT "repos/${REPO}/vulnerability-alerts"
gh api -X PUT "repos/${REPO}/automated-security-fixes"
gh api -X PUT "repos/${REPO}/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false

gh api -X PUT "repos/${REPO}/private-vulnerability-reporting"
gh repo edit "${REPO}" --enable-secret-scanning
gh repo edit "${REPO}" --enable-secret-scanning-push-protection

# Fork PRs: every external fork workflow run needs a maintainer to approve (saves CI abuse)
gh api -X PUT "repos/${REPO}/actions/permissions/fork-pr-contributor-approval" \
  -f approval_policy=all_external_contributors
```

Dependabot **version** updates are driven by [`.github/dependabot.yml`](.github/dependabot.yml).

### Default branch ruleset (`main`)

The canonical ruleset body lives in [`scripts/github-ruleset-main.json`](scripts/github-ruleset-main.json). It enforces:

- **Pull request required** to land changes on the default branch (no direct pushes), with **no bypass** for admins (`current_user_can_bypass: never` when created via API).
- **Required checks:** workflow jobs **`test`** and **`frontend`** (strict: branch must be up to date).
- **No force-push** and **no branch deletion** via the ruleset.

To **re-create** the ruleset after edits to that JSON file:

```bash
gh api -X POST repos/markndg/varden/rulesets --input scripts/github-ruleset-main.json
```

(If a ruleset with the same name already exists, remove it in **Settings → Rules → Rulesets** first, or adjust the JSON `name` field.)

**If `git push origin main` is rejected** (`push declined due to repository rule violations`), that is expected: `main` only accepts changes that arrive via **pull request**. Push a topic branch and open a PR, wait for **`test`** and **`frontend`**, then merge.

**One-time escape hatch** (e.g. you must land commits on `main` without a PR): list rulesets with `gh ruleset list -R markndg/varden`, delete the active ruleset by id, push, then re-apply from `scripts/github-ruleset-main.json` as above. Prefer the PR workflow whenever possible.

**Merge rights:** GitHub allows anyone with **write** access to merge an eligible PR. Today only **`markndg`** has admin/write on this repo, so only you can merge. If you add collaborators with **write** or **maintain**, they can merge too; keep external contributors at **triage** or **read** if you want merges to stay with you alone.

**Solo maintainer note:** the ruleset uses **`required_approving_review_count`: 0** so you can merge your own PRs after CI passes (a count of `1` would block you without a second reviewer). Reviews are still welcome for contributors.

### Optional UI checks

- **Settings → Actions → General:** consider narrowing **Allowed actions** from “all” if you want stricter supply-chain policy (ensure CI still has access to the actions it needs).
- **Settings → General:** Wikis stay disabled if unused.

## Licensing
By submitting a contribution, you agree that your contribution may be distributed
under the repository license.
