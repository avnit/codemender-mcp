# Branch protection for `your-github-org/payment-service`

The security agent can push branches and open pull requests. It must never be
able to merge to `main` on its own. These settings enforce that.

Configure them in GitHub: **Settings > Branches > Add branch protection rule**
(classic rules), or **Settings > Rules > Rulesets > New branch ruleset**. Menu
names change over time; confirm in your environment.

## Rule for `main`

Branch name pattern: `main`

| Setting | Value |
|---|---|
| Require a pull request before merging | On |
| Required approvals | 1 |
| Dismiss stale pull request approvals when new commits are pushed | On |
| Require review from Code Owners | On (uses `.github/CODEOWNERS`: `@your-github-org/security-reviewers`) |
| Require approval of the most recent reviewable push | On |
| Require status checks to pass before merging | On |
| Require branches to be up to date before merging | On |
| Required status checks | `validate` (job in `sandbox-validate`) and your unit test check, if you have one. A check appears in the list only after it has run once on the repo. |
| Require conversation resolution before merging | On |
| Do not allow bypassing the above settings (classic) / Bypass list empty (rulesets) | On / empty |
| Restrict who can push to matching branches | On: only `@your-github-org/security-reviewers` (or release maintainers) |
| Allow force pushes | Off |
| Allow deletions | Off |

## The agent's identity

The agent uses a fine-grained PAT (`ghp_REPLACE_ME`, stored in Secret Manager
as `github-mcp-pat`) or a GitHub App. Give it only:

- Repository access: `your-github-org/payment-service` only.
- Contents: Read and write (to push `security/<finding-id>-<slug>` branches).
- Pull requests: Read and write (to open PRs and comment).
- Actions: Read and write (to dispatch `sandbox-validate`), if the agent starts the workflow.
- Metadata: Read.

The agent's identity must not have:

- Admin or Maintain role on the repository or the organization.
- Any entry in the ruleset bypass list, or "allow specified actors to bypass required pull requests".
- Membership in `@your-github-org/security-reviewers` (otherwise its review could count as the code owner approval).
- Permission to change branch protection, rulesets, secrets, or workflows (`Administration` and `Workflows` permissions off).

## Check that it works

1. Using the agent's token, try to push directly to `main`. The push is rejected.
2. Open a PR from a `security/...` branch. The merge button is blocked until a
   code owner approves and `validate` passes.
3. Push a new commit to the PR. The earlier approval is dismissed.
