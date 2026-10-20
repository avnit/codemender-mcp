# Branch protection for `payment-service`

The AI security agent may open pull requests. It must never merge them. These
settings make that a repository rule, not a convention: every change to `main`
needs one approving review from a human code owner.

Replace `your-github-org` with your org. UI labels change over time; confirm in
your environment.

## 1. Create the reviewer team

1. Org **Settings > Teams > New team**: `security-reviewers`.
2. Add the human reviewers. Do not add the agent's GitHub App, bot user, or the
   account that owns the agent's token (`github-mcp-pat`).
3. Repo **Settings > Collaborators and teams**: give `security-reviewers` the
   **Write** role.

`.github/CODEOWNERS` assigns every path to `@your-github-org/security-reviewers`.

## 2. Protect `main` (ruleset)

Repo **Settings > Rules > Rulesets > New ruleset > New branch ruleset**:

| Setting | Value |
|---------|-------|
| Ruleset name | `protect-main` |
| Enforcement status | Active |
| Bypass list | Empty (no apps, no bots, no roles) |
| Target branches | Include default branch |
| Restrict deletions | On |
| Block force pushes | On |
| Require a pull request before merging | On |
| Required approvals | 1 |
| Dismiss stale pull request approvals when new commits are pushed | On |
| Require review from Code Owners | On |
| Require approval of the most recent reviewable push | On |
| Require conversation resolution before merging | On |

With "Require approval of the most recent reviewable push" on, the person who
pushed the last commit cannot be the approver. If the agent pushes the fix
branch, a different, human account must approve.

Classic branch protection (**Settings > Branches > Add rule**, pattern `main`)
has the same options if your plan does not support rulesets. Also enable
**Do not allow bypassing the above settings**.

## 3. Status checks (optional)

`sandbox-validate` runs on `workflow_dispatch`, not on `pull_request`, so it
does not report a check on the PR head commit and cannot be a required status
check as written. The workflow posts its verdict as a PR comment (when run with
`branch`) and in the job summary. Reviewers confirm the verdict is
`PATCH_VERIFIED` before approving (see the PR template checklist).

## 4. Limit the agent's token

- Use a fine-grained PAT (stored in Secret Manager as `github-mcp-pat`, value
  `ghp_REPLACE_ME` in examples) scoped to `payment-service` only, with
  Contents: Read and write, Pull requests: Read and write, Actions: Read and
  write (to dispatch `sandbox-validate`), Metadata: Read.
- Do not grant Administration. Without it the token cannot change these rules.
- Branch protection, not token scope, is what blocks the merge: a token with
  Contents write can call the merge API, and the ruleset rejects it until a
  code owner approves.

## 5. Check it works

1. As the agent (or with its token), open a PR from a fix branch.
2. Confirm the PR shows "Review required" and "Merging is blocked".
3. Try to merge with the agent's token, e.g. `gh pr merge <number> --squash`.
   It must fail.
4. Approve as a member of `security-reviewers` and merge.
