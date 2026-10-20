# 03 - GitHub remote MCP

**Goal:** Push the sample app to GitHub, protect its main branch, connect the agent to the GitHub remote MCP server with a scoped token, and have the agent start a CodeMender scan only after you confirm.

**Time:** 35 minutes

**Prerequisites:**
- [02 Cloud Logging remote MCP](02-cloud-logging-remote-mcp.md) done.
- Terraform phase 2 applied. You need its outputs for the WIF provider and the service account.
- GitHub org admin rights in `your-github-org`, and `gh auth login` done.
- `source lab.env` works.

## Steps

### 1. Push the sample app to `your-github-org/payment-service`

`sample-app/` is intentionally vulnerable. Create the repo as private.

```bash
source lab.env
gh repo create "$GITHUB_ORG/payment-service" --private --description "Lab: intentionally vulnerable payment service"
cp -R sample-app ~/payment-service
cd ~/payment-service
git init -b main
git add .
git commit -m "Initial import of lab sample app"
git remote add origin "https://github.com/$GITHUB_ORG/payment-service.git"
git push -u origin main
```

Expected: `branch 'main' set up to track 'origin/main'`. On GitHub, the repo shows `app/`, `tests/poc/`, `patches/`, and `.github/workflows/codemender-scan.yml` and `sandbox-validate.yml`.

The copy keeps the sample app's git history separate from the lab repo.

### 2. Set CODEOWNERS and branch protection

Follow [sample-app/docs/branch-protection.md](../sample-app/docs/branch-protection.md). In short:

1. In the CODEOWNERS file, replace the placeholder team or user with a real reviewer in your org. That reviewer must not be the token owner from step 3. Commit and push.
2. Protect `main`:
   - Require a pull request before merging, with 1 approval.
   - Require review from Code Owners.
   - Dismiss stale approvals when new commits are pushed.
   - Do not allow bypassing the above settings.
   - Block force pushes and deletions.

Check:

```bash
gh api "repos/$GITHUB_ORG/payment-service/branches/main/protection" \
  --jq '.required_pull_request_reviews | {count: .required_approving_review_count, codeowners: .require_code_owner_reviews}'
```

Expected: `{"codeowners":true,"count":1}`.

### 3. Create a fine-grained PAT for the agent

On GitHub, go to **Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token**.

| Setting | Value |
|---|---|
| Name | `ai-security-agent-payment-service` |
| Resource owner | `your-github-org` (an org admin may need to approve the token) |
| Expiration | Lab end date, 7 days at most |
| Repository access | Only select repositories: `payment-service` |
| Contents | Read and write |
| Pull requests | Read and write |
| Actions | Read and write (to dispatch `codemender-scan.yml`) |
| Metadata | Read (required, set automatically) |
| Administration | No access |
| All others | No access |

Without Administration access, the token cannot change branch protection. Contents write is still blocked from `main` by branch protection, so the agent has to work on a branch and open a PR.

Store the token in Secret Manager `github-mcp-pat`, which Terraform creates:

```bash
read -s -p "GitHub PAT: " GH_PAT_INPUT; echo
printf '%s' "$GH_PAT_INPUT" | gcloud secrets versions add github-mcp-pat --data-file=-
unset GH_PAT_INPUT
```

Expected: `Created version [1] of the secret [github-mcp-pat].` If the secret does not exist, run `gcloud secrets create github-mcp-pat --replication-policy=automatic` first.

**Alternative for Gemini Enterprise users:** use a GitHub OAuth App or GitHub App so each user authorizes as themselves. Register the app with callback URL `https://vertexaisearch.cloud.google.com/oauth-redirect`, then add a custom MCP connector in Gemini Enterprise. Server URL: `https://api.githubcopilot.com/mcp/`. Auth URL: `https://github.com/login/oauth/authorize`. Token URL: `https://github.com/login/oauth/access_token`. Whether the GitHub MCP server accepts tokens from your own OAuth App, and which scopes to request, is something to confirm in your environment. This lab uses the PAT through the agent.

### 4. Configure repo variables and secrets for the workflows

The workflows authenticate to GCP with Workload Identity Federation: pool `github-pool`, provider `github-provider`, service account `github-actions-sa`. Get the values from Terraform:

```bash
cd infra/terraform
terraform output
```

Find the outputs for the WIF provider resource name, the `github-actions-sa` email, and the sandbox bucket. Output names are listed in [infra/terraform/README.md](../infra/terraform/README.md). Then set the repo variables. Replace each `<output>` with the matching output name:

```bash
R="$GITHUB_ORG/payment-service"
gh variable set GCP_WIF_PROVIDER --repo "$R" --body "$(terraform output -raw <wif_provider_output>)"
gh variable set GCP_SA_EMAIL     --repo "$R" --body "$(terraform output -raw <github_actions_sa_output>)"
gh variable set GCP_PROJECT_ID   --repo "$R" --body "$GCP_PROJECT_ID"
gh variable set GCP_REGION       --repo "$R" --body "$REGION"
gh variable set SANDBOX_BUCKET   --repo "$R" --body "$SANDBOX_BUCKET"
cd ../..
gh variable list --repo "$R"
```

Expected: five variables. `GCP_WIF_PROVIDER` looks like `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider`.

Optional, only if you have a CodeMender endpoint. `gh secret set` prompts for the value and does not echo it:

```bash
gh secret set CODEMENDER_API_URL --repo "$R"
gh secret set CODEMENDER_API_TOKEN --repo "$R"
```

If you skip this, `codemender-scan.yml` runs in mock mode and emits seed findings `CM-0001` to `CM-0004`. CodeMender has no public API. See the README section "About CodeMender".

### 5. Configure the GitHub MCP toolset in the agent

| Item | Value |
|---|---|
| Endpoint | `https://api.githubcopilot.com/mcp/` |
| Auth header | `Authorization: Bearer <PAT>` |
| Toolset selection | Header `X-MCP-Toolsets`, for example `repos,pull_requests,actions` (confirm in your environment) |
| Read-only mode | Header `X-MCP-Readonly: true` (confirm in your environment). Not used here: the agent needs to open PRs and dispatch workflows. |

The agent also filters tools on its side. `merge_pull_request`, `enable_auto_merge`, `delete_branch`, `delete_file`, and pushes to the default branch are excluded. `create_pull_request` and `run_workflow` require your confirmation in chat.

In `agent/.env`, set:

```bash
GITHUB_MCP_URL=https://api.githubcopilot.com/mcp/
GITHUB_ORG=your-github-org
ENABLE_GITHUB=true
ENABLE_LOGGING=true
ENABLE_WIZ=false
ENABLE_CODEMENDER=false
```

Export the PAT for this shell only. Do not put it in `agent/.env`:

```bash
export GITHUB_PAT="$(gcloud secrets versions access latest --secret=github-mcp-pat)"
cd agent && adk web
```

## Exercises

### Exercise 1: read the repo

Ask:

> List open pull requests in your-github-org/payment-service, then show me app/db.py.

Expected: the agent calls a pull request list tool, such as `list_pull_requests`, and `get_file_contents` with `path: app/db.py`. There are no open PRs yet. The file content includes a query built with string formatting. That is the SQL injection behind `CM-0001`.

### Exercise 2: start a CodeMender scan in mock mode

Ask:

> Run the CodeMender scan workflow on payment-service main in mock mode.

Expected:

1. The agent does not dispatch yet. It shows what it will run: workflow `codemender-scan.yml`, ref `main`, input `mode=mock`. Then it asks you to confirm.
2. Reply `yes`. The agent calls `run_workflow`.
3. Check the run:

   ```bash
   gh run list --repo "$GITHUB_ORG/payment-service" --workflow codemender-scan.yml --limit 1
   gh run watch --repo "$GITHUB_ORG/payment-service" "$(gh run list --repo "$GITHUB_ORG/payment-service" --workflow codemender-scan.yml --limit 1 --json databaseId -q '.[0].databaseId')"
   ```

   Expected: the run completes with `success`.

4. Check the `codemender` log entries:

   ```bash
   gcloud logging read 'logName="projects/'"$GCP_PROJECT_ID"'/logs/codemender" AND jsonPayload.repository="'"$GITHUB_ORG"'/payment-service"' \
     --freshness=30m --limit=10 --format='value(timestamp,severity,jsonPayload.event_type,jsonPayload.issue_id)'
   ```

   Expected: `CODEMENDER_SCAN_STARTED`, four `CODEMENDER_FINDING` entries (`CM-0001` to `CM-0004`), and `CODEMENDER_SCAN_COMPLETED`.

5. Also ask the agent: "Show the CodeMender log entries from that scan." It should use `list_log_entries` from module 02.

The workflow also uploads a source tarball to `gs://your-gcp-project-id-sandbox-inputs/sources/your-github-org__payment-service/<commit_sha>.tar.gz`. Module 04 uses it.

### Exercise 3: the guardrail blocks a merge

1. Create a test PR yourself:

   ```bash
   cd ~/payment-service
   git checkout -b lab/guardrail-test
   echo "" >> README.md && git commit -am "Guardrail test" && git push -u origin lab/guardrail-test
   gh pr create --fill --base main
   ```

2. Ask the agent:

   > Merge the guardrail test pull request into main.

   Expected: the agent says it cannot merge. It has no merge tool, and merging needs a human reviewer's approval. It may offer to summarize the PR or request a review.

3. Confirm the second layer. Try to merge without approval:

   ```bash
   gh pr merge lab/guardrail-test --squash
   ```

   Expected: GitHub refuses. The message says the base branch policy requires an approving review (the exact text varies).

4. Close the PR: `gh pr close lab/guardrail-test --delete-branch`.

## Check your work

- `your-github-org/payment-service` exists, is private, and `main` requires 1 Code Owner approval.
- `github-mcp-pat` has a version. The PAT covers only `payment-service` and has no Administration permission.
- Five repo variables are set.
- The agent read `app/db.py`, asked before dispatching `codemender-scan.yml`, and the run wrote `codemender` log entries.
- The merge request was refused by the agent and by branch protection.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md). Common issues:
- `401 Bad credentials` from GitHub MCP: the PAT expired, has a trailing newline, or is still waiting for org approval.
- `403 Resource not accessible by personal access token`: a permission is missing, for example Actions write for dispatch.
- The workflow fails at `google-github-actions/auth`: wrong `GCP_WIF_PROVIDER`, or the repo owner does not match the provider's `attribute_condition` (`assertion.repository_owner == "your-github-org"`).
- No log entries: `github-actions-sa` lacks `roles/logging.logWriter`, or the entries went to a different project.

## What you built

A private `payment-service` repo with CODEOWNERS and branch protection. A fine-grained PAT for one repo, stored in Secret Manager `github-mcp-pat`. Repo variables for WIF. A GitHub MCP connection from the agent that can read code and dispatch a scan after you confirm, but cannot merge.
