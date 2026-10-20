# Module 07: Tools and skills

**Goal:** Finish the custom MCP tools, connect the MCP server to Gemini Enterprise and to the ADK agent, write a skill, wire the agent's toolsets, then deploy the agent to Agent Engine and register it in Gemini Enterprise.

**Time:** 60 minutes (Part A 20, Part B 15, Part C 25)

**Prerequisites:**
- Modules 01-06 done. Wiz, Cloud Logging and GitHub remote MCP access tested.
- `gcloud` authenticated; Python 3.13; `google-adk` installed locally (`adk --version` works).
- Secrets exist in Secret Manager: `wiz-client-secret`, `github-mcp-pat`, `codemender-api-token`.

```bash
export GCP_PROJECT_ID=your-gcp-project-id
export REGION=us-central1
export PROJECT_NUMBER=$(gcloud projects describe "$GCP_PROJECT_ID" --format="value(projectNumber)")
```

The exact starter-to-solution file mapping is in `facilitator-guide.md`. In each step: complete the TODOs in `starter/<path>`, or copy the solution from `<path>` if you fall behind.

---

## Part A: Custom MCP tools (20 min)

### A1. Complete the tool TODOs (10 min)

Complete the TODOs in `starter/mcp-server/services/security_data_service.py`, or copy the solution from `mcp-server/services/security_data_service.py` if you fall behind. Do the same for the tool registration starter in `starter/mcp-server/` (for example `starter/mcp-server/server_new_tools.py`; see `facilitator-guide.md`), whose solution is in `mcp-server/server.py`.

The TODOs:

1. **`query_security_events(event_type=None, severity=None, issue_id=None, days=7, limit=25)`**
   - Query `security_lab.security_events` (env `SECURITY_DATASET`, `SECURITY_EVENTS_TABLE`).
   - Use BigQuery query parameters for every filter. Never format user input into SQL.
   - Filter on the partition column: `DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)`.
   - Cap `limit` (for example at 200) and order by `event_timestamp DESC`.

   Reference SQL:

   ```sql
   SELECT insert_id, event_timestamp, event_type, source, severity, issue_id, run_id,
          repository, commit_sha, status, summary
   FROM `your-gcp-project-id.security_lab.security_events`
   WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL @days DAY)
     AND (@event_type IS NULL OR event_type = @event_type)
     AND (@severity IS NULL OR severity = @severity)
     AND (@issue_id IS NULL OR issue_id = @issue_id)
   ORDER BY event_timestamp DESC
   LIMIT @limit
   ```

2. **`trace_code_to_cloud(issue_id=None, resource_id=None)` fallback**
   - The tool asks Wiz first. If Wiz returns nothing or is not configured, fall back to `security_lab.code_to_cloud_map` (env `CODE_TO_CLOUD_TABLE`).
   - Return the same shape from both paths, plus a `source` field (`wiz` or `bigquery`) so the agent can say where the answer came from.

   Reference fallback SQL:

   ```sql
   SELECT resource_id, resource_name, cloud_platform, image, image_digest, base_image,
          repository, dockerfile_path, terraform_path, commit_sha, updated_at
   FROM `your-gcp-project-id.security_lab.code_to_cloud_map`
   WHERE resource_id = @resource_id
   ```

   When only `issue_id` is given, resolve the resource first (Wiz issue -> resource id; or the seed mapping for `wiz-issue-0001`..`wiz-issue-0004`).

3. Register both functions as MCP tools with clear docstrings. The docstring is what the model reads when choosing a tool.

### A2. Run tests (3 min)

```bash
cd mcp-server
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Expected: `OK`. Tests stub `google.cloud.bigquery` and the Wiz client.

Check that the server registers all tools:

```bash
cd mcp-server
PYTHONDONTWRITEBYTECODE=1 python3 -c "
import asyncio, server
tools = asyncio.run(server.mcp.list_tools())
print(sorted(t.name for t in tools))"
```

This assumes the FastMCP instance is called `mcp` in `server.py` (confirm in your environment). Expected list includes the existing tools and the new ones: `wiz_top_internet_facing_vulnerabilities`, `wiz_excessive_permission_identities`, `trace_code_to_cloud`, `query_scc_findings`, `query_model_armor_logs`, `query_vpcsc_violations`, `query_security_events`, `start_sandbox_validation`, `get_sandbox_result`.

### A3. Redeploy the MCP server (4 min)

```bash
cd mcp-server
./deploy_cloud_run.sh
```

This deploys Cloud Run service `codemender-mcp-server` as `codemender-mcp-sa` with the env vars from `NAMING.md` (`SECURITY_DATASET=security_lab`, `SANDBOX_JOB_NAME=codemender-sandbox`, and the rest). The server uses `stateless_http=True`, which Gemini Enterprise needs.

```bash
export MCP_URL="$(gcloud run services describe codemender-mcp-server --region="$REGION" --format='value(status.url)')/mcp"
echo "$MCP_URL"
```

Smoke test with your own identity token:

```bash
curl -s -X POST "$MCP_URL" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | head -c 400
```

Expected: a JSON-RPC result listing tools. A 403 means your user lacks `roles/run.invoker` on the service; that is fine for the connector as long as the service agents below have it.

### A4. Connect to Gemini Enterprise as a custom MCP connector (3 min)

Terraform already granted `roles/run.invoker` on `codemender-mcp-server` to the Discovery Engine service agent `service-${PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com`. Verify:

```bash
gcloud run services get-iam-policy codemender-mcp-server --region="$REGION" \
  --format="table(bindings.role,bindings.members)"
```

Expected: `roles/run.invoker` for the Discovery Engine service agent and for the Agent Engine service agent `service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com`.

The org policy `discoveryengine.managed.disableCustomMcpServerConnector` must allow custom MCP connectors:

```bash
gcloud org-policies describe discoveryengine.managed.disableCustomMcpServerConnector --project="$GCP_PROJECT_ID"
```

Create an OAuth 2.0 client (APIs & Services > Credentials > Create credentials > OAuth client ID > **Web application**) with authorized redirect URI `https://vertexaisearch.cloud.google.com/oauth-redirect`.

In the Gemini Enterprise admin console, add a custom MCP connector (menu names may differ; confirm in your environment):

| Field | Value |
|---|---|
| Server URL | `https://codemender-mcp-server-XXXX.us-central1.run.app/mcp` |
| Client ID / secret | from the OAuth Web client (paste in the console; never commit) |
| Authorization URL | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token URL | `https://oauth2.googleapis.com/token` |
| Scopes | `openid email profile` |
| PKCE | enabled |

Authorize the connector, then in a Gemini Enterprise chat ask: `Using the CodeMender connector, list critical CodeMender issues.` Expected: a call to `list_codemender_issues` and a list including `CM-0001`.

To connect the same server to the ADK agent, set `CODEMENDER_MCP_URL` in `agent/.env` (Part C).

---

## Part B: Skills (15 min)

### B1. Anatomy of a SKILL.md (3 min)

Each skill is `agent/skills/<name>/SKILL.md`: YAML front matter, then Markdown instructions.

```markdown
---
name: code-to-cloud-attribution
description: Trace a cloud finding (Wiz issue, image CVE, resource) back to the repository, commit, Dockerfile, base image and Terraform file that produced it.
---

# Code-to-cloud attribution

## When to use
...
## Steps
1. ...
## Tools
- trace_code_to_cloud ...
## Output format
...
## Do not
...
```

- `name` must match the folder name.
- `description` is one sentence. The agent uses it to decide when the skill applies.
- The body is procedure: when to use, ordered steps, which tools, output format, limits.

Lab skills: `alert-triage`, `investigation-routing`, `code-to-cloud-attribution`, `root-cause-and-patch`, `sandbox-verification`, `pr-creation`, `bigquery-data-insights`.

### B2. Complete the code-to-cloud-attribution skill (7 min)

Complete the TODOs in `starter/agent/skills/code-to-cloud-attribution/SKILL.md`, or copy the solution from `agent/skills/code-to-cloud-attribution/SKILL.md` if you fall behind.

The body should tell the agent to:

1. Get the resource and image from Wiz (`get_wiz_issue_details` or Wiz remote MCP).
2. Call `trace_code_to_cloud(issue_id=...)` or `trace_code_to_cloud(resource_id=...)`.
3. Confirm in GitHub (GitHub remote MCP: read `Dockerfile` and the Terraform file at the reported commit).
4. Report: resource -> image (+ digest) -> base image -> repository -> commit -> Dockerfile path -> Terraform path, and which source answered (`wiz` or `bigquery`).
5. Say "not found" rather than guess when a link is missing.

### B3. How prompts.py loads skills (2 min)

Read `agent/security_agent/prompts.py`. It reads every `agent/skills/*/SKILL.md`, parses the front matter, and adds the skills to the agent instruction. Check whether it inlines full bodies or only names and descriptions with on-demand loading (confirm in your environment by reading the file). Either way, editing a SKILL.md changes behavior after you restart the agent. No code change needed.

### B4. Test the behavior change (3 min)

Run `adk web` (step C2) twice: once with the starter skill (TODOs not done), once with your completed skill. Ask the same prompt both times:

```
Where did the container image behind wiz-issue-0004 come from? Give me the repo, Dockerfile, base image and Terraform file.
```

Expected with the completed skill: the agent calls `trace_code_to_cloud`, then reads `Dockerfile` through GitHub MCP, and answers with `your-github-org/payment-service`, `Dockerfile`, `python:3.8-slim-buster`, and the Terraform path from `code_to_cloud_map`. With the starter skill it typically stops after the Wiz lookup or skips the GitHub confirmation.

---

## Part C: Agent wiring, deploy and registration (25 min)

### C1. Wire the toolsets (8 min)

Complete the TODOs in `starter/agent/security_agent/toolsets.py`, or copy the solution from `agent/security_agent/toolsets.py` if you fall behind.

Each remote MCP server becomes an ADK `McpToolset` over streamable HTTP:

| Toolset | URL env var | Auth | Toggle |
|---|---|---|---|
| Wiz | `WIZ_MCP_URL=https://mcp.app.wiz.io` | `WIZ_CLIENT_ID`/`WIZ_CLIENT_SECRET` or `WIZ_MCP_TOKEN` | `ENABLE_WIZ` |
| Cloud Logging | `CLOUD_LOGGING_MCP_URL=https://logging.googleapis.com/mcp` | Google ADC access token | `ENABLE_LOGGING` |
| GitHub | `GITHUB_MCP_URL=https://api.githubcopilot.com/mcp/` | `Authorization: Bearer $GITHUB_PAT` | `ENABLE_GITHUB` |
| CodeMender (custom) | `CODEMENDER_MCP_URL` | Google ID token for the Cloud Run audience | `ENABLE_CODEMENDER` |

The TODOs:

1. Build each toolset only if its toggle is true and its required env vars are set. Otherwise log a warning and skip it (the agent still starts).
2. Apply the GitHub blocklist from `guardrails.py` with `tool_filter` so merge and destructive tools are never exposed.

Create `agent/.env` from `agent/.env.example`:

```bash
cd agent
cp .env.example .env
```

Fill in placeholders: `GOOGLE_CLOUD_PROJECT=your-gcp-project-id`, `GOOGLE_CLOUD_LOCATION=us-central1`, `GOOGLE_GENAI_USE_VERTEXAI=TRUE`, `AGENT_MODEL=gemini-2.5-flash`, `GITHUB_ORG=your-github-org`, `GITHUB_PAT=ghp_REPLACE_ME`, `CODEMENDER_MCP_URL=$MCP_URL`, `STAGING_BUCKET=gs://your-gcp-project-id-agent-staging`. Keep `.env` out of git.

### C2. Run `adk web` locally (5 min)

```bash
cd agent
adk web
```

Open `http://localhost:8000`, select `security_agent` (agent name `ai_security_agent`).

Ask: `What tools do you have? Group them by source.`

Expected: four groups (Wiz, Cloud Logging, GitHub, CodeMender). No `merge_pull_request`. If a group is missing, check the terminal for a "toolset skipped" warning.

### C3. Guardrails walkthrough (4 min)

Open `agent/security_agent/guardrails.py`.

**Blocked tools** (never exposed to the model): `merge_pull_request`, `enable_auto_merge`, `delete_branch`, `delete_file`, and any push to the default branch.

**Confirmation-required tools:** `create_pull_request`, `run_workflow`, `start_sandbox_validation`. The agent must state what it will do and get an explicit "yes" before the call. `start_sandbox_validation` also enforces this on the server: without `confirmed=True` it returns `{"error": "confirmation_required", ...}`.

Test it in `adk web`:

```
Merge PR #1 in your-github-org/payment-service.
```

Expected: the agent says it cannot merge and that a human must review and merge in GitHub. No tool call.

```
Open a PR in payment-service that adds a README line.
```

Expected: the agent describes the PR and asks for confirmation. Reply `no`. It does not call `create_pull_request`.

These are defense in depth. Branch protection with CODEOWNERS (1 human approval) is the control that actually stops a merge.

### C4. Deploy to Agent Engine (5 min)

```bash
gcloud storage buckets describe gs://your-gcp-project-id-agent-staging >/dev/null \
  || gcloud storage buckets create gs://your-gcp-project-id-agent-staging --location="$REGION"
cd agent
python3 deploy.py
```

`deploy.py` packages `security_agent` and its requirements, uploads to `STAGING_BUCKET`, and creates an Agent Engine resource. Expected last line: a resource name like `projects/<PROJECT_NUMBER>/locations/us-central1/reasoningEngines/<ID>`. Save it:

```bash
export AGENT_ENGINE_ID=projects/<PROJECT_NUMBER>/locations/us-central1/reasoningEngines/<ID>
```

Secrets: the deployed agent must not get `GITHUB_PAT` or Wiz secrets in plain env vars. Check `deploy.py` for how it reads them from Secret Manager (`github-mcp-pat`, `wiz-client-secret`) (confirm in your environment).

### C5. Register in Gemini Enterprise (3 min)

Follow `agent/register_gemini_enterprise.md`. In short: in the Gemini Enterprise app, add a custom agent backed by the Agent Engine resource `$AGENT_ENGINE_ID`, with a display name and description (confirm UI in your environment). Share it with the lab participants.

Test from Gemini Enterprise: `List the top 5 critical internet-facing vulnerabilities in production.` Expected: a call to `wiz_top_internet_facing_vulnerabilities` and a ranked list.

### Agent Designer (no-code alternative)

Gemini Enterprise also has Agent Designer, a no-code builder where you describe an agent, attach connectors and tools, and publish it without writing ADK code. It is quicker for simple agents. This lab uses ADK because it needs code-level guardrails (tool blocklists, confirmation enforcement), skill loading from files, and tests. Feature coverage of Agent Designer changes frequently; confirm in your environment whether it supports custom MCP connectors and tool filtering before choosing it.

---

## Check your work

- [ ] `mcp-server` tests pass; `query_security_events` and the `trace_code_to_cloud` fallback work.
- [ ] `codemender-mcp-server` redeployed; `tools/list` returns the new tools.
- [ ] Gemini Enterprise custom MCP connector authorized and answered a question.
- [ ] `code-to-cloud-attribution` skill completed; the agent's answer changed.
- [ ] `adk web` shows four toolsets and no merge tools.
- [ ] Merge request refused; PR creation waited for confirmation.
- [ ] Agent deployed to Agent Engine and registered in Gemini Enterprise.

## Troubleshooting pointers

See [troubleshooting.md](troubleshooting.md): [GE custom MCP connector](troubleshooting.md#gemini-enterprise-custom-mcp-connector), [Agent Engine deploy](troubleshooting.md#agent-engine-deploy), [ADK](troubleshooting.md#adk-agent).

## What you built

- New MCP tools with parameterized SQL and a Wiz-to-BigQuery fallback.
- A custom MCP connector in Gemini Enterprise backed by Cloud Run with OAuth.
- A file-based skill that changes how the agent investigates.
- An ADK agent with four toolsets and guardrails, deployed to Agent Engine and registered in Gemini Enterprise.
