# 01 - Wiz remote MCP

**Time:** 20 minutes

**Learning objectives**

- Store a read-only Wiz service account secret in Secret Manager.
- Connect the ADK agent to the Wiz remote MCP server and query it.
- Explain when to use a Gemini Enterprise custom MCP connector and when to go through the agent.

**Goal:** Enable the Wiz remote MCP server, authenticate to it, and query it from the ADK agent. Then compare its answers with the custom MCP tool `wiz_top_internet_facing_vulnerabilities`.

**Prerequisites:**
- [00 Overview](00-overview.md) done, and `source lab.env` works.
- Terraform applied and `wiz-mcp-server` + `codemender-mcp-server` deployed (README quick start, steps 2-4).
- A Wiz admin is available for step 1.
- `agent/.env` created from `agent/.env.example`.

In the 4-hour schedule, the Wiz admin does steps 1 and 3 before the lab and hands each participant the client ID and secret. Participants start at step 2 (read only) and do steps 4-6 and 8 hands-on.

## Steps

### 1. Enable the remote MCP server in Wiz (Wiz admin, optional if using `wiz-mcp-server` on Cloud Run)

1. Sign in to the Wiz portal as a tenant admin.
2. Go to **Settings > Tenant > AI Features** (confirm in your environment; the menu path can differ by tenant version).
3. Turn on the remote MCP server option if you also want to test Wiz's vendor-hosted MCP endpoint (`https://mcp.app.wiz.io`). Note: `wiz-mcp-server` on Cloud Run talks directly to the Wiz GraphQL API, so it works even if the vendor remote MCP toggle is off.
4. Save.

### 2. Choose an authentication method

| Method | Who it acts as | Use it for |
|---|---|---|
| Cloud Run Google ID token -> `wiz-mcp-server` | Caller authenticates to Cloud Run (`roles/run.invoker`); `wiz-mcp-server` (`wiz-mcp-sa`) reads `wiz-client-secret` from Secret Manager | Default in this repo for the ADK agent and Gemini Enterprise custom MCP connector |
| Service account direct to `https://mcp.app.wiz.io` | A Wiz service account (`WIZ_CLIENT_ID` + `WIZ_CLIENT_SECRET`) | Direct connection from the ADK agent to Wiz's vendor remote MCP endpoint |
| Browser OAuth to `https://mcp.app.wiz.io` | The signed-in Wiz user, with that user's Wiz permissions | Interactive clients, if Wiz supports your connector OAuth flow |

This lab uses a read-only Wiz service account stored in Secret Manager (`wiz-client-secret`) and mounted onto the dedicated `wiz-mcp-server` Cloud Run service.

### 3. Create a read-only Wiz service account (Wiz admin)

1. In Wiz, go to **Settings > Access Management > Service Accounts** (confirm in your environment).
2. Click **Add Service Account**. Name: `gemini-security-agent`. Type: custom integration (GraphQL API) (confirm in your environment).
3. Grant read scopes only:
   - `read:issues`
   - `read:vulnerabilities`
   - `read:resources`
   - `read:projects`

   These are the minimum scopes for the lab's queries (confirm in your environment). Do not grant any `write:` or `admin:` scope.
4. Copy the client ID. Copy the client secret: Wiz shows it only once.

Put the client ID in `lab.env`. It is an identifier, not a secret:

```bash
echo 'export WIZ_CLIENT_ID="your-wiz-client-id"' >> lab.env
source lab.env
```

### 4. Store the client secret in Secret Manager

Terraform creates the secret `wiz-client-secret`. Check that it exists:

```bash
gcloud secrets describe wiz-client-secret --format='value(name)'
```

Expected: `projects/<PROJECT_NUMBER>/secrets/wiz-client-secret`. If you get `NOT_FOUND`, create it:

```bash
gcloud secrets create wiz-client-secret --replication-policy=automatic
```

If this fails with `constraints/gcp.resourceLocations violated ... in [global]`, your organization restricts resource locations. Store the secret in your region instead:

```bash
gcloud secrets create wiz-client-secret \
  --replication-policy=user-managed --locations="$REGION"
```

`wiz-mcp-server/deploy_cloud_run.sh` handles this for you: it opens the location policy for the project when it can, and falls back to your region when it can't.

Add the secret value. `read -s` keeps it off the screen and out of shell history:

```bash
read -s -p "Wiz client secret: " WIZ_SECRET_INPUT; echo
printf '%s' "$WIZ_SECRET_INPUT" | gcloud secrets versions add wiz-client-secret --data-file=-
unset WIZ_SECRET_INPUT
```

Expected: `Created version [1] of the secret [wiz-client-secret].`

Do not pass the secret as a command-line argument, and do not write it to `lab.env` or `agent/.env`.

### 5. Deploy `wiz-mcp-server` on Cloud Run with the Wiz credentials

`wiz-mcp-server` mounts `wiz-client-secret` from Secret Manager as `WIZ_CLIENT_SECRET` at runtime. Terraform gives `wiz-mcp-sa` (and **not** `codemender-mcp-sa`) `roles/secretmanager.secretAccessor` on that secret. Deploy (or redeploy) `wiz-mcp-server` so it picks up `WIZ_CLIENT_ID` and the new secret version:

```bash
cd wiz-mcp-server
WIZ_CLIENT_ID="$WIZ_CLIENT_ID" WIZ_SECRET_NAME=wiz-client-secret ./deploy_cloud_run.sh
cd ..
```

Expected: the script ends by printing the service URL, `https://wiz-mcp-server-XXXX.us-central1.run.app`. Refresh `WIZ_MCP_URL` in your shell:

```bash
WIZ_SERVICE_URL="$(gcloud run services describe wiz-mcp-server --region "$REGION" --format='value(status.url)')"
export WIZ_MCP_URL="${WIZ_SERVICE_URL}/mcp"
echo "$WIZ_MCP_URL"
```

See [wiz-mcp-server/README.md](../wiz-mcp-server/README.md) for all flags.

### 6. Test Wiz MCP from the ADK agent, with only Wiz enabled

1. In `agent/.env`, point `WIZ_MCP_URL` at your deployed `wiz-mcp-server` Cloud Run endpoint:

   ```bash
   WIZ_MCP_URL=https://wiz-mcp-server-XXXX.us-central1.run.app/mcp
   ENABLE_WIZ=true
   ENABLE_LOGGING=false
   ENABLE_GITHUB=false
   ENABLE_CODEMENDER=false
   ```

   Because `WIZ_MCP_URL` is a `*.run.app` Cloud Run service, `wiz_toolset()` automatically mints a Google ID token (`audience=https://wiz-mcp-server-XXXX.us-central1.run.app`) and does not need `WIZ_CLIENT_SECRET` on your laptop.

   *(Alternative: to test Wiz's vendor-hosted endpoint directly instead, set `WIZ_MCP_URL=https://mcp.app.wiz.io`, `WIZ_CLIENT_ID=your-wiz-client-id`, and `export WIZ_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=wiz-client-secret)"` in your shell session only.)*

2. Start the dev UI:

   ```bash
   cd agent
   adk web
   ```

   Expected: `ADK Web Server started` and a URL, `http://localhost:8000`.

3. Open http://localhost:8000 and select `security_agent`. Ask:

   > What are our top 5 critical internet-facing vulnerabilities in production right now?

4. Expected: in the event panel, the agent calls `wiz_top_internet_facing_vulnerabilities` (or `list_wiz_issues`) on `wiz-mcp-server`. The answer lists up to 5 findings, each with a CVE or issue name, severity `CRITICAL`, the affected resource, and why it counts as internet-facing.

5. Stop the server with Ctrl+C (and `unset WIZ_CLIENT_SECRET` if you exported it).

Step 7 (calling `wiz-mcp-server` directly with a Python MCP client) is in [Optional / take-home](#optional--take-home).

### 8. Gemini Enterprise: custom MCP connector vs ADK agent

There are two ways to put Wiz in front of Gemini Enterprise users.

**A. `wiz-mcp-server` (or `mcp.app.wiz.io`) as a Gemini Enterprise custom MCP connector.** Because `wiz-mcp-server` runs on Cloud Run with stateless Streamable HTTP (`/mcp`), you can attach `https://wiz-mcp-server-XXXX.us-central1.run.app/mcp` directly as a Gemini Enterprise custom MCP connector using Google OAuth (`https://accounts.google.com/o/oauth2/v2/auth`, redirect URI `https://vertexaisearch.cloud.google.com/oauth-redirect`), exactly like `codemender-mcp-server` in Module 07 step A4! Terraform already grants `roles/run.invoker` on `wiz-mcp-server` to the Discovery Engine service agent.

**B. Wiz MCP through the ADK agent.** This is what you did in step 6. The agent calls `wiz-mcp-server` using its Agent Engine service agent ID token, and you register the agent in Gemini Enterprise in module 07.

| | A. GE custom MCP connector (`wiz-mcp-server`) | B. Through the ADK agent |
|---|---|---|
| Identity at Cloud Run | Gemini Enterprise Discovery Engine service agent + Google OAuth | Vertex AI Agent Engine service agent ID token |
| Wiz permissions | `wiz-mcp-sa` -> `gemini-security-agent` read scopes | Same `wiz-mcp-sa` -> `gemini-security-agent` read scopes |
| Instructions, skills | Gemini Enterprise's general assistant. No lab skills. | `ai_security_agent` instructions and skills (module 07) |
| Combining sources | Only with other connectors in the same chat | One agent combines Wiz, Logging, GitHub, CodeMender/BigQuery, and the sandbox |
| Guardrails | Connector-level only | Tool filters and confirmation for action tools |

Use A for direct Wiz Q&A in Gemini Enterprise. Use B for the multi-source investigation and remediation workflows in this lab.

## Check your work

- `gcloud secrets versions list wiz-client-secret` shows at least one `enabled` version.
- `gcloud run services describe wiz-mcp-server --region "$REGION"` shows the deployed Cloud Run URL running as `wiz-mcp-sa`.
- With only `ENABLE_WIZ=true`, the agent answers the top-5 question using `wiz-mcp-server` tools.
- You can explain when to use a GE custom MCP connector and when to go through the agent.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md). Common issues:
- `401` or `403` from Cloud Run `wiz-mcp-server`: your caller lacks `roles/run.invoker` on `wiz-mcp-server`, or local user ADC cannot mint an ID token with custom audience (impersonate a service account or test via `gcloud auth print-identity-token`).
- `wiz-mcp-server` says Wiz is not configured: `WIZ_CLIENT_ID` was not passed to `wiz-mcp-server/deploy_cloud_run.sh`, or `wiz-mcp-sa` cannot read `wiz-client-secret`.
- GraphQL errors such as `Cannot query field ...`: see "Verify against your tenant's schema" in [Optional / take-home](#optional--take-home).

## What you built

A read-only Wiz service account, its secret stored in Secret Manager `wiz-client-secret`, the dedicated `wiz-mcp-server` Cloud Run MCP service, and a working Wiz MCP connection from the ADK agent.

## Optional / take-home

These steps do not fit the 4-hour schedule. Do them after the lab, or during the buffer if you finish early. The tool `wiz_top_internet_facing_vulnerabilities` is used again in Module 08 Part 1.

### 7. Test `wiz-mcp-server` tool `wiz_top_internet_facing_vulnerabilities` directly

Call the tool directly on the `wiz-mcp-server` Cloud Run service. From the repo root:

```bash
cat > /tmp/call_wiz_tool.py <<'EOF'
import asyncio, os, subprocess
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ["WIZ_MCP_URL"]
TOKEN = subprocess.check_output(["gcloud", "auth", "print-identity-token"]).decode().strip()

async def main():
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with streamablehttp_client(URL, headers=headers) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(
                "wiz_top_internet_facing_vulnerabilities",
                {"environment": "production", "severity": "CRITICAL", "limit": 5},
            )
            for c in res.content:
                print(c.text)

asyncio.run(main())
EOF
source lab.env
python3 /tmp/call_wiz_tool.py
```

Expected: JSON with up to 5 items. Each item has a finding name or CVE, severity, the resource name and type, the project, and an internet exposure indicator. If Wiz is not configured, you get an error object that says so. That points to step 5.

### Exercise: vendor Wiz remote MCP (`mcp.app.wiz.io`) vs Cloud Run `wiz-mcp-server`

1. Ask the same question once with `WIZ_MCP_URL` pointing at `https://wiz-mcp-server-XXXX.us-central1.run.app/mcp` and once with `WIZ_MCP_URL=https://mcp.app.wiz.io`:
   > What are our top 5 critical internet-facing vulnerabilities in production right now?
2. Record for each: which tools were called, how many results came back, and which fields each result had.
3. Answer:
   - Do the two lists match? If not, why? Common reasons: different definitions of "internet-facing", different handling of the `production` environment (project vs tag), and issues vs vulnerability findings.
   - Which answer cites the resource ID you need for code-to-cloud attribution (module 08)?
   - Which one is easier to keep stable for a scheduled report?

### Verify against your tenant's schema

The tools in `wiz-mcp-server/` use Wiz GraphQL fields that vary by tenant and API version. Before you trust the tool output, check these fields with `query_wiz_graphql` or the Wiz GraphQL explorer. Each one: verify against your tenant's schema.

- The `vulnerabilityFindings` query and its `filterBy` fields for severity (`severity` vs `vendorSeverity`).
- The internet exposure filter or field on the vulnerable asset (for example `hasWideInternetExposure`, `isAccessibleFromInternet`, or a network exposure object).
- The `production` environment filter: a project filter, an `environments` field, or a tag. `wiz_top_internet_facing_vulnerabilities(environment="production")` assumes one of these.
- `vulnerableAsset` subfields: `id`, `name`, `type`, `providerUniqueId`, `cloudPlatform`, `projects`.
- `issuesV2` vs `issues` for `list_wiz_issues`, and the `entitySnapshot` subfields.
- Identity and permission fields used by `wiz_excessive_permission_identities` (for example the excessive access or effective permissions finding types).
- Fields used by `wiz_trace_code_to_cloud`, such as container image to repository links. If they are missing, the agent falls back to `trace_code_to_cloud` on `codemender-mcp-server` (BigQuery `security_lab.code_to_cloud_map`).
