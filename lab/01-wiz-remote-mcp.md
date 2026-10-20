# 01 - Wiz remote MCP

**Goal:** Enable the Wiz remote MCP server, authenticate to it, and query it from the ADK agent. Then compare its answers with the custom MCP tool `wiz_top_internet_facing_vulnerabilities`.

**Time:** 35 minutes

**Prerequisites:**
- [00 Overview](00-overview.md) done, and `source lab.env` works.
- Terraform applied and `codemender-mcp-server` deployed (README quick start, steps 2-4).
- A Wiz admin is available for step 1.
- `agent/.env` created from `agent/.env.example`.

## Steps

### 1. Enable the remote MCP server in Wiz (Wiz admin)

1. Sign in to the Wiz portal as a tenant admin.
2. Go to **Settings > Tenant > AI Features** (confirm in your environment; the menu path can differ by tenant version).
3. Turn on the remote MCP server option. The label may be "Wiz MCP Server" or similar (confirm in your environment).
4. Save.

The remote MCP endpoint is:

```
https://mcp.app.wiz.io
```

### 2. Choose an authentication method

Wiz MCP accepts two kinds of authentication (confirm in your environment):

| Method | Who it acts as | Use it for |
|---|---|---|
| Browser OAuth | The signed-in Wiz user, with that user's Wiz permissions | Interactive clients, and a Gemini Enterprise connector if Wiz supports one (step 7) |
| Service account (client ID + client secret) | A Wiz service account | The ADK agent and the custom MCP server. No browser in the loop. |

This lab uses a service account for the agent.

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

Add the secret value. `read -s` keeps it off the screen and out of shell history:

```bash
read -s -p "Wiz client secret: " WIZ_SECRET_INPUT; echo
printf '%s' "$WIZ_SECRET_INPUT" | gcloud secrets versions add wiz-client-secret --data-file=-
unset WIZ_SECRET_INPUT
```

Expected: `Created version [1] of the secret [wiz-client-secret].`

Do not pass the secret as a command-line argument, and do not write it to `lab.env` or `agent/.env`.

### 5. Give the custom MCP server the Wiz credentials

`codemender-mcp-server` reads the secret named by `WIZ_SECRET_NAME` (default `wiz-client-secret`) at startup. Terraform already gives `codemender-mcp-sa` `roles/secretmanager.secretAccessor` on that secret. Redeploy so the service picks up `WIZ_CLIENT_ID` and the new secret version:

```bash
cd mcp-server
WIZ_CLIENT_ID="$WIZ_CLIENT_ID" WIZ_SECRET_NAME=wiz-client-secret ./deploy_cloud_run.sh
cd ..
```

Expected: the script ends by printing the service URL, `https://codemender-mcp-server-XXXX.us-central1.run.app`. See [mcp-server/README.md](../mcp-server/README.md) for all flags.

### 6. Test Wiz MCP from the ADK agent, with only Wiz enabled

1. In `agent/.env`, set:

   ```bash
   WIZ_MCP_URL=https://mcp.app.wiz.io
   WIZ_CLIENT_ID=your-wiz-client-id
   ENABLE_WIZ=true
   ENABLE_LOGGING=false
   ENABLE_GITHUB=false
   ENABLE_CODEMENDER=false
   ```

   Leave `WIZ_CLIENT_SECRET` out of the file. Export it into the shell for this session only:

   ```bash
   export WIZ_CLIENT_SECRET="$(gcloud secrets versions access latest --secret=wiz-client-secret)"
   ```

   The agent exchanges the client ID and secret for a Wiz token and sends it to the MCP endpoint. The header and token flow are implemented in `agent/security_agent/`. Check the exact header format Wiz expects (confirm in your environment). If you already have a token, set `WIZ_MCP_TOKEN` instead.

2. Start the dev UI:

   ```bash
   cd agent
   adk web
   ```

   Expected: `ADK Web Server started` and a URL, `http://localhost:8000`.

3. Open http://localhost:8000 and select `security_agent`. Ask:

   > What are our top 5 critical internet-facing vulnerabilities in production right now?

4. Expected: in the event panel, the agent calls one or more Wiz MCP tools. The answer lists up to 5 findings, each with a CVE or issue name, severity `CRITICAL`, the affected resource, and why it counts as internet-facing. Tool names depend on what the Wiz MCP server exposes; the event panel shows them.

5. Stop the server with Ctrl+C. Then run `unset WIZ_CLIENT_SECRET`.

### 7. Test the custom MCP tool `wiz_top_internet_facing_vulnerabilities`

Call the tool directly on Cloud Run. From the repo root:

```bash
cat > /tmp/call_wiz_tool.py <<'EOF'
import asyncio, os, subprocess
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = os.environ["CODEMENDER_MCP_URL"]
TOKEN = subprocess.check_output(["gcloud", "auth", "print-identity-token"]).decode().strip()

async def main():
    async with streamablehttp_client(URL, headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
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

Then call the same tool through the agent. In `agent/.env`, set `ENABLE_WIZ=false` and `ENABLE_CODEMENDER=true`. Set `CODEMENDER_MCP_URL` to the service URL with `/mcp` appended. Run `adk web` and ask the same question. In the event panel, the agent should call `wiz_top_internet_facing_vulnerabilities`.

### 8. Gemini Enterprise: custom MCP connector vs ADK agent

There are two ways to put Wiz in front of Gemini Enterprise users.

**A. Wiz MCP as a Gemini Enterprise custom MCP connector.** Only if Wiz supports the OAuth flow that Gemini Enterprise custom MCP connectors use (confirm in your environment). In the Gemini Enterprise console, add a custom MCP server connector with URL `https://mcp.app.wiz.io` and the OAuth client details Wiz gives you. The redirect URI is `https://vertexaisearch.cloud.google.com/oauth-redirect`. The org policy `discoveryengine.managed.disableCustomMcpServerConnector` must allow custom connectors. Module 02 shows these settings in full for Cloud Logging.

**B. Wiz MCP through the ADK agent.** This is what you did in step 6. The agent holds the Wiz credential, and you register the agent in Gemini Enterprise in module 07.

| | A. GE custom MCP connector | B. Through the ADK agent |
|---|---|---|
| Identity at Wiz | Each user's own Wiz identity, via OAuth | The `gemini-security-agent` service account |
| Wiz permissions | Whatever the user can see in Wiz | The service account's read scopes, the same for every user |
| Instructions, skills | Gemini Enterprise's general assistant. No lab skills. | `ai_security_agent` instructions and skills (module 07) |
| Combining sources | Only with other connectors in the same chat | One agent combines Wiz, Logging, GitHub, BigQuery, and the sandbox |
| Guardrails | Connector-level only | Tool filters and confirmation for action tools |
| Audit trail at Wiz | Per user | One service account. Log the end user in the agent if needed. |

Use A for direct, per-user Wiz lookups. Use B for the investigation and remediation workflows in this lab.

## Exercise: remote Wiz MCP vs custom tool

1. Ask the same question once with only `ENABLE_WIZ=true` and once with only `ENABLE_CODEMENDER=true`:
   > What are our top 5 critical internet-facing vulnerabilities in production right now?
2. Record for each: which tools were called, how many results came back, and which fields each result had.
3. Answer:
   - Do the two lists match? If not, why? Common reasons: different definitions of "internet-facing", different handling of the `production` environment (project vs tag), and issues vs vulnerability findings.
   - Which answer cites the resource ID you need for code-to-cloud attribution (module 08)?
   - Which one is easier to keep stable for a scheduled report?

## Verify against your tenant's schema

The custom tools in `mcp-server/` use Wiz GraphQL fields that vary by tenant and API version. Before you trust the custom tool output, check these fields with `query_wiz_graphql` or the Wiz GraphQL explorer. Each one: verify against your tenant's schema.

- The `vulnerabilityFindings` query and its `filterBy` fields for severity (`severity` vs `vendorSeverity`).
- The internet exposure filter or field on the vulnerable asset (for example `hasWideInternetExposure`, `isAccessibleFromInternet`, or a network exposure object).
- The `production` environment filter: a project filter, an `environments` field, or a tag. `wiz_top_internet_facing_vulnerabilities(environment="production")` assumes one of these.
- `vulnerableAsset` subfields: `id`, `name`, `type`, `providerUniqueId`, `cloudPlatform`, `projects`.
- `issuesV2` vs `issues` for `list_wiz_issues`, and the `entitySnapshot` subfields.
- Identity and permission fields used by `wiz_excessive_permission_identities` (for example the excessive access or effective permissions finding types).
- Fields used by `trace_code_to_cloud`, such as container image to repository links. If they are missing, the tool falls back to BigQuery `security_lab.code_to_cloud_map`.

## Check your work

- `gcloud secrets versions list wiz-client-secret` shows at least one `enabled` version.
- With only `ENABLE_WIZ=true`, the agent answers the top-5 question using Wiz MCP tools.
- `python3 /tmp/call_wiz_tool.py` returns findings, not an authentication error.
- You can explain when to use a GE custom MCP connector and when to go through the agent.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md). Common issues:
- `401` or `403` from Wiz MCP: the MCP server is not enabled in the tenant, the service account lacks a scope, or the secret has a trailing newline. `printf '%s'` avoids the newline.
- The custom tool says Wiz is not configured: `WIZ_CLIENT_ID` was not passed to `deploy_cloud_run.sh`, or `codemender-mcp-sa` cannot read the secret.
- GraphQL errors such as `Cannot query field ...`: see the verify list above.

## What you built

A read-only Wiz service account, its secret stored in Secret Manager `wiz-client-secret`, a working Wiz MCP connection from the ADK agent, and a comparison between the remote Wiz MCP server and the custom `wiz_top_internet_facing_vulnerabilities` tool.
