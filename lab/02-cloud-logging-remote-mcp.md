# 02 - Cloud Logging remote MCP

**Goal:** Enable the Cloud Logging remote MCP server, use it from the ADK agent, and register it in Gemini Enterprise as a custom MCP connector with OAuth.

**Time:** 30 minutes

**Prerequisites:**
- [01 Wiz remote MCP](01-wiz-remote-mcp.md) done. `adk web` runs locally.
- `source lab.env` works, and `gcloud auth application-default login` is done.
- Gemini Enterprise admin access, for step 5.

## Facts you need

| Item | Value |
|---|---|
| Endpoint | `https://logging.googleapis.com/mcp` |
| Transport | Streamable HTTP |
| Auth | Google OAuth 2.0 access token (`Authorization: Bearer ...`) |
| Tools | `list_log_entries`, `list_log_names` |
| Scope per call | One resource project per call. To search two projects, make two calls. |

## Steps

### 1. Enable the API and the MCP endpoint

```bash
source lab.env
gcloud services enable logging.googleapis.com --project "$GCP_PROJECT_ID"
gcloud beta services mcp enable logging.googleapis.com --project "$GCP_PROJECT_ID"
```

The second command turns on the remote MCP endpoint for the service. Its exact form may change while the feature is in preview (confirm in your environment). If `gcloud beta services mcp` is not recognized, run `gcloud components update`, then check the Cloud Logging MCP documentation for the current enablement step.

Check:

```bash
gcloud beta services mcp list --project "$GCP_PROJECT_ID"
```

Expected: `logging.googleapis.com` is in the list (confirm in your environment).

### 2. IAM

The identity that calls the MCP server needs:

- `roles/logging.viewer` on the project, to read log entries and log names. Reading Data Access audit logs also needs `roles/logging.privateLogViewer`.
- A role that allows MCP tool calls on the project, if your environment requires one. Some previews use a dedicated MCP tool user role (confirm in your environment).

Grant yourself the viewer role for local testing:

```bash
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/logging.viewer" --condition=None
```

Terraform already grants `roles/logging.viewer` to the Agent Engine service agent `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com` and to `codemender-mcp-sa`.

### 3. Smoke-test the endpoint with curl

```bash
TOKEN="$(gcloud auth print-access-token)"
curl -s -X POST https://logging.googleapis.com/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Expected: a JSON-RPC result that lists `list_log_entries` and `list_log_names`. Some servers require an `initialize` call before `tools/list`. If you get an error that says so, use the agent test in step 4 instead.

### 4. Configure the toolset in the ADK agent

The agent connects with Streamable HTTP and a Google access token from `google.auth`. The code is in `agent/security_agent/`. The pattern is:

```python
import google.auth
import google.auth.transport.requests
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
creds.refresh(google.auth.transport.requests.Request())

logging_toolset = MCPToolset(
    connection_params=StreamableHTTPConnectionParams(
        url="https://logging.googleapis.com/mcp",
        headers={"Authorization": f"Bearer {creds.token}"},
    ),
    tool_filter=["list_log_entries", "list_log_names"],
)
```

Access tokens expire after about an hour. The agent code refreshes the token on each new session. A long `adk web` session may need a restart.

In `agent/.env`, set:

```bash
CLOUD_LOGGING_MCP_URL=https://logging.googleapis.com/mcp
ENABLE_LOGGING=true
ENABLE_WIZ=false
ENABLE_GITHUB=false
ENABLE_CODEMENDER=false
```

Start the agent:

```bash
cd agent && adk web
```

Ask: "List the log names in project your-gcp-project-id." Replace the placeholder with your project ID.

Expected: the agent calls `list_log_names` and lists log IDs such as `cloudaudit.googleapis.com%2Factivity`.

### 5. Register Cloud Logging MCP in Gemini Enterprise as a custom MCP connector

1. Check the org policy. Custom MCP connectors are blocked if `discoveryengine.managed.disableCustomMcpServerConnector` is enforced.

   ```bash
   gcloud org-policies describe discoveryengine.managed.disableCustomMcpServerConnector \
     --project "$GCP_PROJECT_ID" --effective
   ```

   Expected: `enforce: false`, or no enforcement. If it is enforced, ask your org policy admin to set it to not enforced for this project. Exact output format: confirm in your environment.

2. Create an OAuth 2.0 client. In the Cloud console, go to **APIs & Services > Credentials > Create credentials > OAuth client ID**.
   - Application type: **Web application**
   - Name: `ge-cloud-logging-mcp`
   - Authorized redirect URI: `https://vertexaisearch.cloud.google.com/oauth-redirect`

   Copy the client ID and client secret. You paste them into the Gemini Enterprise form in the next step. Do not save them in any file. If the OAuth consent screen is not configured, set it to Internal first.

3. In the Gemini Enterprise console, open your app. Go to **Connected data stores** (or **Connectors**) > **Add** > **Custom MCP server** (confirm in your environment). Fill in:

   | Field | Value |
   |---|---|
   | Server URL | `https://logging.googleapis.com/mcp` |
   | Authentication | OAuth 2.0 |
   | Client ID / Client secret | From step 2 |
   | Authorization URL | `https://accounts.google.com/o/oauth2/v2/auth` |
   | Token URL | `https://oauth2.googleapis.com/token` |
   | Scopes | `openid email profile`. Add `https://www.googleapis.com/auth/logging.read` or `https://www.googleapis.com/auth/cloud-platform` if tool calls fail with insufficient scopes (confirm in your environment). |
   | PKCE | Enabled |

4. Save, then authorize when prompted. Each user authorizes with their own Google account. Calls run with that user's Logging permissions.

5. In the Gemini Enterprise app chat, enable the connector and ask: "List log names in project your-gcp-project-id."

### 6. Write sample CodeMender logs

```bash
source lab.env
./seed-data/write_sample_logs.sh
```

Expected: the script writes entries to log `codemender` in your project with `gcloud logging write`. It prints one line per entry. Check:

```bash
gcloud logging read 'logName="projects/'"$GCP_PROJECT_ID"'/logs/codemender"' \
  --freshness=1h --limit=5 --format='value(timestamp,severity,jsonPayload.event_type)'
```

Expected: entries with `event_type` values such as `CODEMENDER_SCAN_STARTED`, `CODEMENDER_FINDING`, and `CODEMENDER_SCAN_COMPLETED`, and at least one `ERROR`.

## Exercises

Run these with `ENABLE_LOGGING=true` in `adk web`, or in Gemini Enterprise with the connector. For each one, open the tool call in the event panel and compare the `filter` the agent sent with the expected filter.

### Exercise 1: "Show CodeMender errors in the last hour for payment-service"

Expected tool: `list_log_entries`, for project `your-gcp-project-id`.

Expected filter (Logging query language), with the timestamp set to one hour ago:

```
logName="projects/your-gcp-project-id/logs/codemender"
severity>=ERROR
jsonPayload.repository="your-github-org/payment-service"
timestamp>="2026-10-20T13:00:00Z"
```

Separate lines are joined with AND. A looser filter is fine if it returns the same entries, for example `jsonPayload.repository:"payment-service"`.

Check: the answer lists only `ERROR` entries or worse, all for `payment-service`, all from the last hour.

### Exercise 2: "Who changed IAM on payment-service-sa today?"

First, make a change for the agent to find. If `payment-service-sa` does not exist in your project, create it with no roles:

```bash
gcloud iam service-accounts create payment-service-sa --display-name="payment-service (lab)" 2>/dev/null || true
SA="payment-service-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
ME="$(gcloud config get-value account)"
gcloud iam service-accounts add-iam-policy-binding "$SA" \
  --member="user:$ME" --role="roles/iam.serviceAccountTokenCreator"
gcloud iam service-accounts remove-iam-policy-binding "$SA" \
  --member="user:$ME" --role="roles/iam.serviceAccountTokenCreator"
```

Wait one to two minutes, then ask the agent.

There are two kinds of IAM change. Expected filters:

Changes to the policy on the service account itself (who can use or impersonate it):

```
logName="projects/your-gcp-project-id/logs/cloudaudit.googleapis.com%2Factivity"
protoPayload.serviceName="iam.googleapis.com"
protoPayload.methodName="google.iam.admin.v1.SetIAMPolicy"
protoPayload.resourceName:"payment-service-sa@your-gcp-project-id.iam.gserviceaccount.com"
timestamp>="2026-10-20T07:00:00Z"
```

Project role grants to the service account (what it can do):

```
logName="projects/your-gcp-project-id/logs/cloudaudit.googleapis.com%2Factivity"
protoPayload.methodName="SetIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.member:"serviceAccount:payment-service-sa@"
timestamp>="2026-10-20T07:00:00Z"
```

"Today" means since local midnight. The timestamp above is midnight Pacific in UTC. Exact `methodName` strings: confirm in your environment, by reading one entry with `gcloud logging read`.

Check: the answer names your account as `protoPayload.authenticationInfo.principalEmail`, shows the add and the remove with times, and names the role.

## Check your work

- The MCP endpoint is enabled for `logging.googleapis.com`.
- The agent with only `ENABLE_LOGGING=true` answers both exercises using `list_log_entries`.
- The Gemini Enterprise custom MCP connector is authorized and returns log names.
- You can explain why each call names exactly one project.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md). Common issues:
- `403 PERMISSION_DENIED`: missing `roles/logging.viewer`, the MCP endpoint is not enabled, or the token lacks a scope.
- Gemini Enterprise connector: `redirect_uri_mismatch` means the redirect URI on the OAuth client is not exactly `https://vertexaisearch.cloud.google.com/oauth-redirect`.
- The connector option is missing in Gemini Enterprise: the org policy is enforced.
- No results: check the time range, and check that `write_sample_logs.sh` wrote to the same project.

## What you built

The Cloud Logging MCP endpoint, enabled and reachable from the ADK agent with a `google.auth` token, and registered in Gemini Enterprise as a per-user OAuth custom MCP connector. Sample `codemender` logs, and two investigation queries checked against expected filters.
