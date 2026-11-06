# Wiz Security MCP Server (`wiz-mcp-server/`)

A dedicated Model Context Protocol (MCP) server deployed on Google Cloud Run as `wiz-mcp-server` (running under least-privilege service account `wiz-mcp-sa`). The lab's ADK security agent (`ai_security_agent`) and Gemini Enterprise invoke it over IAM-authenticated Streamable HTTP (`/mcp`) to:

- list and inspect Wiz cloud security issues (toxic combinations, threat detections, cloud configuration findings),
- rank top internet-facing vulnerabilities by severity, CISA KEV status, active exploitability, and score,
- audit identities (service accounts and users) flagged with admin or high privileges,
- trace a Wiz issue or cloud resource back to its container image digest and source repository (`wiz_trace_code_to_cloud`),
- execute custom read-only Wiz GraphQL queries (`query_wiz_graphql`).

All tools are strictly read-only. Mutations and subscriptions are rejected before any network request is sent. `wiz-mcp-sa` holds zero BigQuery, Cloud Logging, GCS, or Cloud Run Job IAM bindings — its only permission is `roles/secretmanager.secretAccessor` on the `wiz-client-secret` secret.

## Layout

```
wiz-mcp-server/
  server.py                 FastMCP tools, resources, prompts, HTTP routes
  config.py                 Settings (pydantic-settings; reads env vars and .env)
  services/
    wiz_service.py          Wiz GraphQL client (OAuth client credentials, token cache)
  tests/
    test_wiz_server.py      Unit tests for WizService, MCP tools, and HTTP endpoints
  requirements.txt  Dockerfile  deploy_cloud_run.sh  deploy.sh  cloudbuild.yaml  .env.example  .dockerignore
```

## Tools

| Tool | Purpose |
|---|---|
| `list_wiz_issues` | Filter Wiz issues by severity, status, type, project, search query, entity, and dates |
| `get_wiz_issue_details` | Full details for a single Wiz issue (rule, remediation, affected resource, tickets, notes) |
| `get_wiz_issues_summary` | Issue counts broken down by severity |
| `query_wiz_graphql` | Read-only Wiz GraphQL query (mutations and subscriptions rejected) |
| `wiz_top_internet_facing_vulnerabilities(environment="production", project=None, severity="CRITICAL", limit=5)` | Open vulnerabilities on internet-exposed assets, ranked by severity, CISA KEV, known exploit, then score (`limit` max 50) |
| `wiz_excessive_permission_identities(service=None, project=None, limit=25)` | Service accounts and users Wiz marks with admin or high privileges (`limit` max 100) |
| `wiz_trace_code_to_cloud(issue_id=None, resource_id=None)` | Resolves a Wiz issue or cloud resource to its container image digest and OCI source repository via Wiz (`cloudResources` + `issuesV2`) |

All Wiz tools return `{"error": "Wiz integration is not configured. ..."}` when `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, or `WIZ_API_ENDPOINT` is missing. If `wiz_trace_code_to_cloud` returns `found=False` or an unconfigured error, the agent falls back to `trace_code_to_cloud` on `codemender-mcp-server` (`security_lab.code_to_cloud_map` in BigQuery).

## Resources and prompts

- Resource: `wiz://critical-issues`
- Prompts: `triage_wiz_issue(issue_id)`, `remediate_wiz_issue(issue_id)`

## HTTP routes

| Route | Use |
|---|---|
| `POST/GET /mcp` | Streamable HTTP (Gemini Enterprise, Vertex AI Agent Engine, ADK `McpToolset`) |
| `GET /`, `POST /` | Service info; `POST` routes to the MCP handler |
| `GET /sse`, `POST /messages` | SSE transport; `POST /sse` routes to Streamable HTTP |
| `GET /healthz` | Cloud Run startup/liveness check (`service: "wiz-mcp-server"`, `wiz_configured`) |

## Configuration

`config.py` reads environment variables and `.env`. Copy `.env.example` to `.env` and fill in your tenant values.

| Variable | Default |
|---|---|
| `GCP_PROJECT_ID` | ADC project |
| `REGION` | `us-central1` |
| `SERVICE_NAME` | `wiz-mcp-server` |
| `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_API_ENDPOINT` | empty (Wiz unconfigured) |
| `WIZ_AUTH_URL` / `WIZ_AUDIENCE` | `https://auth.app.wiz.io/oauth/token` / `wiz-api` |
| `WIZ_SECRET_NAME` | `wiz-client-secret` |
| `PORT` | `8080` |

The Wiz service account needs read permissions for issues, vulnerabilities, resources, and the security graph (`read:issues`, `read:vulnerabilities`, `read:security_graph`, `read:resources`).

## Deploy

```bash
cd wiz-mcp-server
cp .env.example .env      # set GCP_PROJECT_ID and WIZ_* values
./deploy_cloud_run.sh
```

The script:
- loads `.env`,
- enables Cloud Run, Secret Manager, Artifact Registry, and Cloud Build APIs,
- creates dedicated runtime SA `wiz-mcp-sa`,
- stores `WIZ_CLIENT_SECRET` in Secret Manager (`wiz-client-secret`), grants `roles/secretmanager.secretAccessor` to `wiz-mcp-sa`, and mounts it via `--set-secrets`,
- deploys `wiz-mcp-server` with `--no-allow-unauthenticated` by default,
- grants `roles/run.invoker` to the Gemini Enterprise (Discovery Engine) and Vertex AI Agent Engine service agents.

Set `WIZ_MCP_URL=https://<wiz-mcp-server-url>/mcp` in `agent/.env` so the ADK security agent connects to this Cloud Run service using Google Cloud ID tokens.

## Run the tests

```bash
cd wiz-mcp-server
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash -n deploy_cloud_run.sh deploy.sh
```

## Verify against your tenant's schema

The Wiz GraphQL schema differs slightly across tenants and API versions. Fields and filter keys marked `# verify against your tenant's schema` in `services/wiz_service.py` should be verified in your tenant's Wiz GraphQL explorer (`vulnerabilityFindings`, `graphSearch`, and `cloudResources`).
