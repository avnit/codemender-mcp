# Code Mender Triage MCP Server (GCP Cloud Run)

A Model Context Protocol (MCP) server running on **Google Cloud Run** to inspect, query, and triage security findings published by **Code Mender** to **BigQuery**, correlated with execution, sandbox, and diagnostic traces from **Cloud Logging**. It also serves cloud security issues from **Wiz** through the same MCP endpoint.

---

## Architecture Overview

```mermaid
flowchart LR
    subgraph Client["MCP Client (e.g. Claude Desktop, Cursor, Jetski)"]
        A[MCP Client]
    end

    subgraph CloudRun["GCP Cloud Run (codemender-mcp-server)"]
        B["FastMCP Server (/sse, /messages)"]
        C["Cloud Run Health Check (/healthz)"]
        D["BigQuery Service"]
        E["Cloud Logging Service"]
        W["Wiz Service"]
        B --> D
        B --> E
        B --> W
    end

    subgraph Wiz["Wiz"]
        X[("Wiz GraphQL API\n(Issues)")]
        W -->|OAuth client credentials| X
    end

    subgraph GCP["Google Cloud Platform"]
        F[("BigQuery\n(Code Mender Findings Table)")]
        G[("Cloud Logging\n(Traces, Sandbox Logs, Diagnostics)")]
        D -->|ADC / Query Jobs| F
        E -->|ADC / Entries Filter| G
    end

    A -->|SSE / HTTPS with Auth Token| B
```

---

## Features & Capabilities

### 1. BigQuery Inspection (Code Mender Findings)
- **`list_codemender_issues`**: Query and filter security issues published by Code Mender. Filter by severity (`CRITICAL`, `HIGH`, etc.), status (`DETECTED`, `PATCH_GENERATED`, `VERIFIED`, `FIXED`, `FAILED`), repository, vulnerability type / CWE, date range, or text search.
- **`get_issue_details`**: Fetch full details for a specific issue ID / finding ID, including code snippets, generated patches / diffs, verification results, and remediation status.
- **`get_issues_summary`**: High-level aggregated statistics: total findings, open vs. resolved counts, severity breakdown, and top 5 recurring vulnerabilities.
- **`get_bigquery_schema`**: Inspect BigQuery table schemas, columns, types, and descriptions to guide custom queries.
- **`query_codemender_bigquery`**: Execute safe, parameterized, read-only SQL queries (`SELECT` and `WITH` statements only).

### 2. Cloud Logging Correlation (Diagnostics & Traces)
- **`get_issue_logs`**: Automatically correlates logs with a specific finding ID or Code Mender `session_id`. Retrieves compiler output, sandbox execution traces, and error logs.
- **`search_codemender_logs`**: Search Cloud Logging across Code Mender jobs and workers for exceptions, sandbox policy violations (e.g., blocked commands), or scan failures.

### 3. Wiz Issues (Cloud Security Findings)
Read-only access to Wiz issues through the Wiz GraphQL API. Requires a Wiz service account (see [Wiz Setup](#wiz-setup)). If Wiz isn't configured, these tools return an error and the rest of the server works as normal.
- **`list_wiz_issues`**: List issues, newest first. Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`), status (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `REJECTED`), type (`TOXIC_COMBINATION`, `THREAT_DETECTION`, `CLOUD_CONFIGURATION`), project, text search, date range, or affected resource. Supports cursor pagination.
- **`get_wiz_issue_details`**: Full details for one issue: source rule/control with remediation guidance, affected cloud resource, projects, linked tickets, and notes.
- **`get_wiz_issues_summary`**: Issue counts by severity (open and in-progress by default), with an optional lookback window.
- **`query_wiz_graphql`**: Run any read-only Wiz GraphQL query. Mutations and subscriptions are rejected.

### 4. MCP Resources & Prompts
- **Resource `codemender://schema`**: BigQuery schema representation of the findings table.
- **Resource `codemender://critical-issues`**: Live list of the most recent critical findings.
- **Resource `wiz://critical-issues`**: Latest open critical issues from Wiz.
- **Prompt `triage_wiz_issue`**: Triage a Wiz issue: fetch its details, check Code Mender for related findings, and recommend remediation.
- **Prompt `triage_issue`**: Automated investigation prompt guiding the LLM to inspect the issue in BigQuery, fetch correlated logs, review the patch diff, and recommend next actions.
- **Prompt `diagnose_remediation_failure`**: Automated prompt guiding the LLM to diagnose why a Code Mender patch or verification run failed.

---

## File Structure

```
.
├── .env.example               # Configuration template: copy to .env and fill in (incl. Wiz credentials)
├── config.py                  # Pydantic settings loaded from .env / environment variables
├── server.py                  # FastMCP server with tools, resources, and Cloud Run routes
├── services/
│   ├── __init__.py
│   ├── bigquery_service.py    # BigQuery client, parameterized queries, and serialization
│   ├── logging_service.py     # Cloud Logging client, filter generation, and formatting
│   └── wiz_service.py         # Wiz GraphQL client: OAuth token caching, issue queries
├── tests/
│   ├── __init__.py
│   └── test_server.py         # Unit tests with mocks for BigQuery, Logging, and Wiz
├── Dockerfile                 # Multi-stage, secure non-root Dockerfile for Cloud Run
├── .dockerignore              # Clean container build context
├── requirements.txt           # Python dependencies (mcp, google-cloud-*, uvicorn, etc.)
├── deploy_cloud_run.sh        # Turnkey deployment script for Cloud Run with CLI flags
├── cloudbuild.yaml            # CI/CD pipeline configuration
└── README.md                  # Project documentation
```

---

## Configuration

All settings, including the Wiz client ID and secret, live in one file: `.env`.

```bash
cp .env.example .env
# then edit .env and fill in your values
```

- **Local runs:** `config.py` reads `.env` automatically.
- **Cloud Run:** `deploy_cloud_run.sh` reads the same `.env` and passes the values to the service. `WIZ_CLIENT_SECRET` is stored in Secret Manager and mounted into the service; it is not set as a plain environment variable.
- **Secrets stay out of git and the image:** `.env` is listed in `.gitignore` and `.dockerignore`. Commit `.env.example` only, with placeholder values.
- **Precedence:** environment variables already set in your shell override `.env` for local runs; CLI flags override `.env` for `deploy_cloud_run.sh`.

To change a value later (for example, rotating the Wiz secret), edit `.env` and restart the server locally or re-run `./deploy_cloud_run.sh`. The deploy script adds a new secret version only when the value has changed.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `GCP_PROJECT_ID` | GCP Project ID hosting BigQuery & Logging | ADC Project |
| `REGION` | Cloud Run region (deploy script only) | `us-central1` |
| `SERVICE_NAME` | Cloud Run service name (deploy script only) | `codemender-mcp-server` |
| `BQ_DATASET` | BigQuery dataset containing Code Mender findings | `codemender` |
| `BQ_TABLE` | BigQuery table containing findings | `findings` |
| `LOG_NAME_FILTER` | Substring filter for Code Mender logs | `codemender` |
| `WIZ_CLIENT_ID` | Wiz service account client ID | _(empty: Wiz disabled)_ |
| `WIZ_CLIENT_SECRET` | Wiz service account client secret | _(empty: Wiz disabled)_ |
| `WIZ_API_ENDPOINT` | Your tenant's Wiz GraphQL endpoint, e.g. `https://api.us17.app.wiz.io/graphql` | _(empty: Wiz disabled)_ |
| `WIZ_AUTH_URL` | Wiz OAuth token URL | `https://auth.app.wiz.io/oauth/token` |
| `WIZ_AUDIENCE` | Wiz OAuth audience | `wiz-api` |
| `WIZ_SECRET_NAME` | Secret Manager secret name for the Wiz client secret (deploy script only) | `wiz-client-secret` |
| `PORT` | HTTP port to listen on (injected by Cloud Run) | `8080` |
| `HOST` | Host address to bind | `0.0.0.0` |

Wiz is enabled only when `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, and `WIZ_API_ENDPOINT` are all set. The `/healthz` response includes `"wiz_configured": true|false` so you can confirm it.

### Wiz Setup

1. In the Wiz portal, go to **Settings > Access Management > Service Accounts** and create a service account of type **Custom Integration (GraphQL API)**.
2. Grant it the **`read:issues`** permission. Add other `read:*` scopes only if you plan to use `query_wiz_graphql` for other data (e.g. `read:resources`, `read:vulnerabilities`).
3. Copy the **Client ID** and **Client Secret** into `.env` as `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET`. Wiz shows the secret only once.
4. Find your tenant's API endpoint under **User Settings > Tenant Info** (for example `https://api.us17.app.wiz.io/graphql`) and set it as `WIZ_API_ENDPOINT`.
5. If your tenant uses a different auth endpoint (e.g. FedRAMP or a legacy Cognito tenant), set `WIZ_AUTH_URL` and `WIZ_AUDIENCE` to the values Wiz gives you.

---

## Quick Start: Local Development

### 1. Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Create Your Config File
```bash
cp .env.example .env
```
Edit `.env` and set `GCP_PROJECT_ID`, and the `WIZ_*` values if you want Wiz issues (see [Wiz Setup](#wiz-setup)).

### 3. Authenticate with Google Cloud
Ensure Application Default Credentials (ADC) are configured:
```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
```

### 4. Run Unit Tests
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

### 5. Run the Server Locally
```bash
python3 server.py
```
The server will start on `http://0.0.0.0:8080`:
- **Health check**: `http://localhost:8080/healthz`
- **Root info**: `http://localhost:8080/`
- **MCP SSE Endpoint**: `http://localhost:8080/sse`

---

## Deploying to Google Cloud Run

### Option 1: Automated Script (`deploy_cloud_run.sh`)

The provided [`deploy_cloud_run.sh`](file:///usr/local/google/home/abambah/l400-security-labs/deploy_cloud_run.sh) script handles the entire deployment process:
1. Enables required GCP APIs (`run`, `bigquery`, `logging`, `artifactregistry`, `cloudbuild`).
2. Provisions a dedicated runtime service account (`codemender-mcp-sa`).
3. Grants least-privilege IAM roles:
   - `roles/bigquery.dataViewer` (reads findings tables)
   - `roles/bigquery.jobUser` (runs query jobs)
   - `roles/logging.viewer` (reads Cloud Logging entries)
4. Builds the container image from the [`Dockerfile`](file:///usr/local/google/home/abambah/l400-security-labs/Dockerfile) and deploys to Cloud Run.

The script reads `.env` first, so once that file is filled in you don't need any flags. If the `WIZ_*` values are set, it also:
- enables the Secret Manager API,
- stores `WIZ_CLIENT_SECRET` in the secret named by `WIZ_SECRET_NAME` (creating it, or adding a new version if the value changed),
- grants the runtime service account `roles/secretmanager.secretAccessor` on that secret,
- passes `WIZ_CLIENT_ID`, `WIZ_API_ENDPOINT`, `WIZ_AUTH_URL`, and `WIZ_AUDIENCE` as environment variables and mounts the secret as `WIZ_CLIENT_SECRET`.

If the `WIZ_*` values are empty, Wiz setup is skipped.

#### Basic Run (uses `.env`):
```bash
cp .env.example .env   # first time only; then edit .env
./deploy_cloud_run.sh
```

To use a different config file, for example one per environment:
```bash
ENV_FILE=.env.prod ./deploy_cloud_run.sh
```

#### Run with Custom Options:
```bash
./deploy_cloud_run.sh \
  --project "my-security-project" \
  --region "us-central1" \
  --service "codemender-mcp-server" \
  --dataset "codemender" \
  --table "findings"
```

#### CLI Flags Available in `deploy_cloud_run.sh`:
- `-p, --project PROJECT_ID`: GCP Project ID.
- `-r, --region REGION`: GCP Region (default: `us-central1`).
- `-s, --service SERVICE_NAME`: Cloud Run service name (default: `codemender-mcp-server`).
- `-d, --dataset DATASET`: BigQuery dataset name (default: `codemender`).
- `-t, --table TABLE`: BigQuery table name (default: `findings`).
- `-b, --build-service-account SA`: Service account for Cloud Build (if the default compute SA is disabled).
- `--allow-unauthenticated`: Permit unauthenticated calls (default: require IAM auth).
- `-h, --help`: Display usage guide.

Flags override values from `.env`. Wiz settings have no flags; set them in `.env`.

---

### Option 2: Manual Step-by-Step Deployment with `gcloud`

```bash
PROJECT_ID="your-project-id"
REGION="us-central1"
SERVICE_NAME="codemender-mcp-server"
SA_NAME="codemender-mcp-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# 1. Enable GCP APIs
gcloud services enable run.googleapis.com bigquery.googleapis.com logging.googleapis.com cloudbuild.googleapis.com --project="${PROJECT_ID}"

# 2. Create Service Account
gcloud iam service-accounts create "${SA_NAME}" \
  --display-name="Code Mender MCP Server Runtime SA" \
  --project="${PROJECT_ID}"

# 3. Grant IAM roles
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.dataViewer"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.jobUser"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/logging.viewer"

# 4. Deploy to Cloud Run
gcloud run deploy "${SERVICE_NAME}" \
  --source="." \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  --port=8080 \
  --cpu=1 \
  --memory=1Gi \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},BQ_DATASET=codemender,BQ_TABLE=findings" \
  --no-allow-unauthenticated
```

#### Optional: Enable Wiz in a Manual Deployment
```bash
# Load WIZ_* values from your config file
set -a; source .env; set +a

# 1. Store the Wiz client secret in Secret Manager
gcloud services enable secretmanager.googleapis.com --project="${PROJECT_ID}"
printf '%s' "${WIZ_CLIENT_SECRET}" | gcloud secrets create wiz-client-secret \
  --data-file=- --replication-policy=automatic --project="${PROJECT_ID}"

# 2. Let the runtime service account read it
gcloud secrets add-iam-policy-binding wiz-client-secret \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" \
  --project="${PROJECT_ID}"

# 3. Add the Wiz settings to the service
gcloud run services update "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --update-env-vars="WIZ_CLIENT_ID=${WIZ_CLIENT_ID},WIZ_API_ENDPOINT=${WIZ_API_ENDPOINT}" \
  --set-secrets="WIZ_CLIENT_SECRET=wiz-client-secret:latest"
```

> **Note:** `cloudbuild.yaml` does not read `.env` or configure Wiz. If you deploy through Cloud Build, run the three Wiz steps above once. The pipeline uses `--update-env-vars`, so later deploys keep the Wiz env vars and the secret mount.

---

## Verifying the Deployment

Get the assigned Cloud Run URL:
```bash
SERVICE_URL=$(gcloud run services describe codemender-mcp-server \
  --region=us-central1 \
  --format='value(status.url)')

echo "Service URL: ${SERVICE_URL}"
```

Test the health check endpoint:
```bash
curl -f -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "${SERVICE_URL}/healthz"
```

Expected output:
```json
{
  "status": "healthy",
  "service": "codemender-mcp-server",
  "project": "your-project-id",
  "dataset": "codemender",
  "table": "findings"
}
```

---

## Connecting MCP Clients

Connect your MCP client to the Cloud Run SSE endpoint (`${SERVICE_URL}/sse`):

### 1. Claude Desktop
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "codemender": {
      "url": "https://<your-service-url>.a.run.app/sse",
      "headers": {
        "Authorization": "Bearer YOUR_IDENTITY_TOKEN"
      }
    }
  }
}
```

### 2. Cursor / JetBrains / Jetski
Configure the MCP server:
- **Protocol / Transport**: `sse`
- **URL**: `https://<your-service-url>.a.run.app/sse`
- **Headers**: `Authorization: Bearer <GCP_IDENTITY_TOKEN>`

---

## Example Tool Invocations

### 1. Find Open Critical Findings in a Repository
```json
{
  "name": "list_codemender_issues",
  "arguments": {
    "repository": "frontend-service",
    "severity": "CRITICAL",
    "status": "OPEN",
    "limit": 10
  }
}
```

### 2. Inspect Patch and Remediation Details
```json
{
  "name": "get_issue_details",
  "arguments": {
    "issue_id": "FINDING-2026-9812"
  }
}
```

### 3. Retrieve Cloud Logging Traces for a Failing Fix
```json
{
  "name": "get_issue_logs",
  "arguments": {
    "issue_id": "FINDING-2026-9812",
    "min_severity": "WARNING"
  }
}
```

### 4. List Open Critical and High Wiz Issues
```json
{
  "name": "list_wiz_issues",
  "arguments": {
    "severity": "CRITICAL,HIGH",
    "status": "OPEN,IN_PROGRESS",
    "issue_type": "TOXIC_COMBINATION",
    "limit": 20
  }
}
```
Pass the returned `next_cursor` as `cursor` to get the next page.

### 5. Get Wiz Issue Details
```json
{
  "name": "get_wiz_issue_details",
  "arguments": {
    "issue_id": "<wiz-issue-id>"
  }
}
```
