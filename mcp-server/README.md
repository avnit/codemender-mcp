# Code Mender security MCP server (`mcp-server/`)

A custom Model Context Protocol (MCP) server deployed on Cloud Run as `codemender-mcp-server` (running under least-privilege service account `codemender-mcp-sa`). The lab's security agent and Gemini Enterprise invoke it over IAM-authenticated Streamable HTTP (`/mcp`) to:

- read Code Mender findings from BigQuery and Code Mender logs from Cloud Logging,
- map an issue ID or cloud resource to its container image and source repository via BigQuery (`security_lab.code_to_cloud_map` and `codemender.findings`),
- read SCC findings, Model Armor logs, VPC Service Controls denials and ingested security events from BigQuery,
- start a patch validation run on the `codemender-sandbox` Cloud Run Job and read the result.

> **Note:** Wiz cloud security posture tools (`list_wiz_issues`, `get_wiz_issue_details`, `get_wiz_issues_summary`, `query_wiz_graphql`, `wiz_top_internet_facing_vulnerabilities`, `wiz_excessive_permission_identities`, `wiz_trace_code_to_cloud`) now run in the separate [`wiz-mcp-server/`](../wiz-mcp-server/) Cloud Run service (`wiz-mcp-server`, runtime SA `wiz-mcp-sa`).

Every tool in `codemender-mcp-server` is read-only except `start_sandbox_validation`. That tool does nothing until it is called with `confirmed=True`, and the agent must get explicit user approval before it makes that call.

## Layout

```
mcp-server/
  server.py                 FastMCP tools, resources, prompts, HTTP routes
  config.py                 Settings (pydantic-settings; reads env vars and .env)
  services/
    bigquery_service.py     Code Mender findings (codemender.findings)
    logging_service.py      Cloud Logging search and correlation
    security_data_service.py  SCC, Model Armor, VPC SC, security_events, code_to_cloud_map, sandbox_runs
    sandbox_service.py      Cloud Run Admin API v2 calls for the sandbox job
  tests/
    _stubs.py               Stand-ins for google-cloud-bigquery / -logging when not installed
    test_server.py          BigQuery, Logging, and HTTP route tests
    test_new_tools.py       Tests for SecurityDataService, SandboxService, and server tools
  requirements.txt  Dockerfile  deploy_cloud_run.sh  deploy.sh  cloudbuild.yaml  .env.example  .dockerignore
```

## Tools

### Code Mender and Cloud Logging

| Tool | Purpose |
|---|---|
| `list_codemender_issues` | Filter findings by severity, status, repository, CWE, session, text, dates |
| `get_issue_details` | Full record for one finding |
| `get_issues_summary` | Counts by severity and status, top vulnerability types |
| `get_bigquery_schema` | Schema of the findings table |
| `query_codemender_bigquery` | Read-only SQL (SELECT/WITH only, row limit enforced) |
| `get_issue_logs` | Cloud Logging entries for an issue or session ID |
| `search_codemender_logs` | Free-text log search |

### Code-to-cloud (BigQuery)

`trace_code_to_cloud(issue_id=None, resource_id=None)`

Resolves an issue ID (`finding_id`, `issue_id`, or `wiz_issue_id`) to a repository through `codemender.findings`, then reads matching rows from `security_lab.code_to_cloud_map` by `resource_id` or `repository`. Pairs with `wiz_trace_code_to_cloud` on `wiz-mcp-server` when resolving live Wiz graph entities.

### Security data in BigQuery

All four tools use fixed SELECT statements with query parameters. User input never becomes SQL text. Enum inputs are checked against allowed values, free-text inputs against strict patterns. `days` is capped at 90 and `limit` at 200.

| Tool | Table | Filters |
|---|---|---|
| `query_scc_findings(severity, category, state="ACTIVE", project, days=7, limit=25)` | `scc_export.findings` | Latest row per finding. Severity CRITICAL/HIGH/MEDIUM/LOW; state ACTIVE/INACTIVE. |
| `query_model_armor_logs(match_state, filter_type, days=7, limit=25)` | `security_logs.modelarmor_googleapis_com_sanitize_operations` | match_state MATCH_FOUND/NO_MATCH_FOUND; filter_type rai, pi_and_jailbreak, malicious_uris, sdp, csam |
| `query_vpcsc_violations(perimeter, principal, service, days=7, limit=25)` | `security_logs.cloudaudit_googleapis_com_policy` | Perimeter substring, principal email, API service name. Returns `violation_reason` and `perimeter` from `metadataJson`. |
| `query_security_events(event_type, severity, issue_id, days=7, limit=25)` | `security_lab.security_events` | event_type CODEMENDER_SCAN_STARTED, CODEMENDER_SCAN_COMPLETED, CODEMENDER_FINDING, CODEMENDER_PATCH, SANDBOX_RESULT, IAM_POLICY_CHANGE, OTHER_SECURITY |

### Sandbox validation

`start_sandbox_validation(repository, commit_sha, patch_uri, issue_id, poc_test="tests/poc", confirmed=False)`, the only action tool.

- Input checks: `repository` must be `owner/name`; `commit_sha` 7-40 hex characters; `patch_uri` either `none` or `gs://<SANDBOX_BUCKET>/...`; `issue_id` and `poc_test` must match safe patterns (no `..`, no absolute paths).
- With `confirmed=False` it returns `{"error": "confirmation_required", "planned_run": {...}}` and starts nothing. The agent shows `planned_run` to the user, waits for approval, then calls again with `confirmed=True`.
- With `confirmed=True` it calls `POST https://run.googleapis.com/v2/projects/{project}/locations/{region}/jobs/codemender-sandbox:run` and overrides `RUN_ID`, `REPOSITORY`, `COMMIT_SHA`, `SOURCE_URI`, `PATCH_URI`, `ISSUE_ID`, `POC_TEST`.

`get_sandbox_result(run_id=None, execution_name=None)` returns the Cloud Run execution state and the matching `security_lab.sandbox_runs` row with the verdict (`PATCH_VERIFIED`, `PATCH_FAILED`, `POC_NOT_REPRODUCED`, `ERROR`).

## Resources and prompts

- Resources: `codemender://schema`, `codemender://critical-issues`.
- Prompts: `triage_issue`, `diagnose_remediation_failure`.

## HTTP routes

| Route | Use |
|---|---|
| `POST/GET /mcp` | Streamable HTTP (Gemini Enterprise, Agent Engine, ADK `McpToolset`) |
| `GET /`, `POST /` | Service info; POST goes to the MCP handler |
| `GET /sse`, `POST /messages` | SSE transport; `POST /sse` goes to the Streamable HTTP handler |
| `GET /healthz` | Health check (`service: "codemender-mcp-server"`) |

## Configuration

`config.py` reads environment variables and `.env`. Copy `.env.example` to `.env` and fill it in.

| Variable | Default |
|---|---|
| `GCP_PROJECT_ID` | ADC project |
| `REGION` | `us-central1` |
| `BQ_DATASET` / `BQ_TABLE` | `codemender` / `findings` |
| `LOG_NAME_FILTER` | `codemender` |
| `SECURITY_DATASET` | `security_lab` |
| `SECURITY_EVENTS_TABLE` / `SANDBOX_RUNS_TABLE` / `CODE_TO_CLOUD_TABLE` | `security_events` / `sandbox_runs` / `code_to_cloud_map` |
| `SCC_DATASET` / `SCC_TABLE` | `scc_export` / `findings` |
| `SECURITY_LOGS_DATASET` | `security_logs` |
| `MODEL_ARMOR_TABLE` | `modelarmor_googleapis_com_sanitize_operations` |
| `VPCSC_TABLE` | `cloudaudit_googleapis_com_policy` |
| `SANDBOX_JOB_NAME` | `codemender-sandbox` |
| `SANDBOX_REGION` | value of `REGION` |
| `SANDBOX_BUCKET` | `<GCP_PROJECT_ID>-sandbox-inputs` |
| `PORT` | `8080` |

## Deploy

```bash
cd mcp-server
cp .env.example .env      # set GCP_PROJECT_ID
./deploy_cloud_run.sh
```

The script:
- loads `.env`,
- enables APIs and creates `codemender-mcp-sa`,
- grants `roles/bigquery.dataViewer`, `roles/bigquery.jobUser`, `roles/logging.viewer` and `roles/run.viewer`,
- grants `roles/run.developer` on the `codemender-sandbox` job only (if the job exists),
- deploys `codemender-mcp-server` with `--no-allow-unauthenticated` by default,
- grants `roles/run.invoker` to the Gemini Enterprise and Vertex AI Agent Engine service agents.

## Run the tests

```bash
cd mcp-server
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash -n deploy_cloud_run.sh deploy.sh
```
