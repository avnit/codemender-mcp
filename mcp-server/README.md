# Code Mender security MCP server (`mcp-server/`)

A custom Model Context Protocol (MCP) server that runs on Cloud Run as `codemender-mcp-server`. The lab's security agent and Gemini Enterprise use it to:

- read Code Mender findings from BigQuery and Code Mender logs from Cloud Logging,
- read Wiz issues, internet-facing vulnerabilities and over-privileged identities,
- map a Wiz issue or cloud resource to its container image and source repository,
- read SCC findings, Model Armor logs, VPC Service Controls denials and ingested security events from BigQuery,
- start a patch validation run on the `codemender-sandbox` Cloud Run Job and read the result.

Every tool is read-only except `start_sandbox_validation`. That tool does nothing until it is called with `confirmed=True`, and the agent must get explicit user approval before it makes that call.

## Layout

```
mcp-server/
  server.py                 FastMCP tools, resources, prompts, HTTP routes
  config.py                 Settings (pydantic-settings; reads env vars and .env)
  services/
    bigquery_service.py     Code Mender findings (codemender.findings)
    logging_service.py      Cloud Logging search and correlation
    wiz_service.py          Wiz GraphQL client (OAuth client credentials, token cache)
    security_data_service.py  SCC, Model Armor, VPC SC, security_events, code_to_cloud_map, sandbox_runs
    sandbox_service.py      Cloud Run Admin API v2 calls for the sandbox job
  tests/
    _stubs.py               Stand-ins for google-cloud-bigquery / -logging when not installed
    test_server.py          Existing tests (services, HTTP routes)
    test_new_tools.py       Tests for the new tools and services
  requirements.txt  Dockerfile  deploy_cloud_run.sh  cloudbuild.yaml  .env.example  .dockerignore
```

## Tools

### Code Mender and Cloud Logging (existing)

| Tool | Purpose |
|---|---|
| `list_codemender_issues` | Filter findings by severity, status, repository, CWE, session, text, dates |
| `get_issue_details` | Full record for one finding |
| `get_issues_summary` | Counts by severity and status, top vulnerability types |
| `get_bigquery_schema` | Schema of the findings table |
| `query_codemender_bigquery` | Read-only SQL (SELECT/WITH only, row limit enforced) |
| `get_issue_logs` | Cloud Logging entries for an issue or session ID |
| `search_codemender_logs` | Free-text log search |

### Wiz

| Tool | Purpose |
|---|---|
| `list_wiz_issues`, `get_wiz_issue_details`, `get_wiz_issues_summary`, `query_wiz_graphql` | Existing issue tools and read-only GraphQL |
| `wiz_top_internet_facing_vulnerabilities(environment="production", project=None, severity="CRITICAL", limit=5)` | Open vulnerabilities on internet-exposed assets, ranked by severity, CISA KEV, known exploit, then score. `limit` max 50. |
| `wiz_excessive_permission_identities(service=None, project=None, limit=25)` | Service accounts and users Wiz marks with admin or high privileges. `service` is a substring of the identity name (for example `payment-service`). `limit` max 100. |

All Wiz tools return `{"error": "Wiz integration is not configured. ..."}` when `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET` or `WIZ_API_ENDPOINT` is missing.

### Code-to-cloud

`trace_code_to_cloud(issue_id=None, resource_id=None)`

1. Asks Wiz for the issue's affected resource, then for that resource's graph entity properties: image digest, image labels (`org.opencontainers.image.source`) and repository fields.
2. If Wiz is not configured, returns an error, or finds no repository, it falls back to BigQuery. An issue ID is resolved to a repository through `codemender.findings` (`finding_id`, `issue_id` or `wiz_issue_id`), then rows are read from `security_lab.code_to_cloud_map` by resource ID or repository.

The response says which source answered (`"source": "wiz"` or `"bigquery"`) and, on fallback, why Wiz did not (`wiz_status`).

### Security data in BigQuery

All four tools use fixed SELECT statements with query parameters. User input never becomes SQL text. Enum inputs are checked against allowed values, free-text inputs against strict patterns. `days` is capped at 90 and `limit` at 200.

| Tool | Table | Filters |
|---|---|---|
| `query_scc_findings(severity, category, state="ACTIVE", project, days=7, limit=25)` | `scc_export.findings` | Latest row per finding. Severity CRITICAL/HIGH/MEDIUM/LOW; state ACTIVE/INACTIVE. |
| `query_model_armor_logs(match_state, filter_type, days=7, limit=25)` | `security_logs.modelarmor_googleapis_com_sanitize_operations` | match_state MATCH_FOUND/NO_MATCH_FOUND; filter_type rai, pi_and_jailbreak, malicious_uris, sdp, csam |
| `query_vpcsc_violations(perimeter, principal, service, days=7, limit=25)` | `security_logs.cloudaudit_googleapis_com_policy` | Perimeter substring, principal email, API service name. Returns `violation_reason` and `perimeter` from `metadataJson`. |
| `query_security_events(event_type, severity, issue_id, days=7, limit=25)` | `security_lab.security_events` | event_type CODEMENDER_SCAN_STARTED, CODEMENDER_SCAN_COMPLETED, CODEMENDER_FINDING, CODEMENDER_PATCH, SANDBOX_RESULT, IAM_POLICY_CHANGE, OTHER_SECURITY |

The Model Armor and VPC SC table names and column names come from the log sinks. Confirm them in your environment.

### Sandbox validation

`start_sandbox_validation(repository, commit_sha, patch_uri, issue_id, poc_test="tests/poc", confirmed=False)`, the only action tool.

- Input checks: `repository` must be `owner/name`; `commit_sha` 7-40 hex characters; `patch_uri` either `none` or `gs://<SANDBOX_BUCKET>/...` (the sandbox service account can read only that bucket); `issue_id` and `poc_test` must match safe patterns (no `..`, no absolute paths).
- With `confirmed=False` it returns `{"error": "confirmation_required", "planned_run": {...}}` and starts nothing. The agent shows `planned_run` to the user, waits for approval, then calls again with `confirmed=True`.
- With `confirmed=True` it calls `POST https://run.googleapis.com/v2/projects/{project}/locations/{region}/jobs/codemender-sandbox:run` and overrides these env vars: `RUN_ID`, `REPOSITORY`, `COMMIT_SHA`, `SOURCE_URI`, `PATCH_URI`, `ISSUE_ID`, `POC_TEST`. `SOURCE_URI` is `gs://<SANDBOX_BUCKET>/sources/<owner>__<name>/<commit_sha>.tar.gz`. The response has `run_id` and `execution_name`.

`get_sandbox_result(run_id=None, execution_name=None)` returns the Cloud Run execution state (PENDING, RUNNING, SUCCEEDED, FAILED, CANCELLED) and the matching `security_lab.sandbox_runs` row with the verdict (PATCH_VERIFIED, PATCH_FAILED, POC_NOT_REPRODUCED, ERROR). The row appears after the log ingestion service processes the SANDBOX_RESULT log line, usually a minute or two after the execution ends. If only `run_id` is known and no row exists yet, the tool lists recent executions and matches the `RUN_ID` override. This relies on the execution's template carrying the overrides; confirm in your environment.

The sandbox job runs on the Cloud Run second-generation execution environment (a microVM sandbox). The lab brief asked for gVisor, but gVisor (first generation) is not available for Cloud Run Jobs. Isolation comes from gen2, a VPC that denies all egress except the restricted Google APIs VIP, and a service account with no project roles. The sandbox cannot reach GitHub, so source and patches are staged in the sandbox bucket.

The server uses the Cloud Run Admin API over REST with `google.auth` default credentials, so `google-cloud-run` is not required.

## Resources and prompts

- Resources: `codemender://schema`, `codemender://critical-issues`, `wiz://critical-issues`.
- Prompts: `triage_issue`, `diagnose_remediation_failure`, `triage_wiz_issue`, and `remediate_wiz_issue(issue_id)`. The new prompt walks the agent through: Wiz issue details, code-to-cloud trace, the matching Code Mender finding and patch, a sandbox run (approval first), the verdict, and then a pull request offer. The agent never merges.

## HTTP routes

| Route | Use |
|---|---|
| `POST/GET /mcp` | Streamable HTTP (Gemini Enterprise, Agent Engine) |
| `GET /`, `POST /` | Service info; POST goes to the MCP handler |
| `GET /sse`, `POST /messages` | SSE transport; `POST /sse` goes to the Streamable HTTP handler |
| `GET /healthz` | Health check |

OPTIONS returns 204, DELETE and HEAD return 200, CORS allows all origins, and missing `Accept` headers are normalized for FastMCP.

## Configuration

`config.py` reads environment variables and `.env`. Copy `.env.example` to `.env` and fill it in. Use placeholders only in anything you commit.

| Variable | Default |
|---|---|
| `GCP_PROJECT_ID` | ADC project |
| `REGION` | `us-central1` |
| `BQ_DATASET` / `BQ_TABLE` | `codemender` / `findings` |
| `LOG_NAME_FILTER` | `codemender` |
| `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_API_ENDPOINT` | empty (Wiz disabled) |
| `WIZ_AUTH_URL` / `WIZ_AUDIENCE` | `https://auth.app.wiz.io/oauth/token` / `wiz-api` |
| `WIZ_SECRET_NAME` | `wiz-client-secret` |
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

The Wiz service account needs read permissions for issues, vulnerabilities and the security graph (for example `read:issues`, `read:vulnerabilities`, `read:security_graph`; confirm in your environment).

## Deploy

```bash
cp .env.example .env      # set GCP_PROJECT_ID and, optionally, WIZ_* values
./deploy_cloud_run.sh
```

The script:

- loads `.env`,
- enables APIs and creates `codemender-mcp-sa`,
- grants `roles/bigquery.dataViewer`, `roles/bigquery.jobUser`, `roles/logging.viewer` and `roles/run.viewer`,
- grants `roles/run.developer` on the `codemender-sandbox` job only, if the job exists (re-run after Module 04 creates it),
- stores `WIZ_CLIENT_SECRET` in Secret Manager (`WIZ_SECRET_NAME`) and mounts it as an env var,
- deploys from source with all settings above as env vars.

The service account also needs `roles/storage.objectViewer` on the sandbox bucket. Terraform in `infra/terraform/` grants it.

`cloudbuild.yaml` builds into the Artifact Registry repo `security-lab` and deploys with `--update-env-vars`, so values set earlier (such as Wiz settings) are kept.

## Run the tests

There are no network calls in the tests. `tests/_stubs.py` installs minimal stand-ins for `google-cloud-bigquery` and `google-cloud-logging` only when the real packages are missing. pytest is not required.

```bash
cd mcp-server
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash -n deploy_cloud_run.sh
```

## Verify against your tenant's schema

The Wiz GraphQL schema differs between tenants and API versions. These fields and filter keys are used by the new Wiz tools but have not been confirmed for every tenant. Each one is marked `# verify against your tenant's schema` in `services/wiz_service.py`. Test them in the Wiz GraphQL explorer. If one fails, remove it from the query or replace it with your tenant's equivalent.

`wiz_top_internet_facing_vulnerabilities` (`vulnerabilityFindings`):
- node fields: `severity`, `vendorSeverity`, `exploitabilityScore`, `hasExploit`, `hasCisaKevExploit`, `projects { id name }`
- `vulnerableAsset` on `VulnerableAssetBase`: `tags`, `hasLimitedInternetExposure`, `hasWideInternetExposure`
- `vulnerableAsset` on `VulnerableAssetContainerImage`: `imageId`
- `filterBy` keys: `vendorSeverity`, `hasWideInternetExposure`, `environment` (values PRODUCTION, STAGING, DEVELOPMENT, TESTING, OTHER), `projectId`

`wiz_excessive_permission_identities` (`graphSearch`):
- entity types `SERVICE_ACCOUNT`, `USER_ACCOUNT`
- property filters `hasAdminPrivileges`, `hasHighPrivileges` (`{"EQUALS": [true]}`) and `name` (`{"CONTAINS": [...]}`)
- `properties` keys read: `hasAdminPrivileges`, `hasHighPrivileges`, `cloudPlatform`, `nativeType`, `externalId`, `providerUniqueId`

`trace_code_to_cloud` (`cloudResources`):
- the `cloudResources` query itself, `providerId`, `graphEntity { id type properties }`
- `filterBy` keys `id` and `providerUniqueId`
- `properties` keys read: `imageDigest`, `digest`, `imageId`, `imageLabels`, `labels` (label `org.opencontainers.image.source`), `codeRepository`, `repository`, `repositoryUrl`, `sourceRepository`

If your tenant uses `cloudResourcesV2` or exposes code-to-cloud through a dedicated repository relationship, change `CODE_TO_CLOUD_QUERY` to match. The BigQuery fallback keeps the tool usable either way.
