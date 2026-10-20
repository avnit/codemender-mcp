# Troubleshooting

Find the component, then the symptom. Each row gives the likely cause and the fix. Commands use placeholders: `your-gcp-project-id`, `us-central1`, `<PROJECT_NUMBER>`.

```bash
export GCP_PROJECT_ID=your-gcp-project-id
export REGION=us-central1
export PROJECT_NUMBER=$(gcloud projects describe "$GCP_PROJECT_ID" --format="value(projectNumber)")
```

Components:
- [Gemini Enterprise custom MCP connector](#gemini-enterprise-custom-mcp-connector)
- [Wiz remote MCP](#wiz-remote-mcp)
- [Cloud Logging remote MCP](#cloud-logging-remote-mcp)
- [GitHub remote MCP](#github-remote-mcp)
- [Workload Identity Federation](#workload-identity-federation)
- [Sandbox (Cloud Run Job)](#sandbox-cloud-run-job)
- [Log ingestion](#log-ingestion)
- [BigQuery and Data Insights](#bigquery-and-data-insights)
- [Agent Engine deploy](#agent-engine-deploy)
- [ADK agent](#adk-agent)

---

## Gemini Enterprise custom MCP connector

| Symptom | Cause | Fix |
|---|---|---|
| The option to add a custom MCP connector is missing or greyed out, or saving fails with a policy error | Org policy `discoveryengine.managed.disableCustomMcpServerConnector` blocks custom MCP connectors | Check it: `gcloud org-policies describe discoveryengine.managed.disableCustomMcpServerConnector --project=$GCP_PROJECT_ID`. Ask an org policy admin to allow it for the lab project. |
| Google sign-in shows `Error 400: redirect_uri_mismatch` | The OAuth client is missing the redirect URI, or it is not a Web application client | In APIs & Services > Credentials, use an OAuth client of type **Web application** with authorized redirect URI exactly `https://vertexaisearch.cloud.google.com/oauth-redirect`. |
| Sign-in works but token exchange fails | Wrong auth or token URL, or PKCE not enabled | Auth URL `https://accounts.google.com/o/oauth2/v2/auth`, token URL `https://oauth2.googleapis.com/token`, scopes `openid email profile`, PKCE enabled. |
| Connector calls return 401 or 403 from Cloud Run | The Discovery Engine service agent cannot invoke the service | `gcloud run services add-iam-policy-binding codemender-mcp-server --region=$REGION --member=serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com --role=roles/run.invoker`. Terraform should already have done this; check that the service name matches. |
| Calls fail with "session terminated", "session not found", or work for one call and then fail | Server runs in stateful streamable HTTP mode; requests land on different instances | Run FastMCP with `stateless_http=True` (as in `mcp-server/server.py`) and redeploy with `mcp-server/deploy_cloud_run.sh`. |
| 405 Method Not Allowed | The server does not answer CORS preflight (`OPTIONS`), or the URL is missing `/mcp` | Use the URL ending in `/mcp`. Make sure the Starlette app handles `OPTIONS` (CORS middleware). Test: `curl -i -X OPTIONS $MCP_URL`. |
| Connector added but no tools appear | Server returned an error on `tools/list`, or the URL points at the root path | Run the `tools/list` curl from Module 07 step A3. Check Cloud Run logs for `codemender-mcp-server`. |

## Wiz remote MCP

| Symptom | Cause | Fix |
|---|---|---|
| `https://mcp.app.wiz.io` returns 403 or "MCP not enabled" | MCP is not enabled for the tenant | In Wiz: Settings > Tenant > AI Features, enable MCP (confirm in your environment). Needs a tenant admin. |
| 401 Unauthorized | Expired or wrong token; service account lacks scopes | Regenerate the token from the Wiz service account. Check the account has read scopes for issues, vulnerabilities and the security graph. In the custom MCP server, check `WIZ_CLIENT_ID`, the `wiz-client-secret` secret, `WIZ_AUTH_URL`, `WIZ_AUDIENCE`. |
| `query_wiz_graphql` or the new Wiz tools return GraphQL field errors (`Cannot query field ...`) | Field names differ in your tenant's schema | Verify against your tenant's schema (Wiz GraphQL explorer or introspection). Update the query in `mcp-server/services/`. |
| Auth works but API calls time out or return 404 | Wrong data center endpoint | Set `WIZ_API_ENDPOINT` to your tenant's region endpoint (for example `https://api.<region>.app.wiz.io/graphql`). Find it in Wiz under User Settings > Tenant (confirm in your environment). |

## Cloud Logging remote MCP

| Symptom | Cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` from `list_log_entries` | Caller lacks `roles/logging.viewer` (or `roles/logging.privateLogViewer` for Data Access logs) on the project, or the MCP API is not enabled | Grant the role to the user or to the Agent Engine service agent `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com`. Check that the Cloud Logging MCP endpoint is enabled for the project (confirm in your environment). |
| Error when querying several projects at once | `https://logging.googleapis.com/mcp` accepts one resource project per call | Call `list_log_entries` once per project and merge the results. Put this in the `investigation-routing` skill. |
| No entries returned | Filter too narrow or wrong time window | Test the same filter with `gcloud logging read '<filter>' --freshness=1d --limit=5`. |

## GitHub remote MCP

| Symptom | Cause | Fix |
|---|---|---|
| 401 from `https://api.githubcopilot.com/mcp/` | Missing or wrong `Authorization: Bearer` header | Check `GITHUB_PAT` (placeholder `ghp_REPLACE_ME` replaced) or the `github-mcp-pat` secret. |
| 403 or "Resource not accessible" on repo or workflow tools | PAT lacks scopes | Fine-grained PAT on `payment-service`: Contents read/write, Pull requests read/write, Issues read, Actions read/write, Metadata read. Classic PAT: `repo`, `workflow`. |
| 403 mentioning SAML or SSO | Org enforces SSO and the token is not authorized | GitHub > Settings > Personal access tokens > Configure SSO > Authorize for `your-github-org`. |
| `run_workflow` returns 404 | The workflow file is not on the default branch, or the name is wrong | `workflow_dispatch` workflows must exist on the default branch. Merge `.github/workflows/sandbox-validate.yml` to `main` first. Use the file name `sandbox-validate.yml`. |
| Merge tools listed in the agent | Blocklist not applied | Check `tool_filter` in `agent/security_agent/toolsets.py` uses the blocklist from `guardrails.py`. |

## Workload Identity Federation

| Symptom | Cause | Fix |
|---|---|---|
| `google-github-actions/auth` fails with `unauthorized_client` or "rejected by attribute condition" | The token does not match `assertion.repository_owner == "<github_org>"` | Check the provider: `gcloud iam workload-identity-pools providers describe github-provider --workload-identity-pool=github-pool --location=global --format="value(attributeCondition)"`. The org name must match exactly, including case. |
| `Unable to get ACTIONS_ID_TOKEN_REQUEST_URL` | Workflow lacks `id-token: write` permission | Add `permissions: { id-token: write, contents: read }` to the workflow or job. |
| `Permission 'iam.serviceAccounts.getAccessToken' denied` | The principal cannot impersonate `github-actions-sa` | Grant `roles/iam.workloadIdentityUser` on `github-actions-sa` to `principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/attribute.repository_owner/<github_org>` (confirm the attribute mapping in `infra/terraform/`). |
| Auth works, `gcloud run jobs execute` fails with permission denied | `github-actions-sa` lacks `roles/run.developer` on job `codemender-sandbox`, or `iam.serviceAccountUser` on `sandbox-runner-sa` | See the sandbox section. |
| Wrong provider string | `GCP_WIF_PROVIDER` variable malformed | Format: `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider` (project number, not ID). |

## Sandbox (Cloud Run Job)

| Symptom | Cause | Fix |
|---|---|---|
| Runner fails to download `SOURCE_URI`, verdict `ERROR`, timeout connecting to storage | No route to Google APIs: Private Google Access off, DNS not mapped to the restricted VIP, or the allow rule missing | `gcloud compute networks subnets describe sandbox-subnet --region=$REGION --format="value(privateIpGoogleAccess)"` must be `True`. Check the private DNS zone maps `googleapis.com` to `199.36.153.4/30`. Check firewall `sandbox-allow-restricted-apis` (priority 1000, tcp:443). |
| Download fails with 403 | `sandbox-runner-sa` lacks `roles/storage.objectViewer` on the bucket, or wrong bucket | `gcloud storage buckets get-iam-policy gs://your-gcp-project-id-sandbox-inputs`. Check the object path matches `sources/<repo_owner>__<repo_name>/<commit_sha>.tar.gz`. |
| `gcloud run jobs execute` fails: `Permission 'iam.serviceaccounts.actAs' denied` | The caller (you, `github-actions-sa` or `codemender-mcp-sa`) cannot act as `sandbox-runner-sa` | Grant `roles/iam.serviceAccountUser` on `sandbox-runner-sa` to the caller. |
| `run.jobs.runWithOverrides` permission denied | `--update-env-vars` needs override permission | Caller needs `roles/run.developer` on job `codemender-sandbox` (not `roles/run.invoker`). |
| Execution killed, no `SANDBOX_RESULT` | Task timeout shorter than the run, or `TIMEOUT_SECONDS` too low | Raise the job task timeout (`gcloud run jobs update codemender-sandbox --task-timeout=15m --region=$REGION`) and/or `TIMEOUT_SECONDS`. Keep the task timeout above `TIMEOUT_SECONDS`. |
| `ModuleNotFoundError` or `pip install` fails inside the job | No egress: dependencies cannot be downloaded at run time | Add the dependency to `sandbox/Dockerfile`, rebuild with `sandbox/deploy.sh`. Do not open egress. |
| Verdict `POC_NOT_REPRODUCED` | PoC did not succeed on the unpatched code: wrong `POC_TEST`, wrong commit, or the code is already fixed | Run `sandbox/run_local.sh` with the same inputs. Check that `COMMIT_SHA` is the vulnerable commit. |
| Verdict `PATCH_FAILED` with a patch | Patch did not apply (`patch_applied=false`), or it broke unit tests | Read `log_excerpt`. Regenerate the diff against the exact commit staged. |

## Log ingestion

| Symptom | Cause | Fix |
|---|---|---|
| Push requests return 403; nothing in BigQuery | `pubsub-push-sa` lacks `roles/run.invoker` on `security-log-ingestion`, or the OIDC audience is wrong | `gcloud run services add-iam-policy-binding security-log-ingestion --region=$REGION --member=serviceAccount:pubsub-push-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com --role=roles/run.invoker`. Check the subscription's push audience matches the service URL. |
| Push fails with token creation error | Pub/Sub service agent cannot mint tokens for `pubsub-push-sa` | Grant `roles/iam.serviceAccountTokenCreator` on `pubsub-push-sa` to `service-<PROJECT_NUMBER>@gcp-sa-pubsub.iam.gserviceaccount.com`. |
| Messages accumulate in `security-logs-dlq-sub` | Service returned 500 five times: BigQuery errors, wrong dataset/table env vars, or a bug | Check service logs. Check env vars `SECURITY_DATASET`, `SECURITY_EVENTS_TABLE`, `SANDBOX_RUNS_TABLE`, `INGESTION_ERRORS_TABLE`. After fixing, replay: pull from `security-logs-dlq-sub` and republish to `security-logs`. |
| Messages never dead-letter | Pub/Sub service agent lacks publisher on the DLQ topic or subscriber on `security-logs-push` | Grant both to `service-<PROJECT_NUMBER>@gcp-sa-pubsub.iam.gserviceaccount.com`. |
| Rows in `ingestion_errors` mentioning `no such field` or invalid value | Payload fields do not match the table schema | Compare with `log-ingestion/schema/` and `infra/terraform/schemas/`. Fix the producer or `parser.py`. Schemas must stay identical in both places. |
| Nothing arrives at all | Sink filter does not match, or sink writer cannot publish | `gcloud logging sinks describe security-logs-to-pubsub`. Grant the writer identity `roles/pubsub.publisher` on `security-logs`. Test the filter with `gcloud logging read`. |

## BigQuery and Data Insights

| Symptom | Cause | Fix |
|---|---|---|
| Data Insights agent does not list a dataset or says access denied | User lacks `roles/geminidataanalytics.dataAgentUser` or `roles/bigquery.dataViewer` on the dataset | Add the user to `var.participant_members` and re-apply Terraform, or grant both roles directly. |
| Queries fail with `bigquery.jobs.create` denied | Missing `roles/bigquery.jobUser` on the project | Grant `roles/bigquery.jobUser`. |
| `query_model_armor_logs` or `query_vpcsc_violations` fail with "Not found: Table" | Sink has not written yet, or table name differs | List tables: `bq ls your-gcp-project-id:security_logs`. Set `MODEL_ARMOR_TABLE` / `VPCSC_TABLE` to the actual names, or load seed data. |
| SCC queries return nothing | Continuous export not configured; seed table not loaded | Run `seed-data/load_seed_data.py`. |
| MCP server BigQuery calls denied | `codemender-mcp-sa` lacks dataViewer on the dataset | Grant `roles/bigquery.dataViewer` on the dataset and `roles/bigquery.jobUser` on the project. |

## Agent Engine deploy

| Symptom | Cause | Fix |
|---|---|---|
| `deploy.py` fails with bucket not found or 403 | `STAGING_BUCKET` missing or wrong region | `gcloud storage buckets create gs://your-gcp-project-id-agent-staging --location=us-central1`. Use the same region as `GOOGLE_CLOUD_LOCATION`. |
| Deploy succeeds but the engine fails to start; `ModuleNotFoundError` in logs | Package missing from the requirements passed in `deploy.py` | Add it to the requirements list in `deploy.py` with a pinned version. Redeploy. |
| Deployed agent cannot call the custom MCP server (401/403) | Agent Engine service agent lacks `roles/run.invoker` | Grant `roles/run.invoker` on `codemender-mcp-server` to `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com`. |
| Deployed agent cannot read secrets | Service agent lacks `roles/secretmanager.secretAccessor` on `github-mcp-pat` / `wiz-client-secret` | Grant it on the specific secrets. |
| Vertex AI API errors | APIs not enabled | `gcloud services enable aiplatform.googleapis.com`. |

## ADK agent

| Symptom | Cause | Fix |
|---|---|---|
| A toolset is missing; log says "toolset skipped" | Required env var not set (`WIZ_MCP_URL`, `GITHUB_PAT`, `CODEMENDER_MCP_URL`, ...) or `ENABLE_*` set to false | Fill `agent/.env` from `agent/.env.example`. Restart `adk web`. |
| `adk web` does not list the agent | Run from the wrong directory, or the package does not export `root_agent` | Run `adk web` from `agent/`. Check `agent/security_agent/__init__.py` imports `agent` and that `agent.py` defines `root_agent`. |
| Model errors (`403` / `404 model not found`) | Vertex AI not configured or wrong model | `GOOGLE_GENAI_USE_VERTEXAI=TRUE`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION=us-central1`, `AGENT_MODEL=gemini-2.5-flash`. Run `gcloud auth application-default login`. |
| Skill changes have no effect | Agent not restarted, or front matter `name` does not match the folder | Restart. Check YAML front matter parses (`name`, `description`). |
| Agent calls `start_sandbox_validation` and gets `confirmation_required` repeatedly | Agent did not ask the user, or did not pass `confirmed=True` after the "yes" | Check the confirmation instructions in `prompts.py` and the `sandbox-verification` skill. |
