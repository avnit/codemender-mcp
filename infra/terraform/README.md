# infra/terraform

Terraform for the lab "Build an AI Security Agent on Gemini Enterprise integrated with Wiz, Cloud Logging, GitHub, CodeMender, and BigQuery".

It creates the GCP side of the lab in one existing project: Artifact Registry, BigQuery datasets and tables, log sinks, Pub/Sub, the sandbox network, buckets, Secret Manager secrets (empty), service accounts, IAM, Workload Identity Federation for GitHub Actions, two Cloud Run services, the sandbox Cloud Run Job, and (optionally) the SCC export to BigQuery.

`terraform fmt` and `terraform validate` have not been run on this code. Run them before the first apply.

## Requirements

- Terraform >= 1.5, google and google-beta providers ~> 6.0.
- `gcloud` authenticated as a user with Owner (or equivalent) on the project.
- For the SCC export only: org-level permission to create SCC BigQuery exports (see below).

## Two-phase apply

The Cloud Run services and job need container images, and the images need the Artifact Registry repository. So the first apply runs without services.

Phase 1: everything except Cloud Run.

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # edit values
terraform init
terraform apply -var deploy_services=false
```

Between phases:

1. Add the secret values (Terraform never stores them):

   ```bash
   printf '%s' 'REPLACE_ME'     | gcloud secrets versions add wiz-client-secret    --data-file=-
   printf '%s' 'ghp_REPLACE_ME' | gcloud secrets versions add github-mcp-pat       --data-file=-
   printf '%s' 'REPLACE_ME'     | gcloud secrets versions add codemender-api-token --data-file=-
   ```

   `wiz-client-secret` must have a version before phase 2, because the MCP server reads version `latest` at deploy time. If you are not using Wiz, add a placeholder value.

2. Build and push the three images to `REGION-docker.pkg.dev/PROJECT/security-lab/`:

   ```bash
   REPO=$(terraform output -raw artifact_registry_prefix)
   gcloud builds submit ../../mcp-server    --tag "$REPO/codemender-mcp-server:latest"
   gcloud builds submit ../../log-ingestion --tag "$REPO/security-log-ingestion:latest"
   gcloud builds submit ../../sandbox       --tag "$REPO/codemender-sandbox:latest"
   ```

Phase 2: services, job, push subscription and the IAM that references them.

```bash
terraform apply -var deploy_services=true
```

Then copy `terraform output github_actions_vars` into the payment-service repository variables, and use `terraform output -raw mcp_endpoint` as `CODEMENDER_MCP_URL`.

## What each file creates

| File | Creates |
|---|---|
| `versions.tf`, `providers.tf` | Version pins, providers, `data.google_project` (for the project number). |
| `variables.tf`, `locals.tf` | Inputs; names from NAMING.md; default image URIs; service agent emails. |
| `apis.tf` | Enables the required APIs. APIs stay enabled on destroy. |
| `artifact_registry.tf` | Docker repo `security-lab`. |
| `bigquery.tf` | Datasets `codemender`, `security_lab`, `scc_export`, `security_logs`; tables `codemender.findings`, `security_lab.{security_events,sandbox_runs,code_to_cloud_map,ingestion_errors}`, `scc_export.findings`. Schemas come from `schemas/*.json`. |
| `schemas/` | BigQuery JSON schemas. `model_armor_logs.json` and `vpcsc_logs.json` are used only by seed-data; Terraform does not create those tables (the sinks do). |
| `logging.tf` | Sinks `security-logs-to-pubsub`, `model-armor-to-bq`, `vpcsc-to-bq`, plus IAM for their writer identities. |
| `pubsub.tf` | Topics `security-logs`, `security-logs-dlq`; push sub `security-logs-push` (OIDC as `pubsub-push-sa`, 5 delivery attempts, then DLQ); pull sub `security-logs-dlq-sub`; Pub/Sub service agent IAM. |
| `network.tf` | `sandbox-vpc`, `sandbox-subnet` (10.10.0.0/24, Private Google Access), firewall rules `sandbox-deny-all-egress` and `sandbox-allow-restricted-apis`, private DNS zone mapping `*.googleapis.com` to `restricted.googleapis.com` (199.36.153.4-7). No Cloud NAT, on purpose. |
| `storage.tf` | `PROJECT-sandbox-inputs` (7-day lifecycle delete, no versioning, public access prevention) and `PROJECT-agent-staging`. |
| `secrets.tf` | Secrets `wiz-client-secret`, `github-mcp-pat`, `codemender-api-token` with no versions; accessor bindings. |
| `service_accounts.tf` | `codemender-mcp-sa`, `log-ingestion-sa`, `sandbox-runner-sa`, `pubsub-push-sa`, `github-actions-sa`. |
| `iam.tf` | Role bindings for participants, the lab service accounts and the Discovery Engine / Agent Engine service agents. |
| `wif.tf` | Pool `github-pool`, provider `github-provider`, `workloadIdentityUser` for `GITHUB_ORG/payment-service` on `github-actions-sa`. |
| `cloud_run.tf` | Services `codemender-mcp-server`, `security-log-ingestion`; job `codemender-sandbox`. |
| `scc.tf` | Org-level SCC export to `scc_export` (only when `scc_organization_id` is set). |
| `outputs.tf` | URLs, MCP endpoint, bucket, WIF provider, SA email, dataset IDs, service agent emails, `github_actions_vars`. |

## Security notes

- Neither Cloud Run service allows `allUsers`. Both use ingress "all" and IAM-authenticated invocation. The ingestion service cannot use "internal and Cloud Load Balancing" ingress because Pub/Sub push requests do not come from the VPC.
- The sandbox is a Cloud Run Job. Cloud Run Jobs run only on the second-generation execution environment (microVM). gVisor (gen1) is not available for jobs, even though the lab brief asked for gVisor. Isolation comes from the gen2 microVM, a VPC whose only allowed egress is tcp:443 to the restricted Google APIs VIP, and `sandbox-runner-sa`, which has no project roles (only `storage.objectViewer` on the sandbox bucket).
- The sandbox cannot reach GitHub. Source and patches are staged in the sandbox bucket.
- `github-actions-sa` can only be impersonated by workflows in `GITHUB_ORG/payment-service`. Its `run.developer` grant is scoped to the `codemender-sandbox` job only. Note that `run.developer` on the job also allows updating the job's configuration, not only executing it.

## Items that need org-level permissions

- **SCC export** (`scc.tf`): an organization-level resource. Requires SCC active on the org and a role such as `roles/securitycenter.bigQueryExportsEditor` at org level. Leave `scc_organization_id` empty to skip it; the pre-created `scc_export.findings` table and seed data cover the lab exercises.
- **Gemini Enterprise custom MCP connector**: the org policy `discoveryengine.managed.disableCustomMcpServerConnector` must allow custom MCP connectors. Terraform does not change org policy. Ask an org policy admin.
- **VPC Service Controls logs** only appear if the org has a service perimeter. The `vpcsc-to-bq` sink is harmless without one.

## Things to confirm in your environment

- The API name `geminidataanalytics.googleapis.com` and the role `roles/geminidataanalytics.dataAgentUser`.
- The Agent Engine service agent (`service-PROJECT_NUMBER@gcp-sa-aiplatform-re.iam.gserviceaccount.com`) may not exist until Agent Engine is first used. If bindings to it fail, deploy an agent once (or create the service identity) and apply again. The same can apply to the Discovery Engine service agent before Gemini Enterprise is set up in the project.
- Whether `roles/iam.serviceAccountUser` on `sandbox-runner-sa` is needed by callers that execute (not deploy) the job. It is granted to be safe.
- The Model Armor log name and field names in `model_armor_logs.json`.
- Whether the SCC export writes into the pre-created `scc_export.findings` table or wants to create its own. If it conflicts, delete the table and let the export create it.
- The SCC export resource type (`google_scc_v2_organization_scc_big_query_export` vs the v1 resource) for your provider version.

## Cost

Everything scales to zero or is billed per use, except:

- Cloud DNS private zone: a small monthly charge per zone.
- BigQuery storage and queries: small for lab data. The SCC export can grow in large orgs; the export filter limits it to this project.
- Artifact Registry storage for three images.
- Cloud Run: min instances are 0, so idle cost is zero. Each sandbox run is billed for its duration (up to 15 minutes, 2 vCPU / 2 GiB).
- Pub/Sub and Cloud Logging: low volume. Firewall logging on `sandbox-deny-all-egress` adds log volume when the sandbox tries to reach the internet.

## Destroy

```bash
terraform destroy
```

- Buckets use `force_destroy = true` and datasets use `delete_contents_on_destroy = true`, so destroy removes the data. This is for the lab only.
- Cloud Run services and the job set `deletion_protection = false` so destroy works.
- APIs are left enabled.
- Secrets are deleted along with all versions you added via gcloud.
- Tables created by the log sinks in `security_logs` are deleted with the dataset.
- The WIF pool and provider are soft-deleted for 30 days. Re-applying within that window with the same IDs fails; undelete them with `gcloud iam workload-identity-pools undelete github-pool --location=global` (and the provider) or wait.
- Service accounts are deleted; re-creating one with the same name gets a new unique ID, so re-apply all IAM.
