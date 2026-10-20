# Cleanup

**Goal:** Remove everything the lab created so nothing keeps running, billing, or holding credentials.

**Time:** 20-30 minutes

**Prerequisites:** The same access you used for the lab (project Owner or equivalent, Gemini Enterprise admin, GitHub org admin, Wiz admin).

```bash
export GCP_PROJECT_ID=your-gcp-project-id
export REGION=us-central1
export PROJECT_NUMBER=$(gcloud projects describe "$GCP_PROJECT_ID" --format="value(projectNumber)")
export GITHUB_ORG=your-github-org
```

If the whole project was created only for this lab, deleting the project (`gcloud projects delete $GCP_PROJECT_ID`) replaces steps 3-6 and 10. Still do steps 1-2, 7-9.

Do the steps in this order. Front-end registrations go first so users cannot call back-ends that are being deleted.

---

## Steps

### 1. Stop agents in Gemini Enterprise

In the Gemini Enterprise app, disable the `ai_security_agent` registration and any Agent Designer agents built during the lab (confirm UI in your environment).

### 2. Delete Gemini Enterprise connectors and agent registrations

- Delete the agent registration created from `agent/register_gemini_enterprise.md`.
- Delete the custom MCP connector pointing at `codemender-mcp-server`.
- Delete the Data Insights data source configuration if it was added only for the lab.
- In APIs & Services > Credentials, delete the OAuth 2.0 Web client used by the connector.

### 3. Delete the Agent Engine resource

```bash
gcloud ai reasoning-engines list --region="$REGION"   # confirm in your environment; or use the Vertex AI console
```

Delete it with the Vertex AI SDK (works without extra CLI components):

```bash
python3 -c "
import vertexai
from vertexai import agent_engines
vertexai.init(project='$GCP_PROJECT_ID', location='$REGION')
agent_engines.get('projects/$PROJECT_NUMBER/locations/$REGION/reasoningEngines/<ID>').delete(force=True)
"
```

Then remove the staging bucket:

```bash
gcloud storage rm -r gs://your-gcp-project-id-agent-staging
```

### 4. Terraform destroy

```bash
cd infra/terraform
terraform plan -destroy
terraform destroy
```

This removes Cloud Run services and the job, Pub/Sub topics and subscriptions, log sinks, the VPC and firewall rules, datasets, buckets, service accounts, IAM bindings and the WIF pool. If buckets or datasets fail to delete because they are not empty, either set `force_destroy` / `delete_contents_on_destroy` and re-run, or empty them:

```bash
gcloud storage rm -r "gs://${GCP_PROJECT_ID}-sandbox-inputs/**"
bq rm -r -f -d "${GCP_PROJECT_ID}:security_lab"
```

Delete anything you created by hand outside Terraform (for example a `security_logs` table you loaded from seed data if the dataset is not Terraform-managed).

### 5. Delete container images

```bash
gcloud artifacts repositories delete security-lab --location="$REGION" --quiet
```

If Terraform owns the repo, step 4 already removed it. Also delete any Cloud Build source buckets (`gs://${GCP_PROJECT_ID}_cloudbuild`) if they were created only for the lab.

### 6. Delete secrets

```bash
for s in wiz-client-secret github-mcp-pat codemender-api-token; do
  gcloud secrets delete "$s" --quiet
done
```

Skip `wiz-client-secret` if it predates the lab and other services use it.

### 7. Revoke the GitHub PAT

GitHub > Settings > Developer settings > Personal access tokens: delete the token used for GitHub MCP. Also revoke any OAuth app authorizations created for the lab. Delete repo secrets `CODEMENDER_API_URL` and `CODEMENDER_API_TOKEN` and the WIF repository variables if you keep the repo.

### 8. Clean up Wiz

- Delete the Wiz service account created for the lab (Settings > Service Accounts).
- If MCP was enabled only for the lab, disable it (Settings > Tenant > AI Features; confirm in your environment).

### 9. Delete or archive the GitHub repo

```bash
gh repo archive "${GITHUB_ORG}/payment-service" --yes
# or, to delete (needs delete_repo scope):
gh repo delete "${GITHUB_ORG}/payment-service" --yes
```

### 10. Remove the WIF pool

If Terraform did not delete it:

```bash
gcloud iam workload-identity-pools delete github-pool --location=global --quiet
```

A deleted pool is soft-deleted for 30 days. During that time the name `github-pool` cannot be reused. To reuse the name within 30 days, undelete it (`gcloud iam workload-identity-pools undelete github-pool --location=global`) or pick a new name in Terraform.

---

## Verification

Each command should return nothing (or "Listed 0 items").

```bash
gcloud run services list --region="$REGION" --filter="metadata.name:(codemender-mcp-server security-log-ingestion)"
gcloud run jobs list --region="$REGION" --filter="metadata.name:codemender-sandbox"
gcloud pubsub topics list --filter="name:security-logs"
gcloud pubsub subscriptions list --filter="name:security-logs"
gcloud logging sinks list --filter="name:(security-logs-to-pubsub model-armor-to-bq vpcsc-to-bq)"
gcloud compute networks list --filter="name=sandbox-vpc"
gcloud compute firewall-rules list --filter="name~^sandbox-"
gcloud artifacts repositories list --location="$REGION" --filter="name~security-lab"
gcloud secrets list --filter="name~(wiz-client-secret|github-mcp-pat|codemender-api-token)"
gcloud iam service-accounts list --filter="email~(codemender-mcp-sa|log-ingestion-sa|sandbox-runner-sa|pubsub-push-sa|github-actions-sa)"
gcloud iam workload-identity-pools list --location=global --filter="name~github-pool"   # shows state DELETED for 30 days
gcloud storage ls | grep -E "sandbox-inputs|agent-staging"
bq ls --project_id="$GCP_PROJECT_ID" | grep -E "security_lab|security_logs|scc_export|codemender"
```

`codemender` may be an existing dataset used outside the lab. Delete it only if the lab created it.

Check IAM for leftover bindings to deleted accounts (they show as `deleted:serviceAccount:...`):

```bash
gcloud projects get-iam-policy "$GCP_PROJECT_ID" --format=json | grep -E "deleted:|discoveryengine|aiplatform-re"
```

Remove any lab-only bindings that remain, for example `roles/geminidataanalytics.dataAgentUser` for participants.

## What you removed

Gemini Enterprise registrations and connector, Agent Engine resource, all Terraform-managed infrastructure, images, secrets, the GitHub PAT and repo, the Wiz service account, and the WIF pool.
