# IAM bindings from NAMING.md. Additive *_iam_member resources only, so
# existing bindings in the project are not removed.
#
# Secret accessor bindings are in secrets.tf. Pub/Sub bindings are in
# pubsub.tf. Log sink writer bindings are in logging.tf.

# ===========================================================================
# Participants
# ===========================================================================
resource "google_project_iam_member" "participants_data_agent_user" {
  for_each = toset(var.participant_members)

  project = var.project_id
  role    = "roles/geminidataanalytics.dataAgentUser"
  member  = each.value
}

resource "google_project_iam_member" "participants_bq_job_user" {
  for_each = toset(var.participant_members)

  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = each.value
}

resource "google_project_iam_member" "participants_logging_viewer" {
  for_each = toset(var.participant_members)

  project = var.project_id
  role    = "roles/logging.viewer"
  member  = each.value
}

resource "google_bigquery_dataset_iam_member" "participants_data_viewer" {
  for_each = local.participant_dataset_pairs

  project    = var.project_id
  dataset_id = local.lab_dataset_ids[each.value.dataset]
  role       = "roles/bigquery.dataViewer"
  member     = each.value.member
}

# ===========================================================================
# codemender-mcp-sa (custom MCP server)
# ===========================================================================
resource "google_bigquery_dataset_iam_member" "mcp_sa_data_viewer" {
  for_each = local.lab_dataset_ids

  project    = var.project_id
  dataset_id = each.value
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

resource "google_project_iam_member" "mcp_sa_bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

resource "google_project_iam_member" "mcp_sa_logging_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

# run.developer on the sandbox job only: needed for run.jobs.runWithOverrides
# (start_sandbox_validation passes per-run env vars).
resource "google_cloud_run_v2_job_iam_member" "mcp_sa_job_developer" {
  count = var.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.sandbox[0].name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

# run.viewer on the sandbox job: read executions for get_sandbox_result.
resource "google_cloud_run_v2_job_iam_member" "mcp_sa_job_viewer" {
  count = var.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.sandbox[0].name
  role     = "roles/run.viewer"
  member   = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

# Executing a job that runs as sandbox-runner-sa requires actAs on that SA.
# Confirm in your environment (some setups only need this at deploy time).
resource "google_service_account_iam_member" "mcp_sa_act_as_sandbox_runner" {
  service_account_id = google_service_account.sandbox_runner.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

resource "google_storage_bucket_iam_member" "mcp_sa_sandbox_object_viewer" {
  bucket = google_storage_bucket.sandbox_inputs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

# ===========================================================================
# log-ingestion-sa (security-log-ingestion)
# ===========================================================================
resource "google_bigquery_dataset_iam_member" "ingestion_sa_security_lab_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.security_lab.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.log_ingestion.email}"
}

resource "google_bigquery_dataset_iam_member" "ingestion_sa_codemender_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.codemender.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.log_ingestion.email}"
}

resource "google_project_iam_member" "ingestion_sa_bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.log_ingestion.email}"
}

# ===========================================================================
# sandbox-runner-sa: bucket-level objectViewer ONLY. No project roles.
# ===========================================================================
resource "google_storage_bucket_iam_member" "sandbox_runner_object_viewer" {
  bucket = google_storage_bucket.sandbox_inputs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.sandbox_runner.email}"
}

# ===========================================================================
# github-actions-sa (impersonated from GitHub through WIF, see wif.tf)
# ===========================================================================
resource "google_cloud_run_v2_job_iam_member" "github_actions_job_developer" {
  count = var.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.sandbox[0].name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.github_actions.email}"
}

resource "google_service_account_iam_member" "github_actions_act_as_sandbox_runner" {
  service_account_id = google_service_account.sandbox_runner.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_actions.email}"
}

resource "google_storage_bucket_iam_member" "github_actions_sandbox_object_admin" {
  bucket = google_storage_bucket.sandbox_inputs.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.github_actions.email}"
}

resource "google_project_iam_member" "github_actions_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.github_actions.email}"
}

# Read SANDBOX_RESULT log lines to post the verdict back to the PR.
resource "google_project_iam_member" "github_actions_logging_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.github_actions.email}"
}

# ===========================================================================
# Google-managed service agents
# ===========================================================================

# Gemini Enterprise custom MCP connector calls the MCP server as the
# Discovery Engine service agent.
resource "google_cloud_run_v2_service_iam_member" "mcp_invoker_discovery_engine" {
  count = var.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.mcp_server[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.discovery_engine_service_agent}"

  depends_on = [google_project_service.apis]
}

# The ADK agent on Agent Engine calls the MCP server and reads logs as the
# Agent Engine (Reasoning Engine) service agent. This agent may not exist
# until Agent Engine is first used; see the note in secrets.tf.
resource "google_cloud_run_v2_service_iam_member" "mcp_invoker_agent_engine" {
  count = var.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.mcp_server[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${local.agent_engine_service_agent}"

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "agent_engine_logging_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${local.agent_engine_service_agent}"

  depends_on = [google_project_service.apis]
}
