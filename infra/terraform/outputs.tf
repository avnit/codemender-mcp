output "mcp_server_url" {
  description = "codemender-mcp-server base URL (null until deploy_services = true)."
  value       = local.mcp_url
}

output "mcp_endpoint" {
  description = "MCP endpoint for Gemini Enterprise and the ADK agent (CODEMENDER_MCP_URL)."
  value       = var.deploy_services ? "${local.mcp_url}/mcp" : null
}

output "log_ingestion_url" {
  description = "security-log-ingestion base URL (null until deploy_services = true)."
  value       = local.ingestion_url
}

output "sandbox_job_name" {
  description = "Cloud Run Job name for the validation sandbox."
  value       = local.sandbox_job_name
}

output "sandbox_bucket" {
  description = "Sandbox inputs bucket name (SANDBOX_BUCKET)."
  value       = google_storage_bucket.sandbox_inputs.name
}

output "agent_staging_bucket" {
  description = "Agent Engine staging bucket (STAGING_BUCKET)."
  value       = "gs://${google_storage_bucket.agent_staging.name}"
}

output "artifact_registry_prefix" {
  description = "Prefix for image URIs: <prefix>/<image>:<tag>."
  value       = local.ar_prefix
}

output "wif_provider_name" {
  description = "Full WIF provider resource name (GCP_WIF_PROVIDER)."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "github_actions_sa_email" {
  description = "Service account impersonated by GitHub Actions (GCP_SA_EMAIL)."
  value       = google_service_account.github_actions.email
}

output "dataset_ids" {
  description = "Lab BigQuery dataset IDs."
  value       = local.lab_dataset_ids
}

output "discovery_engine_service_agent" {
  description = "Discovery Engine service agent (Gemini Enterprise custom MCP connector caller)."
  value       = local.discovery_engine_service_agent
}

output "agent_engine_service_agent" {
  description = "Agent Engine (Reasoning Engine) service agent."
  value       = local.agent_engine_service_agent
}

output "github_actions_vars" {
  description = "Repository variables for payment-service (Settings > Secrets and variables > Actions > Variables)."
  value = {
    GCP_WIF_PROVIDER = google_iam_workload_identity_pool_provider.github.name
    GCP_SA_EMAIL     = google_service_account.github_actions.email
    GCP_PROJECT_ID   = var.project_id
    GCP_REGION       = var.region
    SANDBOX_BUCKET   = google_storage_bucket.sandbox_inputs.name
  }
}
