# Secret containers only. Terraform does NOT create secret versions, so secret
# values never land in Terraform state. Add values with gcloud, for example:
#
#   printf '%s' 'REPLACE_ME' | gcloud secrets versions add wiz-client-secret --data-file=-
#   printf '%s' 'ghp_REPLACE_ME' | gcloud secrets versions add github-mcp-pat --data-file=-
#   printf '%s' 'REPLACE_ME' | gcloud secrets versions add codemender-api-token --data-file=-
#
# codemender-mcp-server reads wiz-client-secret at deploy time (version
# "latest"), so add that version before phase 2 (deploy_services = true).

resource "google_secret_manager_secret" "wiz_client_secret" {
  project   = var.project_id
  secret_id = local.wiz_secret_name

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "github_mcp_pat" {
  project   = var.project_id
  secret_id = "github-mcp-pat"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "codemender_api_token" {
  project   = var.project_id
  secret_id = "codemender-api-token"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

# codemender-mcp-sa reads the Wiz client secret.
resource "google_secret_manager_secret_iam_member" "wiz_secret_mcp_sa" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.wiz_client_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.codemender_mcp.email}"
}

# The Agent Engine service agent reads the GitHub PAT for the GitHub remote MCP.
# This service agent may not exist until Agent Engine is first used in the
# project; if apply fails on this binding, deploy an agent once (or run
# `gcloud beta services identity create --service=aiplatform.googleapis.com`)
# and re-apply. Confirm in your environment.
resource "google_secret_manager_secret_iam_member" "github_pat_agent_engine" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.github_mcp_pat.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.agent_engine_service_agent}"
}
