resource "google_service_account" "codemender_mcp" {
  project      = var.project_id
  account_id   = "codemender-mcp-sa"
  display_name = "codemender-mcp-server runtime"

  depends_on = [google_project_service.apis]
}

resource "google_service_account" "log_ingestion" {
  project      = var.project_id
  account_id   = "log-ingestion-sa"
  display_name = "security-log-ingestion runtime"

  depends_on = [google_project_service.apis]
}

# sandbox-runner-sa has NO project-level roles. Its only grant is
# roles/storage.objectViewer on the sandbox inputs bucket (iam.tf). Untrusted
# code runs as this identity, so keep it that way.
resource "google_service_account" "sandbox_runner" {
  project      = var.project_id
  account_id   = "sandbox-runner-sa"
  display_name = "codemender-sandbox runtime (no project roles)"

  depends_on = [google_project_service.apis]
}

resource "google_service_account" "pubsub_push" {
  project      = var.project_id
  account_id   = "pubsub-push-sa"
  display_name = "Pub/Sub push identity for security-log-ingestion"

  depends_on = [google_project_service.apis]
}

resource "google_service_account" "github_actions" {
  project      = var.project_id
  account_id   = "github-actions-sa"
  display_name = "GitHub Actions (WIF) for payment-service workflows"

  depends_on = [google_project_service.apis]
}
