resource "google_artifact_registry_repository" "security_lab" {
  project       = var.project_id
  location      = var.region
  repository_id = local.ar_repository_id
  format        = "DOCKER"
  description   = "Images for codemender-mcp-server, security-log-ingestion and codemender-sandbox."

  depends_on = [google_project_service.apis]
}
