# Sandbox inputs: source tarballs and patches.
#   gs://BUCKET/sources/<repo_owner>__<repo_name>/<commit_sha>.tar.gz
#   gs://BUCKET/patches/<issue_id>/<run_id>.diff
resource "google_storage_bucket" "sandbox_inputs" {
  project                     = var.project_id
  name                        = local.sandbox_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true # lab only

  versioning {
    enabled = false
  }

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.apis]
}

# Staging bucket for Vertex AI Agent Engine deployments (STAGING_BUCKET).
resource "google_storage_bucket" "agent_staging" {
  project                     = var.project_id
  name                        = local.agent_staging_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true # lab only

  depends_on = [google_project_service.apis]
}
