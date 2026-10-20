locals {
  required_apis = [
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "bigquery.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "aiplatform.googleapis.com",
    "discoveryengine.googleapis.com",
    "securitycenter.googleapis.com",
    "modelarmor.googleapis.com",
    # Gemini Data Analytics (conversational analytics / data agents).
    # Service name: confirm in your environment.
    "geminidataanalytics.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.required_apis)

  project = var.project_id
  service = each.value

  # Leave APIs enabled on destroy; other workloads in the project may use them.
  disable_on_destroy         = false
  disable_dependent_services = false
}
