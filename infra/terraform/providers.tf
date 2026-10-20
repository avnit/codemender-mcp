provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# Project number is needed to build Google-managed service agent emails.
data "google_project" "this" {
  project_id = var.project_id
}
