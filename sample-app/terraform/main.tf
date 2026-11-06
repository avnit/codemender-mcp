# =====================================================================
# INTENTIONALLY VULNERABLE INFRASTRUCTURE - LAB / SANDBOX USE ONLY.
# CM-0003 / CWE-250: payment-service-sa gets roles/editor at project
# level. The service needs no project-wide permissions.
# Do NOT apply this in the lab unless the facilitator tells you to. The
# lab uses this file as a code-to-cloud finding target, not as a deploy.
# =====================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_service_account" "payment_service" {
  account_id   = "payment-service-sa"
  display_name = "payment-service runtime (lab, intentionally over-permissioned)"
}

# VULNERABLE (CM-0003): primitive Editor role on the whole project.
resource "google_project_iam_member" "payment_service_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.payment_service.email}"
}

resource "google_cloud_run_v2_service" "payment_service" {
  name     = "payment-service"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  labels = {
    app                      = "payment-service"
    intentionally-vulnerable = "true"
  }

  template {
    service_account = google_service_account.payment_service.email

    containers {
      image = var.image

      ports {
        container_port = 8080
      }
    }
  }

  deletion_protection = false
}
