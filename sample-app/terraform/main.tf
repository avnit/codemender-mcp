# =============================================================================
# INTENTIONALLY VULNERABLE - LAB / SANDBOX USE ONLY
#
# This Terraform deploys the payment-service demo with a deliberately
# over-permissioned service account (finding CM-0003, CWE-250 / CWE-732).
# It exists so Wiz, SCC and the AI security agent have a real misconfiguration
# to find and fix. Do not apply it unless the facilitator tells you to, and
# never apply it in a project that holds real data.
# =============================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_service_account" "payment_service" {
  account_id   = "payment-service-sa"
  display_name = "payment-service runtime (intentionally over-permissioned lab demo)"
}

# CM-0003: INTENTIONALLY VULNERABLE.
# roles/editor at project level gives the service write access to almost every
# resource in the project. The fix the agent should propose is to remove this
# binding and grant only what the app needs (it needs no Google Cloud APIs;
# at most roles/logging.logWriter, which Cloud Run already provides).
resource "google_project_iam_member" "payment_service_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.payment_service.email}"
}

resource "google_cloud_run_v2_service" "payment_service" {
  name                = "payment-service"
  location            = var.region
  deletion_protection = false
  ingress             = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.payment_service.email

    containers {
      image = var.image

      env {
        name  = "HOST"
        value = "0.0.0.0"
      }

      ports {
        container_port = 8080
      }
    }
  }

  labels = {
    app         = "payment-service"
    environment = "production" # label used by the Wiz "production" queries in the lab
    lab         = "ai-security-agent"
  }
}

# Public access is off by default. Set allow_unauthenticated = true only if the
# facilitator wants Wiz to see the service as internet-facing.
resource "google_cloud_run_v2_service_iam_member" "public" {
  count    = var.allow_unauthenticated ? 1 : 0
  name     = google_cloud_run_v2_service.payment_service.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}
