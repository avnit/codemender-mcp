# Cloud Run services and the sandbox job. All gated by var.deploy_services so
# phase 1 can create Artifact Registry before the images exist.

locals {
  # Env vars for codemender-mcp-server (NAMING.md). PORT is not set here:
  # Cloud Run reserves PORT and sets it from the container port (8080).
  # WIZ_CLIENT_SECRET is injected from Secret Manager below.
  mcp_env = {
    GCP_PROJECT_ID        = var.project_id
    REGION                = var.region
    SERVICE_NAME          = local.mcp_service_name
    BQ_DATASET            = local.bq_dataset
    BQ_TABLE              = local.bq_table
    LOG_NAME_FILTER       = "codemender"
    WIZ_CLIENT_ID         = var.wiz_client_id
    WIZ_API_ENDPOINT      = var.wiz_api_endpoint
    WIZ_AUTH_URL          = var.wiz_auth_url
    WIZ_AUDIENCE          = var.wiz_audience
    WIZ_SECRET_NAME       = local.wiz_secret_name
    SECURITY_DATASET      = local.security_dataset
    SECURITY_EVENTS_TABLE = local.security_events_table
    SANDBOX_RUNS_TABLE    = local.sandbox_runs_table
    CODE_TO_CLOUD_TABLE   = local.code_to_cloud_table
    SCC_DATASET           = local.scc_dataset
    SCC_TABLE             = local.scc_table
    SECURITY_LOGS_DATASET = local.security_logs_dataset
    MODEL_ARMOR_TABLE     = local.model_armor_table
    VPCSC_TABLE           = local.vpcsc_table
    SANDBOX_JOB_NAME      = local.sandbox_job_name
    SANDBOX_REGION        = var.region
    SANDBOX_BUCKET        = local.sandbox_bucket_name
  }

  ingestion_env = {
    GCP_PROJECT_ID         = var.project_id
    BQ_DATASET             = local.bq_dataset
    BQ_TABLE               = local.bq_table
    SECURITY_DATASET       = local.security_dataset
    SECURITY_EVENTS_TABLE  = local.security_events_table
    SANDBOX_RUNS_TABLE     = local.sandbox_runs_table
    INGESTION_ERRORS_TABLE = local.ingestion_errors_table
  }

  # Defaults for the sandbox job. Per-run values (RUN_ID, REPOSITORY,
  # COMMIT_SHA, SOURCE_URI, PATCH_URI, ISSUE_ID) are passed as overrides by
  # start_sandbox_validation or `gcloud run jobs execute --update-env-vars`.
  sandbox_env = {
    POC_TEST        = "tests/poc"
    UNIT_TEST_CMD   = "python -m pytest -q tests/unit"
    TIMEOUT_SECONDS = "600"
  }
}

# ---------------------------------------------------------------------------
# codemender-mcp-server
# Ingress all, but NOT public: there is no allUsers invoker binding. Callers
# (Gemini Enterprise via the Discovery Engine service agent, Agent Engine
# service agent) are granted roles/run.invoker in iam.tf.
# ---------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "mcp_server" {
  count = var.deploy_services ? 1 : 0

  project             = var.project_id
  name                = local.mcp_service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false # lab only

  template {
    service_account = google_service_account.codemender_mcp.email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    containers {
      image = local.mcp_server_image

      ports {
        container_port = 8080
      }

      dynamic "env" {
        for_each = local.mcp_env
        content {
          name  = env.key
          value = env.value
        }
      }

      env {
        name = "WIZ_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.wiz_client_secret.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_secret_manager_secret_iam_member.wiz_secret_mcp_sa,
  ]
}

# ---------------------------------------------------------------------------
# security-log-ingestion
# Ingress "internal-and-cloud-load-balancing" would block Pub/Sub push,
# because push requests do not originate from the VPC. Use ingress all and
# rely on IAM: only pubsub-push-sa has roles/run.invoker (pubsub.tf), and
# the push request carries an OIDC token for that SA.
# ---------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "log_ingestion" {
  count = var.deploy_services ? 1 : 0

  project             = var.project_id
  name                = local.ingestion_service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false # lab only

  template {
    service_account = google_service_account.log_ingestion.email

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = local.log_ingestion_image

      ports {
        container_port = 8080
      }

      dynamic "env" {
        for_each = local.ingestion_env
        content {
          name  = env.key
          value = env.value
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# ---------------------------------------------------------------------------
# codemender-sandbox (Cloud Run Job)
# Cloud Run Jobs run only on the second-generation execution environment
# (microVM sandbox). gVisor (gen1) is not available for jobs, even though the
# lab brief asked for gVisor. Isolation here comes from: gen2 microVM +
# sandbox-vpc with all egress denied except the restricted Google APIs VIP +
# sandbox-runner-sa with no project roles.
# ---------------------------------------------------------------------------
resource "google_cloud_run_v2_job" "sandbox" {
  count = var.deploy_services ? 1 : 0

  project             = var.project_id
  name                = local.sandbox_job_name
  location            = var.region
  deletion_protection = false # lab only

  template {
    task_count  = 1
    parallelism = 1

    template {
      service_account       = google_service_account.sandbox_runner.email
      max_retries           = 0
      timeout               = "900s"
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

      # Direct VPC egress. ALL_TRAFFIC sends every packet into sandbox-vpc,
      # where the firewall allows only tcp:443 to 199.36.153.4/30.
      vpc_access {
        egress = "ALL_TRAFFIC"
        network_interfaces {
          network    = google_compute_network.sandbox_vpc.id
          subnetwork = google_compute_subnetwork.sandbox_subnet.id
        }
      }

      containers {
        image = local.sandbox_image

        dynamic "env" {
          for_each = local.sandbox_env
          content {
            name  = env.key
            value = env.value
          }
        }

        resources {
          limits = {
            cpu    = "2"
            memory = "2Gi"
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.apis,
    google_compute_firewall.sandbox_deny_all_egress,
    google_compute_firewall.sandbox_allow_restricted_apis,
    google_dns_record_set.googleapis_wildcard_cname,
    google_dns_record_set.restricted_googleapis_a,
    google_storage_bucket_iam_member.sandbox_runner_object_viewer,
  ]
}
