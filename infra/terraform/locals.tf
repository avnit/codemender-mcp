locals {
  project_number = data.google_project.this.number

  # Artifact Registry
  ar_repository_id = "security-lab"
  ar_host          = "${var.region}-docker.pkg.dev"
  ar_prefix        = "${local.ar_host}/${var.project_id}/${local.ar_repository_id}"

  # Service, job and image names (NAMING.md)
  mcp_service_name       = "codemender-mcp-server"
  ingestion_service_name = "security-log-ingestion"
  sandbox_job_name       = "codemender-sandbox"

  mcp_server_image    = var.mcp_server_image != "" ? var.mcp_server_image : "${local.ar_prefix}/${local.mcp_service_name}:${var.image_tag}"
  log_ingestion_image = var.log_ingestion_image != "" ? var.log_ingestion_image : "${local.ar_prefix}/${local.ingestion_service_name}:${var.image_tag}"
  sandbox_image       = var.sandbox_image != "" ? var.sandbox_image : "${local.ar_prefix}/${local.sandbox_job_name}:${var.image_tag}"

  # Buckets
  sandbox_bucket_name       = "${var.project_id}-sandbox-inputs"
  agent_staging_bucket_name = "${var.project_id}-agent-staging"

  # BigQuery (NAMING.md)
  bq_dataset             = "codemender"
  bq_table               = "findings"
  security_dataset       = "security_lab"
  security_events_table  = "security_events"
  sandbox_runs_table     = "sandbox_runs"
  code_to_cloud_table    = "code_to_cloud_map"
  ingestion_errors_table = "ingestion_errors"
  scc_dataset            = "scc_export"
  scc_table              = "findings"
  security_logs_dataset  = "security_logs"
  model_armor_table      = "modelarmor_googleapis_com_sanitize_operations"
  vpcsc_table            = "cloudaudit_googleapis_com_policy"

  # Secrets
  wiz_secret_name = "wiz-client-secret"

  # Google-managed service agents (emails derived from the project number)
  discovery_engine_service_agent = "service-${local.project_number}@gcp-sa-discoveryengine.iam.gserviceaccount.com"
  agent_engine_service_agent     = "service-${local.project_number}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
  pubsub_service_agent           = "service-${local.project_number}@gcp-sa-pubsub.iam.gserviceaccount.com"

  # Map of dataset key -> dataset resource, used for per-dataset IAM.
  lab_dataset_ids = {
    codemender    = google_bigquery_dataset.codemender.dataset_id
    security_lab  = google_bigquery_dataset.security_lab.dataset_id
    scc_export    = google_bigquery_dataset.scc_export.dataset_id
    security_logs = google_bigquery_dataset.security_logs.dataset_id
  }

  # participant x dataset pairs for dataViewer bindings
  participant_dataset_pairs = {
    for pair in setproduct(var.participant_members, keys(local.lab_dataset_ids)) :
    "${pair[0]}|${pair[1]}" => { member = pair[0], dataset = pair[1] }
  }

  # Cloud Run URLs (null when deploy_services = false)
  ingestion_url = var.deploy_services ? google_cloud_run_v2_service.log_ingestion[0].uri : null
  mcp_url       = var.deploy_services ? google_cloud_run_v2_service.mcp_server[0].uri : null
}
