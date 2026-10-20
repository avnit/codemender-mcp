# BigQuery datasets and tables. Canonical schemas live in ./schemas/*.json.
# Schema files use the legacy type names INTEGER/BOOLEAN (equivalent to
# INT64/BOOL in NAMING.md). The API returns the legacy names, so using them
# avoids a perpetual diff in terraform plan.
#
# deletion_protection = false and delete_contents_on_destroy = true because
# this is a lab project. Do not copy these settings to production.

resource "google_bigquery_dataset" "codemender" {
  project                    = var.project_id
  dataset_id                 = local.bq_dataset
  location                   = var.bq_location
  description                = "CodeMender findings (existing table used by the custom MCP server)."
  delete_contents_on_destroy = true

  depends_on = [google_project_service.apis]
}

resource "google_bigquery_dataset" "security_lab" {
  project                    = var.project_id
  dataset_id                 = local.security_dataset
  location                   = var.bq_location
  description                = "Normalized security events, sandbox runs, code-to-cloud map and ingestion errors."
  delete_contents_on_destroy = true

  depends_on = [google_project_service.apis]
}

resource "google_bigquery_dataset" "scc_export" {
  project                    = var.project_id
  dataset_id                 = local.scc_dataset
  location                   = var.bq_location
  description                = "Security Command Center continuous export destination."
  delete_contents_on_destroy = true

  depends_on = [google_project_service.apis]
}

resource "google_bigquery_dataset" "security_logs" {
  project                    = var.project_id
  dataset_id                 = local.security_logs_dataset
  location                   = var.bq_location
  description                = "Log sink destination for Model Armor and VPC Service Controls logs. Tables are created by the sinks."
  delete_contents_on_destroy = true

  depends_on = [google_project_service.apis]
}

# ---------------------------------------------------------------------------
# codemender.findings
# ---------------------------------------------------------------------------
resource "google_bigquery_table" "codemender_findings" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.codemender.dataset_id
  table_id            = local.bq_table
  description         = "CodeMender findings."
  deletion_protection = false
  schema              = file("${path.module}/schemas/codemender_findings.json")

  time_partitioning {
    type  = "DAY"
    field = "created_at"
  }
}

# ---------------------------------------------------------------------------
# security_lab.*
# ---------------------------------------------------------------------------
resource "google_bigquery_table" "security_events" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.security_lab.dataset_id
  table_id            = local.security_events_table
  description         = "One row per ingested security log entry (row id = LogEntry insertId)."
  deletion_protection = false
  schema              = file("${path.module}/schemas/security_events.json")

  time_partitioning {
    type  = "DAY"
    field = "event_timestamp"
  }

  clustering = ["event_type", "severity"]
}

resource "google_bigquery_table" "sandbox_runs" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.security_lab.dataset_id
  table_id            = local.sandbox_runs_table
  description         = "One row per codemender-sandbox execution (SANDBOX_RESULT)."
  deletion_protection = false
  schema              = file("${path.module}/schemas/sandbox_runs.json")
}

resource "google_bigquery_table" "code_to_cloud_map" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.security_lab.dataset_id
  table_id            = local.code_to_cloud_table
  description         = "Fallback mapping from cloud resources to source repository, Dockerfile and Terraform path."
  deletion_protection = false
  schema              = file("${path.module}/schemas/code_to_cloud_map.json")
}

resource "google_bigquery_table" "ingestion_errors" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.security_lab.dataset_id
  table_id            = local.ingestion_errors_table
  description         = "Messages the ingestion service could not parse."
  deletion_protection = false
  schema              = file("${path.module}/schemas/ingestion_errors.json")
}

# ---------------------------------------------------------------------------
# scc_export.findings
# Pre-created with a subset of the SCC export schema so seed data and lab
# queries work before (or without) the real export. The real SCC export may
# create or manage its own table and add columns; if the export refuses to
# write to a pre-existing table, delete this table and let the export create
# it. Confirm in your environment.
# ---------------------------------------------------------------------------
resource "google_bigquery_table" "scc_findings" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.scc_export.dataset_id
  table_id            = local.scc_table
  description         = "SCC findings (subset schema; confirm in your environment)."
  deletion_protection = false
  schema              = file("${path.module}/schemas/scc_findings.json")

  # The SCC export may add columns. Do not let Terraform fight it.
  lifecycle {
    ignore_changes = [schema]
  }
}

# ---------------------------------------------------------------------------
# security_logs.* tables are NOT created here.
# The model-armor-to-bq and vpcsc-to-bq sinks create their tables
# (modelarmor_googleapis_com_sanitize_operations, cloudaudit_googleapis_com_policy)
# from the log ID on first write. If Terraform also created them, the sink
# and Terraform would both own the schema. schemas/model_armor_logs.json and
# schemas/vpcsc_logs.json are simplified versions used only by seed-data/ to
# pre-create those tables in projects with no real traffic yet.
# ---------------------------------------------------------------------------
