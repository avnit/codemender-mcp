# Log sinks. Filters are copied from NAMING.md.

# CodeMender events, sandbox results and IAM policy changes -> Pub/Sub -> ingestion.
resource "google_logging_project_sink" "security_logs_to_pubsub" {
  project                = var.project_id
  name                   = "security-logs-to-pubsub"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.security_logs.id}"
  unique_writer_identity = true

  filter = "logName:\"logs/codemender\" OR (resource.type=\"cloud_run_job\" AND resource.labels.job_name=\"codemender-sandbox\" AND jsonPayload.event_type=\"SANDBOX_RESULT\") OR (protoPayload.methodName=\"SetIamPolicy\" AND logName:\"cloudaudit.googleapis.com%2Factivity\")"
}

# Model Armor sanitize operations -> BigQuery security_logs.
# Log name: confirm in your environment.
resource "google_logging_project_sink" "model_armor_to_bq" {
  project                = var.project_id
  name                   = "model-armor-to-bq"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.security_logs.dataset_id}"
  unique_writer_identity = true

  filter = "logName=\"projects/${var.project_id}/logs/modelarmor.googleapis.com%2Fsanitize_operations\""

  bigquery_options {
    use_partitioned_tables = true
  }
}

# VPC Service Controls violations -> BigQuery security_logs.
resource "google_logging_project_sink" "vpcsc_to_bq" {
  project                = var.project_id
  name                   = "vpcsc-to-bq"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.security_logs.dataset_id}"
  unique_writer_identity = true

  filter = "logName=\"projects/${var.project_id}/logs/cloudaudit.googleapis.com%2Fpolicy\" AND protoPayload.metadata.\"@type\"=\"type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata\""

  bigquery_options {
    use_partitioned_tables = true
  }
}

# ---------------------------------------------------------------------------
# Writer identity IAM
# ---------------------------------------------------------------------------
resource "google_pubsub_topic_iam_member" "security_logs_sink_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.security_logs.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.security_logs_to_pubsub.writer_identity
}

resource "google_bigquery_dataset_iam_member" "model_armor_sink_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.security_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.model_armor_to_bq.writer_identity
}

resource "google_bigquery_dataset_iam_member" "vpcsc_sink_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.security_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.vpcsc_to_bq.writer_identity
}
