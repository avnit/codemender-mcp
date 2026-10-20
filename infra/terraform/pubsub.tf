resource "google_pubsub_topic" "security_logs" {
  project = var.project_id
  name    = "security-logs"

  depends_on = [google_project_service.apis]
}

resource "google_pubsub_topic" "security_logs_dlq" {
  project = var.project_id
  name    = "security-logs-dlq"

  depends_on = [google_project_service.apis]
}

# Push subscription to the ingestion service. Needs the service URL, so it
# exists only when deploy_services = true.
resource "google_pubsub_subscription" "security_logs_push" {
  count = var.deploy_services ? 1 : 0

  project              = var.project_id
  name                 = "security-logs-push"
  topic                = google_pubsub_topic.security_logs.id
  ack_deadline_seconds = 60

  push_config {
    push_endpoint = "${local.ingestion_url}/pubsub/push"

    oidc_token {
      service_account_email = google_service_account.pubsub_push.email
      audience              = local.ingestion_url
    }
  }

  # Unparseable messages get a 2xx from the service; only transient
  # BigQuery failures (HTTP 500) are retried and then dead-lettered.
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.security_logs_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  depends_on = [
    google_cloud_run_v2_service_iam_member.ingestion_invoker_pubsub_push,
    google_service_account_iam_member.pubsub_agent_token_creator,
  ]
}

resource "google_pubsub_subscription" "security_logs_dlq_sub" {
  project                    = var.project_id
  name                       = "security-logs-dlq-sub"
  topic                      = google_pubsub_topic.security_logs_dlq.id
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"
}

# ---------------------------------------------------------------------------
# IAM for the Pub/Sub service agent and the push identity
# ---------------------------------------------------------------------------

# Dead-lettering: the Pub/Sub service agent publishes to the DLQ topic ...
resource "google_pubsub_topic_iam_member" "dlq_publisher_pubsub_agent" {
  project = var.project_id
  topic   = google_pubsub_topic.security_logs_dlq.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${local.pubsub_service_agent}"

  depends_on = [google_project_service.apis]
}

# ... and must be able to acknowledge on the source subscription.
resource "google_pubsub_subscription_iam_member" "push_sub_subscriber_pubsub_agent" {
  count = var.deploy_services ? 1 : 0

  project      = var.project_id
  subscription = google_pubsub_subscription.security_logs_push[0].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${local.pubsub_service_agent}"
}

# The Pub/Sub service agent mints OIDC tokens for pubsub-push-sa.
resource "google_service_account_iam_member" "pubsub_agent_token_creator" {
  service_account_id = google_service_account.pubsub_push.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${local.pubsub_service_agent}"

  depends_on = [google_project_service.apis]
}

# pubsub-push-sa may invoke the ingestion service.
resource "google_cloud_run_v2_service_iam_member" "ingestion_invoker_pubsub_push" {
  count = var.deploy_services ? 1 : 0

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.log_ingestion[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.pubsub_push.email}"
}
