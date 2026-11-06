# Lab / sandbox use only. See the banner in main.tf.

output "service_url" {
  description = "URL of the payment-service Cloud Run service."
  value       = google_cloud_run_v2_service.payment_service.uri
}

output "service_account_email" {
  description = "Runtime service account (over-permissioned on purpose, CM-0003)."
  value       = google_service_account.payment_service.email
}
