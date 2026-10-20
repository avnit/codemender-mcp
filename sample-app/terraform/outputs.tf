output "service_url" {
  description = "payment-service URL."
  value       = google_cloud_run_v2_service.payment_service.uri
}

output "service_account_email" {
  description = "payment-service-sa email (intentionally over-permissioned, CM-0003)."
  value       = google_service_account.payment_service.email
}

output "resource_id" {
  description = "Resource ID in the format used by seed-data/code_to_cloud_map.jsonl."
  value       = "//run.googleapis.com/projects/${var.project_id}/locations/${var.region}/services/${google_cloud_run_v2_service.payment_service.name}"
}
