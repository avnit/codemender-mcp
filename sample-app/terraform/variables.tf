# Lab / sandbox use only. See the banner in main.tf.

variable "project_id" {
  description = "GCP project ID."
  type        = string
  default     = "your-gcp-project-id"
}

variable "region" {
  description = "Region for the Cloud Run service."
  type        = string
  default     = "us-central1"
}

variable "image" {
  description = "Container image for payment-service."
  type        = string
  default     = "us-central1-docker.pkg.dev/your-gcp-project-id/security-lab/payment-service:latest"
}
