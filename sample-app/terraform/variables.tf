variable "project_id" {
  description = "Lab GCP project ID."
  type        = string
}

variable "region" {
  description = "Region for the payment-service Cloud Run service."
  type        = string
  default     = "us-central1"
}

variable "image" {
  description = "Container image for payment-service, e.g. us-central1-docker.pkg.dev/your-gcp-project-id/security-lab/payment-service:latest"
  type        = string
}

variable "allow_unauthenticated" {
  description = "Grant roles/run.invoker to allUsers. Keep false unless the facilitator asks for an internet-facing demo."
  type        = bool
  default     = false
}
