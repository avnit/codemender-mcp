variable "project_id" {
  description = "GCP project ID for the lab (for example your-gcp-project-id)."
  type        = string
}

variable "region" {
  description = "Region for Cloud Run, Artifact Registry, the sandbox subnet and BigQuery-adjacent resources."
  type        = string
  default     = "us-central1"
}

variable "bq_location" {
  description = "BigQuery dataset location. US multi-region by default."
  type        = string
  default     = "US"
}

variable "github_org" {
  description = "GitHub organization that owns the payment-service repo (for example your-github-org). Used in the WIF attribute condition."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name that may impersonate github-actions-sa through WIF."
  type        = string
  default     = "payment-service"
}

variable "participant_members" {
  description = "Lab participants as IAM members, for example [\"user:alice@example.com\", \"group:lab@example.com\"]."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for m in var.participant_members : can(regex("^(user|group):", m))])
    error_message = "Each participant member must start with \"user:\" or \"group:\"."
  }
}

# ---------------------------------------------------------------------------
# Wiz (custom MCP server). The client secret is NOT a variable: it lives in
# Secret Manager (wiz-client-secret) and is added with gcloud.
# ---------------------------------------------------------------------------
variable "wiz_client_id" {
  description = "Wiz service account client ID. Leave empty to deploy without Wiz (Wiz tools return a 'not configured' error)."
  type        = string
  default     = ""
}

variable "wiz_api_endpoint" {
  description = "Wiz GraphQL endpoint for your tenant, for example https://api.<region>.app.wiz.io/graphql. Confirm in your environment."
  type        = string
  default     = ""
}

variable "wiz_auth_url" {
  description = "Wiz OAuth token URL."
  type        = string
  default     = "https://auth.app.wiz.io/oauth/token"
}

variable "wiz_audience" {
  description = "Wiz OAuth audience."
  type        = string
  default     = "wiz-api"
}

# ---------------------------------------------------------------------------
# Container images. Empty string means "use the Artifact Registry default"
# REGION-docker.pkg.dev/PROJECT/security-lab/<name>:<image_tag> (see locals.tf).
# ---------------------------------------------------------------------------
variable "image_tag" {
  description = "Tag used for the default Artifact Registry image URIs."
  type        = string
  default     = "latest"
}

variable "mcp_server_image" {
  description = "Full image URI for codemender-mcp-server. Empty = Artifact Registry default."
  type        = string
  default     = ""
}

variable "log_ingestion_image" {
  description = "Full image URI for security-log-ingestion. Empty = Artifact Registry default."
  type        = string
  default     = ""
}

variable "sandbox_image" {
  description = "Full image URI for the codemender-sandbox job. Empty = Artifact Registry default."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Feature switches
# ---------------------------------------------------------------------------
variable "deploy_services" {
  description = "Create the Cloud Run services, the sandbox job and everything that depends on them. Set false for phase 1 (APIs, Artifact Registry, data, network) before images are pushed."
  type        = bool
  default     = true
}

variable "enable_scc_export" {
  description = "Create the SCC continuous export to BigQuery dataset scc_export. Also requires scc_organization_id."
  type        = bool
  default     = true
}

variable "scc_organization_id" {
  description = "Numeric organization ID for the SCC BigQuery export (org-level resource). Leave empty to skip the export."
  type        = string
  default     = ""
}
