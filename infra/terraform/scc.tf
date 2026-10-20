# Security Command Center continuous export to BigQuery (scc_export).
#
# This is an ORGANIZATION-level resource. The identity running Terraform needs
# an org-level role such as roles/securitycenter.bigQueryExportsEditor (or
# securitycenter.admin), and SCC must be active on the organization. It is
# skipped when scc_organization_id is empty or enable_scc_export is false; the
# pre-created scc_export.findings table (bigquery.tf) plus seed data then
# stand in for the export.
#
# Resource choice: google_scc_v2_organization_scc_big_query_export (SCC v2 API,
# available in google provider 6.x). If your provider version or org uses the
# v1 API, switch to google_scc_organization_scc_big_query_export with the same
# arguments minus `location`. Confirm in your environment.
#
# After creation, the SCC service agent needs write access to the dataset.
# SCC normally grants this itself; if findings do not appear, grant
# roles/bigquery.dataEditor on scc_export to the SCC service agent shown in the
# export details. Confirm in your environment.

resource "google_scc_v2_organization_scc_big_query_export" "findings" {
  count = var.enable_scc_export && var.scc_organization_id != "" ? 1 : 0

  organization        = var.scc_organization_id
  location            = "global"
  big_query_export_id = "security-lab-scc-export"
  dataset             = "projects/${var.project_id}/datasets/${google_bigquery_dataset.scc_export.dataset_id}"
  description         = "SCC findings for the AI Security Agent lab."
  filter              = "resource.project_display_name=\"${var.project_id}\""

  depends_on = [google_project_service.apis]
}
