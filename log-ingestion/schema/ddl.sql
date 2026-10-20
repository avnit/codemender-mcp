-- BigQuery DDL for the security lab tables written or read by security-log-ingestion.
--
-- ${PROJECT_ID} is a placeholder. Replace it before running, for example:
--   sed "s/\${PROJECT_ID}/your-gcp-project-id/g" schema/ddl.sql \
--     | bq query --use_legacy_sql=false
--
-- Canonical schemas live in infra/terraform/schemas/<table>.json. If Terraform
-- already created these tables, this script is a no-op (IF NOT EXISTS).
-- Partitioning and clustering follow NAMING.md: security_events and
-- codemender.findings are partitioned; the other tables are not.

CREATE SCHEMA IF NOT EXISTS `${PROJECT_ID}.security_lab`;
CREATE SCHEMA IF NOT EXISTS `${PROJECT_ID}.codemender`;

CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.security_lab.security_events` (
  insert_id STRING NOT NULL,
  event_timestamp TIMESTAMP NOT NULL,
  ingest_timestamp TIMESTAMP NOT NULL,
  event_type STRING NOT NULL,
  source STRING,
  severity STRING,
  project_id STRING,
  resource_type STRING,
  resource_name STRING,
  principal STRING,
  repository STRING,
  commit_sha STRING,
  issue_id STRING,
  session_id STRING,
  run_id STRING,
  status STRING,
  summary STRING,
  log_name STRING,
  raw_payload STRING OPTIONS (description = "Full LogEntry as JSON text, capped at 100 KB")
)
PARTITION BY DATE(event_timestamp)
CLUSTER BY event_type, severity
OPTIONS (description = "Security-relevant log entries ingested from Pub/Sub topic security-logs");

CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.security_lab.sandbox_runs` (
  run_id STRING NOT NULL,
  execution_name STRING,
  repository STRING,
  commit_sha STRING,
  patch_ref STRING,
  issue_id STRING,
  poc_test STRING,
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  poc_before STRING,
  poc_after STRING,
  patch_applied BOOL,
  unit_tests_passed BOOL,
  tests_total INT64,
  tests_failed INT64,
  verdict STRING,
  log_excerpt STRING
)
OPTIONS (description = "One row per codemender-sandbox SANDBOX_RESULT log entry");

CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.security_lab.code_to_cloud_map` (
  resource_id STRING NOT NULL,
  resource_name STRING,
  cloud_platform STRING,
  image STRING,
  image_digest STRING,
  base_image STRING,
  repository STRING,
  dockerfile_path STRING,
  terraform_path STRING,
  commit_sha STRING,
  updated_at TIMESTAMP
)
OPTIONS (description = "Maps cloud resources to the repository, Dockerfile and Terraform that produced them");

CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.security_lab.ingestion_errors` (
  received_at TIMESTAMP NOT NULL,
  message_id STRING,
  insert_id STRING,
  error STRING,
  raw_message STRING
)
OPTIONS (description = "Pub/Sub messages security-log-ingestion could not parse or write");

CREATE TABLE IF NOT EXISTS `${PROJECT_ID}.codemender.findings` (
  finding_id STRING NOT NULL,
  issue_id STRING,
  session_id STRING,
  repository STRING,
  commit_sha STRING,
  file_path STRING,
  line_number INT64,
  title STRING,
  description STRING,
  vulnerability_type STRING,
  cwe_id STRING,
  severity STRING,
  status STRING,
  patch_ref STRING,
  pr_url STRING,
  wiz_issue_id STRING,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP
)
PARTITION BY DATE(created_at)
OPTIONS (description = "CodeMender findings (existing table used by the MCP server tools)");
