# seed-data

Static data that lets every lab module run without live CodeMender, Wiz, SCC, Model Armor or VPC Service Controls findings. The same findings, repository, commit, resource IDs and timestamps appear in every file, so questions that cross sources have answers.

Fixed values used throughout:

| Item | Value |
|---|---|
| Project | `your-gcp-project-id` (project number placeholder `123456789012`, org `123456789`) |
| Repository / commit | `your-github-org/payment-service` @ `3f2a9c1d8e7b6a5f4c3d2e1f0a9b8c7d6e5f4a3b` |
| Cloud Run resource | `//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/services/payment-service` |
| Image | `us-central1-docker.pkg.dev/your-gcp-project-id/security-lab/payment-service@sha256:...` (base `python:3.8-slim-buster`) |
| Runtime SA | `payment-service-sa@your-gcp-project-id.iam.gserviceaccount.com` |
| CodeMender findings | `CM-0001`..`CM-0004` (payment-service), `CM-0101`..`CM-0104` (older, other repos) |
| Wiz issues | `wiz-issue-0001`..`wiz-issue-0004` (map 1:1 to `CM-0001`..`CM-0004`) |
| Sandbox runs | `sbx-run-0000` (inventory-api), `sbx-run-0001` (CM-0001, failed), `sbx-run-0002` (CM-0001, verified) |
| VPC SC perimeter | `accessPolicies/123456789/servicePerimeters/security_lab_perimeter` |

All dates are fixed in October 2026 (UTC). See "Timestamps" below.

## The story

1. **2026-10-01 to 10-03** – Earlier CodeMender scans of `inventory-api` and `notification-worker` produce four medium/low findings. One is fixed (PR #14), one is a false positive after the sandbox PoC did not reproduce (`sbx-run-0000`, `POC_NOT_REPRODUCED`), two stay open.
2. **2026-10-08 18:22** – A Terraform apply by `platform-admin@example.com` grants `roles/editor` on the project to `payment-service-sa` (`IAM_POLICY_CHANGE` event, SetIamPolicy audit log). SCC later reports `PRIMITIVE_ROLES_USED`.
3. **2026-10-13** – `payment-service` is deployed to Cloud Run, public, from an image built on `python:3.8-slim-buster`. Wiz raises four issues: internet-facing service + SQL injection (CRITICAL), internet-facing service + path traversal (HIGH), SA with a primitive role on an internet-facing workload (HIGH), internet-facing service running an image with critical CVE-2022-37434 in zlib1g (CRITICAL). SCC reports an open firewall, a public receipts bucket and the image vulnerability.
4. **2026-10-14 15:00–15:14** – CodeMender scans payment-service (session `cm-session-20261014-01`) and finds:
   - `CM-0001` CWE-89 SQL injection, `app/db.py` (CRITICAL)
   - `CM-0002` CWE-22 path traversal, `app/receipts.py` (HIGH)
   - `CM-0003` CWE-250 over-permissioned SA, `terraform/main.tf` (HIGH)
   - `CM-0004` CWE-1104 outdated base image, `Dockerfile` (HIGH)
5. **2026-10-14 15:41–16:46** – First patch for CM-0001 blocks the exploit but breaks 2 of 12 unit tests (`sbx-run-0001`, `PATCH_FAILED`). Second patch (parameterised query) passes (`sbx-run-0002`, `PATCH_VERIFIED`). CM-0001 status becomes `VERIFIED`; no PR yet (module 03/08 opens it).
6. **2026-10-14 17:05** – Patch generated for CM-0002, uploaded as `patches/CM-0002/sbx-run-0003.diff`, not yet validated (module 04 runs it). CM-0003 and CM-0004 are `OPEN`.
7. **2026-10-15 10:12** – Model Armor blocks a prompt injection sent to the agent (`MATCH_FOUND`, `pi_and_jailbreak`), then a second one that also carries a malicious URI, then flags sensitive data in a model response (`sdp`).
8. **2026-10-15 11:03** – VPC Service Controls blocks `svc-export@untrusted-project-000000.iam.gserviceaccount.com` from `203.0.113.45` trying to run a BigQuery job against `codemender.findings` (`RESOURCES_NOT_IN_SAME_SERVICE_PERIMETER`) and then reading `security_lab.security_events` (`NO_MATCHING_ACCESS_LEVEL`). An earlier, benign denial on 10-13 is a participant listing the sandbox bucket from outside the perimeter.

## Files

| File | Target (dataset.table) | Rows | Contents |
|---|---|---|---|
| `codemender_findings.jsonl` | `codemender.findings` | 8 | CM-0001..0004 plus four older findings in `inventory-api` / `notification-worker` |
| `security_events.jsonl` | `security_lab.security_events` | 21 | Scan started/completed, findings, patches, sandbox results, IAM change. `raw_payload` is the full LogEntry as JSON text |
| `sandbox_runs.jsonl` | `security_lab.sandbox_runs` | 3 | One POC_NOT_REPRODUCED, CM-0001 PATCH_FAILED then PATCH_VERIFIED |
| `code_to_cloud_map.jsonl` | `security_lab.code_to_cloud_map` | 4 | payment-service Cloud Run service and SA; inventory-api service and SA |
| `ingestion_errors.jsonl` | `security_lab.ingestion_errors` | 2 | A non-JSON Pub/Sub message; a LogEntry without insertId |
| `scc_findings.jsonl` | `scc_export.findings` | 6 | OPEN_FIREWALL (active + inactive), PUBLIC_BUCKET_ACL, PRIMITIVE_ROLES_USED, OVER_PRIVILEGED_SERVICE_ACCOUNT_USER, OS_VULNERABILITY. Illustrative |
| `model_armor_logs.jsonl` | `security_logs.modelarmor_googleapis_com_sanitize_operations` | 6 | 3 NO_MATCH_FOUND, 3 MATCH_FOUND |
| `vpcsc_logs.jsonl` | `security_logs.cloudaudit_googleapis_com_policy` | 3 | VPC SC denials; details in `protopayload_auditlog.metadataJson` |
| `schemas/*.json` | – | – | BigQuery JSON schemas for the eight tables above |
| `wiz_mock/*.json` | – | – | Wiz GraphQL-shaped responses: issues, vulnerability findings, identities, code-to-cloud |
| `log_entries/*.json` | – | – | Sample Cloud Logging LogEntry JSON: two CodeMender findings, a sandbox result, a SetIamPolicy audit entry |
| `log_entries/write_sample_logs.sh` | – | – | Writes the samples to Cloud Logging / Pub/Sub to test ingestion end to end |
| `load_seed_data.py` | – | – | Loader with validation, dry run and timestamp shift |
| `load_seed_data.sh` | – | – | `bq load` alternative (no timestamp shift) |
| `tests/` | – | – | unittest suite for schemas, cross-file consistency, shift logic and dry run |

Notes on specific files:

- **security_events.severity** uses the finding severity (CRITICAL/HIGH/MEDIUM/LOW) for `CODEMENDER_FINDING` rows and the Cloud Logging severity (INFO/NOTICE/ERROR) for the others. The LogEntry inside `raw_payload` always carries the Cloud Logging severity.
- **insert IDs** in the seed tables start with `seed-`; insert IDs in `log_entries/` start with `sample-`, so neither collides with real ingested rows.
- **SCC rows** are a subset of the continuous-export schema, and the category used for container image vulnerabilities (`OS_VULNERABILITY`) is illustrative. Every description starts with `[illustrative seed data]`. Confirm in your environment.
- **Model Armor and VPC SC rows** contain only the columns the lab uses. Real sink tables have many more columns; the field names follow NAMING.md and are marked "confirm in your environment".
- **wiz_mock/** files were written by hand, not captured from a tenant. Each has a `_comment` saying so; field names and enum values must be verified against your tenant's schema. `issues.json` has a `_lab_mapping` key (Wiz issue to CodeMender ID) and `vulnerability_findings.json` has a `_lab_context` key; neither is a Wiz field.
- **Line numbers** in findings (42, 27, 58, 1) are illustrative; they may not match the exact lines in `sample-app/`.

## Schemas

`infra/terraform/schemas/<table>.json` is canonical (`log-ingestion/schema/` holds identical copies). The files in `seed-data/schemas/` must match them column for column; the coordinator diffs them. File names here are the seed file stems (for example `schemas/codemender_findings.json` corresponds to `codemender.findings`). Types use the names in NAMING.md (`STRING`, `INT64`, `BOOL`, `TIMESTAMP`, `RECORD`); every field has an explicit `mode`; no descriptions. The loader treats `INTEGER`/`BOOLEAN` as aliases of `INT64`/`BOOL`.

## Timestamps

Static files cannot hold relative dates, so rows use fixed October 2026 times (newest: 2026-10-15T11:04:02Z). With `--shift-to-now` (the default) `load_seed_data.py` computes one offset across all tables so that the newest row becomes the current time, then adds it to:

- every `TIMESTAMP` column, including nested ones (`scc_findings.finding.event_time`, `create_time`);
- ISO-8601 timestamps inside JSON-text columns (`security_events.raw_payload`, `ingestion_errors.raw_message`, `vpcsc_logs.protopayload_auditlog.metadataJson`).

Relative gaps are kept, so the payment-service story falls within the last two days and `days=7` queries return it. The older inventory-api rows fall about two weeks back. `--only` still uses the global offset, so tables loaded separately stay aligned. `load_seed_data.sh` does not shift.

## Load

Prerequisites: `gcloud auth application-default login` (or a service account) with BigQuery Data Editor on the lab datasets and BigQuery Job User. The datasets and tables normally come from `infra/terraform`; the loader creates any that are missing.

```bash
cd seed-data

# Validate every row and print what would be loaded. No GCP access needed.
python3 load_seed_data.py --project your-gcp-project-id --dry-run

# Load (needs: pip install google-cloud-bigquery)
python3 load_seed_data.py --project your-gcp-project-id

# Options
#   --replace            truncate each target table first (WRITE_TRUNCATE)
#   --no-shift           keep the fixed 2026-10 timestamps
#   --only TABLE         load one table; repeatable; short name (security_events) or
#                        BigQuery name (cloudaudit_googleapis_com_policy)
#   --location US        location for datasets the script creates
```

Behaviour:

- The project placeholder `your-gcp-project-id` inside row values is replaced with `--project`.
- Table names follow the MCP server env vars (`BQ_DATASET`, `BQ_TABLE`, `SECURITY_DATASET`, `SECURITY_EVENTS_TABLE`, `SANDBOX_RUNS_TABLE`, `CODE_TO_CLOUD_TABLE`, `INGESTION_ERRORS_TABLE`, `SCC_DATASET`, `SCC_TABLE`, `SECURITY_LOGS_DATASET`, `MODEL_ARMOR_TABLE`, `VPCSC_TABLE`) when set.
- Missing tables are created from `schemas/` (partitioned on `created_at`, `event_timestamp` or `timestamp` where NAMING.md says so; `security_events` clustered on `event_type, severity`). This includes the two `security_logs` sink tables, which the log sinks normally create on first export.
- Existing tables keep their own schema; rows are loaded into them without overriding it. If `scc_export.findings` is a live SCC export table, skip it with `--only` for the other tables, or point `SCC_DATASET` at a scratch dataset.

Alternative with the bq CLI (no shift, no placeholder replacement):

```bash
./load_seed_data.sh your-gcp-project-id            # append
./load_seed_data.sh your-gcp-project-id --replace  # truncate, then load
```

## Test ingestion end to end

```bash
GCP_PROJECT_ID=your-gcp-project-id ./log_entries/write_sample_logs.sh --dry-run   # print commands
GCP_PROJECT_ID=your-gcp-project-id ./log_entries/write_sample_logs.sh
```

The script writes the two CodeMender findings with `gcloud logging write codemender ... --payload-type=json` (the `security-logs-to-pubsub` sink forwards them) and publishes the sandbox result and the SetIamPolicy entry as full LogEntry JSON to topic `security-logs` with `gcloud pubsub topics publish`, after setting `timestamp` and `insertId` to current values. New rows appear in `security_lab.security_events`, `security_lab.sandbox_runs` and `codemender.findings` within a minute or two (confirm in your environment).

## Reset

Reload from scratch (removes everything in the target tables, including real ingested rows):

```bash
python3 load_seed_data.py --project your-gcp-project-id --replace
```

Remove only seed rows and keep anything ingested during the lab:

```sql
DELETE FROM `your-gcp-project-id.codemender.findings`
  WHERE finding_id IN ('CM-0001','CM-0002','CM-0003','CM-0004','CM-0101','CM-0102','CM-0103','CM-0104');
DELETE FROM `your-gcp-project-id.security_lab.security_events` WHERE STARTS_WITH(insert_id, 'seed-');
DELETE FROM `your-gcp-project-id.security_lab.sandbox_runs`
  WHERE run_id IN ('sbx-run-0000','sbx-run-0001','sbx-run-0002');
DELETE FROM `your-gcp-project-id.security_lab.code_to_cloud_map`
  WHERE repository IN ('your-github-org/payment-service','your-github-org/inventory-api')
    AND commit_sha IN ('3f2a9c1d8e7b6a5f4c3d2e1f0a9b8c7d6e5f4a3b','9b8a7c6d5e4f30211f0e9d8c7b6a5f4e3d2c1b0a');
DELETE FROM `your-gcp-project-id.security_lab.ingestion_errors`
  WHERE message_id IN ('1700000000000001','1700000000000002');
DELETE FROM `your-gcp-project-id.scc_export.findings`
  WHERE STARTS_WITH(finding.description, '[illustrative seed data]');
DELETE FROM `your-gcp-project-id.security_logs.modelarmor_googleapis_com_sanitize_operations`
  WHERE STARTS_WITH(insertId, 'seed-ma-');
DELETE FROM `your-gcp-project-id.security_logs.cloudaudit_googleapis_com_policy`
  WHERE STARTS_WITH(insertId, 'seed-vpcsc-');
```

The CodeMender mock findings use the same IDs as rows ingested from the mock scan workflow, so the first statement also removes those. Rows inserted by streaming within the last ~30 minutes cannot be deleted by DML (BigQuery streaming buffer); wait and retry.

## Tests

```bash
cd seed-data
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 load_seed_data.py --project your-gcp-project-id --dry-run
```

The tests need no network and no google-cloud-bigquery. They check every row against its schema (types, REQUIRED, nested and repeated fields), column lists against NAMING.md, cross-file IDs (findings, events, sandbox runs, code-to-cloud, Wiz mocks, log entry samples), the shift logic and the dry run. They also run under pytest.
