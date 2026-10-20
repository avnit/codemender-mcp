# Module 06: Data insights with BigQuery

**Goal:** Put SCC findings, Model Armor logs, VPC Service Controls violations and the lab tables in BigQuery. Query them two ways: with the Data Insights agent in Gemini Enterprise for ad-hoc questions, and with the custom MCP tools the security agent calls.

**Time:** 35 minutes

**Prerequisites:**
- Module 05 done.
- Python 3.13 locally, `bq` CLI installed.
- Access to the Gemini Enterprise app for this lab.

```bash
export GCP_PROJECT_ID=your-gcp-project-id
export REGION=us-central1
```

Datasets used in this module:

| Dataset | Tables | Filled by |
|---|---|---|
| `codemender` | `findings` | ingestion + seed data |
| `security_lab` | `security_events`, `sandbox_runs`, `code_to_cloud_map`, `ingestion_errors` | ingestion + seed data |
| `scc_export` | `findings` | SCC continuous export, or seed data |
| `security_logs` | `modelarmor_googleapis_com_sanitize_operations`, `cloudaudit_googleapis_com_policy` | log sinks `model-armor-to-bq`, `vpcsc-to-bq`, or seed data |

The `security_logs` table names are created by the sink from the log ID. Confirm in your environment that they match the names above.

---

## Steps

### 1. Load seed data (5 min)

```bash
cd seed-data
python3 load_seed_data.py --help
python3 load_seed_data.py --project "$GCP_PROJECT_ID"
```

Check `--help` for the exact flags (confirm in your environment). The script loads seed rows for every table above, including `wiz-issue-0001`..`wiz-issue-0004`, `CM-0001`..`CM-0004`, and the `code_to_cloud_map` rows for `payment-service`.

Verify row counts:

```bash
for t in codemender.findings security_lab.security_events security_lab.sandbox_runs \
         security_lab.code_to_cloud_map scc_export.findings \
         security_logs.modelarmor_googleapis_com_sanitize_operations \
         security_logs.cloudaudit_googleapis_com_policy; do
  echo -n "$t: "
  bq query --use_legacy_sql=false --format=csv \
    "SELECT COUNT(*) FROM \`${GCP_PROJECT_ID}.${t}\`" | tail -1
done
```

Expected: a non-zero count for each table.

### 2. SCC continuous export to BigQuery (5 min, read or facilitator demo)

SCC continuous export to BigQuery is configured at organization level (or folder/project level, depending on your SCC tier; confirm in your environment). It needs `roles/securitycenter.bigQueryExportsEditor` and a dataset in the same region constraints SCC supports. Participants usually do not have org-level rights, so the lab uses the seed table `scc_export.findings`.

If you have the rights, the command looks like this (confirm in your environment):

```bash
gcloud scc bqexports create lab-scc-export \
  --organization=YOUR_ORG_ID \
  --location=global \
  --dataset="projects/${GCP_PROJECT_ID}/datasets/scc_export" \
  --description="AI security lab export" \
  --filter='state="ACTIVE"'
```

The exported table schema is larger than what the lab uses. The lab uses only these columns: `finding_id`, `source_id`, `event_time`, `finding.{name, parent, resource_name, state, category, severity, finding_class, external_uri, description, event_time, create_time}`, `resource.{name, display_name, type, project_display_name, parent_display_name}`.

### 3. Model Armor and VPC SC sinks (3 min)

Terraform created two sinks into `security_logs` with `use_partitioned_tables=true`. Confirm:

```bash
gcloud logging sinks describe model-armor-to-bq --format="value(destination,filter,bigqueryOptions)"
gcloud logging sinks describe vpcsc-to-bq --format="value(destination,filter,bigqueryOptions)"
```

Expected destination for both: `bigquery.googleapis.com/projects/your-gcp-project-id/datasets/security_logs`. Expected filters:

- Model Armor: `logName="projects/your-gcp-project-id/logs/modelarmor.googleapis.com%2Fsanitize_operations"` (confirm in your environment)
- VPC SC: `logName="projects/your-gcp-project-id/logs/cloudaudit.googleapis.com%2Fpolicy" AND protoPayload.metadata."@type"="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"`

Each sink writer identity needs `roles/bigquery.dataEditor` on `security_logs`. Terraform grants it.

Model Armor writes sanitize-operation logs only when logging is enabled on the template or floor setting (confirm in your environment). Without live traffic, the seed rows are what you query.

### 4. Check IAM for the Data Insights agent (2 min)

Terraform granted participants (`var.participant_members`) `roles/geminidataanalytics.dataAgentUser`, `roles/bigquery.dataViewer` on the lab datasets, and `roles/bigquery.jobUser`. Confirm yours:

```bash
gcloud projects get-iam-policy "$GCP_PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:user:YOUR_EMAIL" \
  --format="value(bindings.role)"
```

Expected to include `roles/geminidataanalytics.dataAgentUser` and `roles/bigquery.jobUser`. Dataset-level `dataViewer` shows in `bq show --format=prettyjson your-gcp-project-id:security_lab` under `access`.

### 5. Open the Data Insights agent in Gemini Enterprise (5 min)

The UI changes often. These steps are a guide; confirm in your environment.

1. Open the Gemini Enterprise app for the lab.
2. Go to **Agents** and open the Data Insights agent (an administrator may need to enable it first under the app's agent settings).
3. Add BigQuery as a data source and select project `your-gcp-project-id`, datasets `security_lab`, `codemender`, `scc_export`, `security_logs`.
4. Start a new chat with the agent.

### 6. Ask natural-language questions (8 min)

Ask each question. Compare the SQL the agent shows with the reference SQL. The agent's SQL does not need to match word for word; the result should.

**Q1. "Which active SCC findings are HIGH or CRITICAL, by category, in the last 7 days?"**

```sql
SELECT finding.category AS category, finding.severity AS severity, COUNT(*) AS findings
FROM `your-gcp-project-id.scc_export.findings`
WHERE finding.state = 'ACTIVE'
  AND finding.severity IN ('HIGH', 'CRITICAL')
  AND event_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY category, severity
ORDER BY findings DESC;
```

**Q2. "Which Model Armor filters matched most often this week?"**

```sql
SELECT f AS filter, COUNT(*) AS matches
FROM `your-gcp-project-id.security_logs.modelarmor_googleapis_com_sanitize_operations`,
  UNNEST(SPLIT(jsonPayload.matched_filters, ',')) AS f
WHERE jsonPayload.filter_match_state = 'MATCH_FOUND'
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY filter
ORDER BY matches DESC;
```

**Q3. "Who caused VPC Service Controls violations, on which service and perimeter?"**

```sql
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail AS principal,
  protopayload_auditlog.serviceName AS service,
  JSON_VALUE(protopayload_auditlog.metadataJson, '$.securityPolicyInfo.servicePerimeterName') AS perimeter,
  JSON_VALUE(protopayload_auditlog.metadataJson, '$.violationReason') AS reason,
  COUNT(*) AS violations
FROM `your-gcp-project-id.security_logs.cloudaudit_googleapis_com_policy`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY principal, service, perimeter, reason
ORDER BY violations DESC;
```

**Q4. "Which CodeMender findings are still open, and which Wiz issue does each map to?"**

```sql
SELECT finding_id, repository, file_path, line_number, cwe_id, severity, status, wiz_issue_id
FROM `your-gcp-project-id.codemender.findings`
WHERE status IN ('DETECTED', 'OPEN', 'PATCH_GENERATED')
ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, created_at;
```

Expected with seed data: `CM-0001`..`CM-0004` mapped to `wiz-issue-0001`..`wiz-issue-0004` (exact statuses depend on seed data and your Module 04-05 runs).

**Q5. "Show every sandbox run and its verdict for CM-0001."**

```sql
SELECT run_id, execution_name, commit_sha, poc_before, poc_after,
       patch_applied, unit_tests_passed, tests_total, tests_failed, verdict, finished_at
FROM `your-gcp-project-id.security_lab.sandbox_runs`
WHERE issue_id = 'CM-0001'
ORDER BY finished_at DESC;
```

**Q6. "Which repository, Dockerfile and Terraform file produced the payment-service Cloud Run service?"**

```sql
SELECT resource_id, resource_name, image, base_image, repository, dockerfile_path, terraform_path, commit_sha
FROM `your-gcp-project-id.security_lab.code_to_cloud_map`
WHERE resource_id = '//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/services/payment-service';
```

Expected: `base_image = python:3.8-slim-buster`, repository `your-github-org/payment-service`.

**Q7. "How many security events of each type arrived per day this week?"**

```sql
SELECT DATE(event_timestamp) AS day, event_type, severity, COUNT(*) AS events
FROM `your-gcp-project-id.security_lab.security_events`
WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
GROUP BY day, event_type, severity
ORDER BY day DESC, events DESC;
```

### 7. Use the custom MCP tools from the agent (5 min)

The security agent does not use the Data Insights agent. It calls fixed, parameterized queries in the custom MCP server (`mcp-server/services/security_data_service.py`):

| Tool | Reads | Parameters |
|---|---|---|
| `query_scc_findings` | `scc_export.findings` | `severity`, `category`, `state="ACTIVE"`, `project`, `days=7`, `limit=25` |
| `query_model_armor_logs` | `security_logs.modelarmor_googleapis_com_sanitize_operations` | `match_state`, `filter_type`, `days=7`, `limit=25` |
| `query_vpcsc_violations` | `security_logs.cloudaudit_googleapis_com_policy` | `perimeter`, `principal`, `service`, `days=7`, `limit=25` |
| `query_security_events` | `security_lab.security_events` | `event_type`, `severity`, `issue_id`, `days=7`, `limit=25` |

If the agent is running (ADK web UI now, or Gemini Enterprise after Module 07), try:

```
Show active CRITICAL SCC findings from the last 7 days.
```
Expected tool call: `query_scc_findings(severity="CRITICAL", state="ACTIVE", days=7)`.

```
Were there any Model Armor prompt injection or jailbreak matches this week?
```
Expected tool call: `query_model_armor_logs(match_state="MATCH_FOUND", filter_type="pi_and_jailbreak", days=7)`.

```
List VPC Service Controls violations for BigQuery in the last 3 days.
```
Expected tool call: `query_vpcsc_violations(service="bigquery.googleapis.com", days=3)`.

You can also call the tools directly without the agent. Use the MCP Inspector or the test client described in `mcp-server/` (confirm in your environment).

### When to use which

| Use | Data Insights agent | Custom MCP tools |
|---|---|---|
| Who asks | A human analyst | The security agent |
| Query shape | Free-form, generated SQL | Fixed SQL with parameters |
| Repeatability | Varies by phrasing | Same input, same query |
| Good for | Exploring, one-off questions, building a new query | Triage and investigation steps the agent repeats every time |
| Risk | Generated SQL may be wrong; review it | Only the questions the tool author anticipated |

A common pattern: explore with Data Insights, then turn a useful query into a new MCP tool (Module 07).

---

## Check your work

- [ ] All seven tables have rows.
- [ ] Both BigQuery log sinks exist and point at `security_logs`.
- [ ] You have `roles/geminidataanalytics.dataAgentUser` and can open the Data Insights agent.
- [ ] Data Insights answered at least three of Q1-Q7 with results that match the reference SQL.
- [ ] (If the agent is running) the agent called `query_scc_findings`, `query_model_armor_logs` and `query_vpcsc_violations` with the expected parameters.

## Troubleshooting pointers

See [troubleshooting.md](troubleshooting.md#bigquery-and-data-insights) if the Data Insights agent cannot see a dataset or queries fail with permission errors.

## What you built

- One place in BigQuery for SCC, Model Armor, VPC SC, CodeMender and sandbox data.
- Reference SQL for each table.
- A clear split: Data Insights for human exploration, MCP tools for the agent's repeatable queries.
