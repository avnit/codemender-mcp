---
name: bigquery-data-insights
description: Answer aggregate and trend questions from the lab BigQuery datasets (scc_export, security_logs, security_lab, codemender) with read-only SQL, or by handing a natural-language question to the Gemini Enterprise Data Insights agent.
---

## When to use
- Counts, trends, top-N and joins across findings, logs, sandbox runs and the code-to-cloud map.
- When a `query_*` tool does not have the filter the user needs.

## Steps
1. Try the specific tool first: `query_scc_findings`, `query_model_armor_logs`, `query_vpcsc_violations`, `query_security_events`. Use SQL only when they cannot answer.
2. Write one read-only `SELECT`. Always filter on the partition column (`created_at`, `event_timestamp`, `timestamp`, `event_time`) and add `LIMIT`.
3. Run it with `query_codemender_bigquery` (the server enforces read-only). Replace `your-gcp-project-id` with the project.
4. If the user prefers, or the question is open-ended, give them a question to ask the GE Data Insights agent instead (examples below).
5. Field names in `scc_export` and `security_logs` come from export/sink schemas: confirm in your environment. Call `get_bigquery_schema` if a query fails on a column name.

## Example SQL
Active high and critical SCC findings, last 7 days:
```sql
SELECT finding.category, finding.severity, resource.name AS resource, COUNT(*) AS n
FROM `your-gcp-project-id.scc_export.findings`
WHERE event_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND finding.state = 'ACTIVE'
  AND finding.severity IN ('HIGH', 'CRITICAL')
GROUP BY 1, 2, 3
ORDER BY n DESC
LIMIT 25;
```

Model Armor matches by filter, last 7 days:
```sql
SELECT jsonPayload.matched_filters AS filters, jsonPayload.template AS template, COUNT(*) AS n
FROM `your-gcp-project-id.security_logs.modelarmor_googleapis_com_sanitize_operations`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND jsonPayload.filter_match_state = 'MATCH_FOUND'
GROUP BY 1, 2
ORDER BY n DESC
LIMIT 25;
```

VPC Service Controls violations by perimeter and principal:
```sql
SELECT
  JSON_VALUE(protopayload_auditlog.metadataJson, '$.securityPolicyInfo.servicePerimeterName') AS perimeter,
  JSON_VALUE(protopayload_auditlog.metadataJson, '$.violationReason') AS reason,
  protopayload_auditlog.authenticationInfo.principalEmail AS principal,
  protopayload_auditlog.serviceName AS service,
  COUNT(*) AS n
FROM `your-gcp-project-id.security_logs.cloudaudit_googleapis_com_policy`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY 1, 2, 3, 4
ORDER BY n DESC
LIMIT 25;
```

Security event timeline for one finding:
```sql
SELECT event_timestamp, event_type, source, severity, status, run_id, summary, insert_id
FROM `your-gcp-project-id.security_lab.security_events`
WHERE event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  AND issue_id = 'CM-0001'
ORDER BY event_timestamp
LIMIT 100;
```

Sandbox verdicts per issue:
```sql
SELECT issue_id, verdict, COUNT(*) AS runs, MAX(finished_at) AS last_run
FROM `your-gcp-project-id.security_lab.sandbox_runs`
WHERE started_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY 1, 2
ORDER BY issue_id, last_run DESC
LIMIT 50;
```

Open CodeMender findings joined to deployed resources:
```sql
SELECT f.finding_id, f.cwe_id, f.severity, f.file_path, m.resource_id, m.image, m.base_image
FROM `your-gcp-project-id.codemender.findings` AS f
LEFT JOIN `your-gcp-project-id.security_lab.code_to_cloud_map` AS m
  ON m.repository = f.repository
WHERE f.created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  AND f.status IN ('DETECTED', 'OPEN', 'PATCH_GENERATED')
ORDER BY f.severity, f.finding_id
LIMIT 50;
```

## Example questions for the GE Data Insights agent
- "How many active critical SCC findings do we have by category this week?"
- "Which principals caused the most VPC Service Controls violations in the last 7 days, and on which perimeter?"
- "Show Model Armor prompt-injection matches per day for the last two weeks."
- "List every sandbox run for CM-0001 with its verdict and test counts."
- "Which open CodeMender findings map to a Cloud Run service that is deployed from payment-service?"

## Tools
- CodeMender MCP: `query_codemender_bigquery`, `get_bigquery_schema`, `query_scc_findings`, `query_model_armor_logs`, `query_vpcsc_violations`, `query_security_events`, `get_sandbox_result`.
- Gemini Enterprise Data Insights agent (separate agent; the user asks it directly).

## Output format
Show the SQL you ran, then a small table of results (max 25 rows), then a one-paragraph reading of the result. Cite `query_codemender_bigquery` and the table names.

## Do not
- No DML or DDL (`INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`).
- No queries without a partition filter and `LIMIT`.
- Do not present column names from this file as certain if `get_bigquery_schema` disagrees.
