# security-log-ingestion

Cloud Run service that receives security log entries from Pub/Sub and writes them to BigQuery.

```
Cloud Logging sink security-logs-to-pubsub
  -> Pub/Sub topic security-logs
  -> push subscription security-logs-push (OIDC, SA pubsub-push-sa)
  -> Cloud Run security-log-ingestion  POST /pubsub/push
  -> BigQuery security_lab.security_events (+ sandbox_runs, codemender.findings)
```

Failed deliveries go to dead-letter topic `security-logs-dlq` after 5 attempts (pull subscription `security-logs-dlq-sub`).

## Sink filter

```
logName:"logs/codemender"
OR (resource.type="cloud_run_job" AND resource.labels.job_name="codemender-sandbox" AND jsonPayload.event_type="SANDBOX_RESULT")
OR (protoPayload.methodName="SetIamPolicy" AND logName:"cloudaudit.googleapis.com%2Factivity")
```

## What gets written

| LogEntry | event_type | Tables |
|---|---|---|
| log ID `codemender`, `jsonPayload.event_type` = SCAN_STARTED / SCAN_COMPLETED / FINDING / PATCH (with or without the `CODEMENDER_` prefix) | `CODEMENDER_*` | security_events; FINDING also codemender.findings |
| `cloud_run_job` `codemender-sandbox`, `jsonPayload.event_type=SANDBOX_RESULT` | `SANDBOX_RESULT` | security_events, sandbox_runs |
| audit log with `methodName` ending in `SetIamPolicy` | `IAM_POLICY_CHANGE` | security_events |
| anything else that reaches the service | `OTHER_SECURITY` | security_events |

Parsing rules (`parser.py`):

- `insertId` and a timestamp (`timestamp`, else `receiveTimestamp`) are required. Without them the message goes to `ingestion_errors`.
- Ints, bools and timestamps are coerced. Values that cannot be coerced become NULL; enum columns (`status`, `poc_before`, `poc_after`, `verdict`) become NULL if the value is not in the allowed list. `codemender.findings.status` defaults to `DETECTED`.
- `raw_payload` holds the full LogEntry as JSON, capped at 100 KB. A larger entry is stored as `{"truncated": true, "original_bytes": N, "prefix": "..."}` so the column is always valid JSON.
- A sandbox result without `run_id` is written to security_events only. A CodeMender finding without `finding_id` is written to security_events only.
- Every `CODEMENDER_FINDING` event appends a row to `codemender.findings` (no update in place). Use the latest row per `finding_id` (query below).
- If the sandbox writes a JSON line that Cloud Logging did not parse, `textPayload` is parsed as JSON.

## Response codes and error policy

| Case | HTTP | Effect |
|---|---|---|
| Written | 204 | Ack |
| Duplicate insertId seen recently by this instance | 204 | Ack, nothing written |
| Body, envelope, base64, JSON or LogEntry unusable | 204 | Row in `ingestion_errors`, ack (no retry storm) |
| BigQuery rejects the row (row error `invalid`, HTTP 400/413) | 204 | Row in `ingestion_errors`, ack |
| BigQuery transient error (5xx, 429, timeout, connection error, row error `backendError`/`timeout`/...) | 500 | Pub/Sub retries, then dead-letters to `security-logs-dlq` |
| 403/404 from BigQuery (usually missing table or IAM) | 500 | Treated as transient so messages reach the DLQ instead of being dropped |
| Writing to `ingestion_errors` fails transiently | 500 | Pub/Sub retries |
| Missing/invalid OIDC token (only when `PUSH_AUDIENCE` is set) | 401 | Pub/Sub retries |

## Authentication

The service is deployed with `--no-allow-unauthenticated`. Cloud Run IAM rejects requests that lack a valid Google-signed token from an identity with `roles/run.invoker`; `deploy.sh` grants that role to `pubsub-push-sa`.

`PUSH_AUDIENCE` adds an in-app check with `google.oauth2.id_token.verify_oauth2_token` (signature, expiry, issuer, audience). When it is unset the in-app check is skipped and only Cloud Run IAM applies. Set it to the audience configured on the push subscription; Pub/Sub uses the push endpoint URL (`https://.../pubsub/push`) when no audience is configured. Optional `PUSH_SERVICE_ACCOUNT` also requires the token's `email` claim to match (403 otherwise).

`GET /health` needs no token in-app, but Cloud Run IAM still applies to it.

## Deduplication is best-effort

Pub/Sub push is at-least-once. Two mechanisms reduce duplicates; neither guarantees exactly-once:

1. An in-process LRU of the last 10,000 insertIds written. It is per instance and lost on restart or scale-out.
2. `insert_rows_json(..., row_ids=[insertId])`. BigQuery drops repeated row IDs it sees within a short window (about one minute), best-effort.

If a transient error hits after `security_events` was written but before `sandbox_runs` or `findings`, the retry re-sends `security_events` with the same row ID. Run this to remove duplicates exactly (replace `your-gcp-project-id` and the window). It rewrites one fixed time window: every row in the window is deleted and one copy per `insert_id` is re-inserted, atomically.

```sql
DECLARE window_start TIMESTAMP DEFAULT TIMESTAMP_SUB(TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), DAY), INTERVAL 7 DAY);
DECLARE window_end   TIMESTAMP DEFAULT TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 HOUR);

MERGE `your-gcp-project-id.security_lab.security_events` AS t
USING (
  SELECT *
  FROM `your-gcp-project-id.security_lab.security_events`
  WHERE event_timestamp >= window_start AND event_timestamp < window_end
  QUALIFY ROW_NUMBER() OVER (PARTITION BY insert_id ORDER BY ingest_timestamp) = 1
) AS s
ON FALSE
WHEN NOT MATCHED BY SOURCE
  AND t.event_timestamp >= window_start AND t.event_timestamp < window_end
  THEN DELETE
WHEN NOT MATCHED BY TARGET THEN
  INSERT ROW;
```

Notes:
- `ON FALSE` means no row matches, so the source rows are inserted and the old rows in the window are deleted.
- BigQuery does not allow subqueries in `WHEN` conditions, so the window is a pair of scalar variables, not an "only duplicated ids" filter.
- The window ends 2 hours ago because rows still in the streaming buffer (roughly the last 30-90 minutes) cannot be modified by DML. If the statement fails with a streaming buffer error, move `window_end` back and retry.
- A duplicate pair whose copies have different `event_timestamp` values cannot happen here: both copies come from the same LogEntry.
- The same pattern works for `sandbox_runs` (key `run_id`; it is not partitioned, so filter on `finished_at` or drop the window to rewrite the whole table).

For reads, deduplicate at query time instead of rewriting:

```sql
SELECT * FROM `your-gcp-project-id.security_lab.security_events`
WHERE event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
QUALIFY ROW_NUMBER() OVER (PARTITION BY insert_id ORDER BY ingest_timestamp) = 1;

-- Latest state per CodeMender finding
SELECT * FROM `your-gcp-project-id.codemender.findings`
WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
QUALIFY ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY updated_at DESC) = 1;
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `GCP_PROJECT_ID` | client default project | Project that holds the datasets |
| `SECURITY_DATASET` | `security_lab` | |
| `SECURITY_EVENTS_TABLE` | `security_events` | |
| `SANDBOX_RUNS_TABLE` | `sandbox_runs` | |
| `INGESTION_ERRORS_TABLE` | `ingestion_errors` | |
| `BQ_DATASET` | `codemender` | Findings dataset |
| `BQ_TABLE` | `findings` | Findings table |
| `PUSH_AUDIENCE` | empty (check off) | Expected OIDC audience |
| `PUSH_SERVICE_ACCOUNT` | empty (check off) | Expected token email |
| `PORT` | `8080` | Set by Cloud Run |

`log-ingestion-sa` needs `roles/bigquery.dataEditor` on `security_lab` and `codemender` (confirm in your environment that Terraform grants it).

## Files

- `main.py` Starlette app and push handler
- `parser.py` pure LogEntry -> row functions
- `bq_writer.py` BigQuery writes, error classification, insertId LRU
- `config.py` env settings
- `schema/*.json` BigQuery JSON schemas (copies of `infra/terraform/schemas/`), `schema/ddl.sql` CREATE TABLE IF NOT EXISTS statements
- `tests/` unittest suite and sample LogEntries

## Create tables without Terraform

```bash
sed "s/\${PROJECT_ID}/your-gcp-project-id/g" schema/ddl.sql | bq query --use_legacy_sql=false
```

## Deploy

```bash
GCP_PROJECT_ID=your-gcp-project-id ./deploy.sh
# then, to turn on the in-app token check:
GCP_PROJECT_ID=your-gcp-project-id PUSH_AUDIENCE=https://SERVICE_URL/pubsub/push ./deploy.sh
```

## Test locally

No network or BigQuery access is needed; the tests use a fake BigQuery client.

```bash
cd log-ingestion
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Send a sample message to a local server (with `PUSH_AUDIENCE` unset; writes go to real BigQuery using your ADC credentials):

```bash
uvicorn main:app --port 8080 &
DATA=$(base64 < tests/fixtures/codemender_finding.json | tr -d '\n')
curl -i -X POST localhost:8080/pubsub/push -H 'Content-Type: application/json' \
  -d "{\"message\":{\"data\":\"${DATA}\",\"messageId\":\"local-1\"}}"
```

## Check ingestion in BigQuery

```sql
SELECT event_type, COUNT(*) AS n, MAX(event_timestamp) AS latest
FROM `your-gcp-project-id.security_lab.security_events`
WHERE event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
GROUP BY event_type ORDER BY n DESC;

SELECT received_at, message_id, error
FROM `your-gcp-project-id.security_lab.ingestion_errors`
ORDER BY received_at DESC LIMIT 20;
```

Messages in the DLQ: `gcloud pubsub subscriptions pull security-logs-dlq-sub --limit=10 --auto-ack=false`.
