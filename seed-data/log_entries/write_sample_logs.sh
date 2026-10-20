#!/usr/bin/env bash
# Write sample log entries to test the ingestion path end to end.
#
#  1. CodeMender findings: `gcloud logging write codemender ... --payload-type=json`.
#     Cloud Logging assigns a new insertId and timestamp. The sink security-logs-to-pubsub
#     forwards them to Pub/Sub -> security-log-ingestion -> BigQuery.
#  2. Sandbox result and SetIamPolicy: these cannot be produced faithfully with
#     `gcloud logging write` (wrong resource type / audit log), so the full LogEntry JSON is
#     published straight to the security-logs topic, the same format the sink publishes.
#     timestamp and insertId are replaced with current values first.
#
# Usage: GCP_PROJECT_ID=my-project ./write_sample_logs.sh [--dry-run]
set -euo pipefail

PROJECT="${GCP_PROJECT_ID:?set GCP_PROJECT_ID}"
TOPIC="${TOPIC:-security-logs}"
DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi
cd "$(dirname "$0")"

run() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

# Prints a field of a LogEntry file after replacing the project placeholder.
# $1 file, $2 one of: payload | severity | entry
extract() {
  python3 -c '
import datetime, json, sys, uuid
path, what, project = sys.argv[1], sys.argv[2], sys.argv[3]
entry = json.loads(open(path).read().replace("your-gcp-project-id", project))
if what == "payload":
    print(json.dumps(entry["jsonPayload"], separators=(",", ":")))
elif what == "severity":
    print(entry.get("severity", "DEFAULT"))
else:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    entry["timestamp"] = now
    entry["receiveTimestamp"] = now
    entry["insertId"] = "sample-" + uuid.uuid4().hex[:16]
    print(json.dumps(entry, separators=(",", ":")))
' "$1" "$2" "${PROJECT}"
}

for f in codemender_finding_cm-0001.json codemender_finding_cm-0002.json; do
  echo "== gcloud logging write codemender (${f})"
  run gcloud logging write codemender "$(extract "${f}" payload)" \
    --payload-type=json --severity="$(extract "${f}" severity)" --project="${PROJECT}"
done

for f in sandbox_result_cm-0001_verified.json set_iam_policy_editor.json; do
  echo "== gcloud pubsub topics publish ${TOPIC} (${f})"
  run gcloud pubsub topics publish "${TOPIC}" --message="$(extract "${f}" entry)" \
    --project="${PROJECT}"
done

echo "Check: bq query --use_legacy_sql=false 'SELECT event_type, issue_id, insert_id FROM \`${PROJECT}.security_lab.security_events\` ORDER BY ingest_timestamp DESC LIMIT 10'"
