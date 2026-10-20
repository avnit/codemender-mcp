#!/usr/bin/env bash
# Load seed data with the bq CLI instead of load_seed_data.py.
#
# Differences from load_seed_data.py:
#   - NO timestamp shift. Rows keep their fixed 2026-10 dates, so queries with days=7
#     return nothing unless the lab runs in that week. Use load_seed_data.py for shifting.
#   - The your-gcp-project-id placeholder inside row values is not replaced.
#
# Usage (from seed-data/):
#   ./load_seed_data.sh your-gcp-project-id            # append
#   ./load_seed_data.sh your-gcp-project-id --replace  # truncate, then load
# Env overrides: BQ_DATASET, BQ_TABLE, SECURITY_DATASET, SCC_DATASET, SCC_TABLE,
#   SECURITY_LOGS_DATASET, MODEL_ARMOR_TABLE, VPCSC_TABLE, BQ_LOCATION (default US).
set -euo pipefail

PROJECT="${1:-${GCP_PROJECT_ID:-}}"
if [[ -z "${PROJECT}" ]]; then
  echo "usage: $0 <project-id> [--replace]" >&2
  exit 2
fi
REPLACE_FLAG=""
if [[ "${2:-}" == "--replace" ]]; then
  REPLACE_FLAG="--replace"
fi

cd "$(dirname "$0")"
LOCATION="${BQ_LOCATION:-US}"

# file-stem  dataset  table
TABLES=(
  "codemender_findings ${BQ_DATASET:-codemender} ${BQ_TABLE:-findings}"
  "security_events ${SECURITY_DATASET:-security_lab} ${SECURITY_EVENTS_TABLE:-security_events}"
  "sandbox_runs ${SECURITY_DATASET:-security_lab} ${SANDBOX_RUNS_TABLE:-sandbox_runs}"
  "code_to_cloud_map ${SECURITY_DATASET:-security_lab} ${CODE_TO_CLOUD_TABLE:-code_to_cloud_map}"
  "ingestion_errors ${SECURITY_DATASET:-security_lab} ${INGESTION_ERRORS_TABLE:-ingestion_errors}"
  "scc_findings ${SCC_DATASET:-scc_export} ${SCC_TABLE:-findings}"
  "model_armor_logs ${SECURITY_LOGS_DATASET:-security_logs} ${MODEL_ARMOR_TABLE:-modelarmor_googleapis_com_sanitize_operations}"
  "vpcsc_logs ${SECURITY_LOGS_DATASET:-security_logs} ${VPCSC_TABLE:-cloudaudit_googleapis_com_policy}"
)

for entry in "${TABLES[@]}"; do
  # shellcheck disable=SC2086
  set -- ${entry}
  stem="$1"; dataset="$2"; table="$3"
  if ! bq --project_id="${PROJECT}" show --format=none "${PROJECT}:${dataset}" >/dev/null 2>&1; then
    echo "creating dataset ${PROJECT}:${dataset}"
    bq --project_id="${PROJECT}" --location="${LOCATION}" mk --dataset "${PROJECT}:${dataset}"
  fi
  if ! bq --project_id="${PROJECT}" show --format=none "${PROJECT}:${dataset}.${table}" >/dev/null 2>&1; then
    echo "creating table ${PROJECT}:${dataset}.${table} from schemas/${stem}.json"
    bq --project_id="${PROJECT}" mk --table "${PROJECT}:${dataset}.${table}" "schemas/${stem}.json"
  fi
  # No schema argument: existing tables (sink tables, SCC export) keep their own schema.
  echo "loading ${stem}.jsonl -> ${PROJECT}:${dataset}.${table} ${REPLACE_FLAG}"
  bq --project_id="${PROJECT}" load ${REPLACE_FLAG} \
    --source_format=NEWLINE_DELIMITED_JSON \
    "${PROJECT}:${dataset}.${table}" "${stem}.jsonl"
done
echo "Done. Timestamps were not shifted."
