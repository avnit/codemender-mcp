#!/usr/bin/env bash
# Stage source + patch for one sandbox run and print the execute command.
#
# The sandbox has no internet egress and cannot clone from GitHub, so the
# source is packed here with `git archive` and uploaded to GCS:
#   gs://BUCKET/sources/<owner>__<name>/<commit_sha>.tar.gz
#   gs://BUCKET/patches/<issue_id>/<run_id>.diff
#
# Usage (from sandbox/, after filling in .env):
#   ./stage_inputs.sh --repo-dir ../sample-app --repository my-org/sample-app \
#       --commit HEAD --patch /path/to/fix.diff --issue-id CM-0001 \
#       [--poc-test tests/poc] [--run-id run-...] [--subdir sample-app]
#
#   --repo-dir   any directory inside the git checkout
#   --commit     commit-ish to archive (resolved to a full SHA)
#   --subdir     archive only this subdirectory of the repo (path from repo
#                root), e.g. when the app lives in a monorepo folder
#   --patch      optional; omit for a reproduce-only run (PATCH_URI=none)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${SCRIPT_DIR}/.env"
  set +a
fi

REPO_DIR=""
REPOSITORY=""
COMMIT="HEAD"
PATCH_FILE=""
ISSUE_ID=""
POC_TEST="tests/poc"
RUN_ID=""
SUBDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir) REPO_DIR="$2"; shift 2 ;;
    --repository) REPOSITORY="$2"; shift 2 ;;
    --commit) COMMIT="$2"; shift 2 ;;
    --patch) PATCH_FILE="$2"; shift 2 ;;
    --issue-id) ISSUE_ID="$2"; shift 2 ;;
    --poc-test) POC_TEST="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --subdir) SUBDIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

: "${GCP_PROJECT_ID:?set GCP_PROJECT_ID in sandbox/.env}"
REGION="${REGION:-us-central1}"
SANDBOX_JOB_NAME="${SANDBOX_JOB_NAME:-codemender-sandbox}"
SANDBOX_BUCKET="${SANDBOX_BUCKET:-${GCP_PROJECT_ID}-sandbox-inputs}"

[[ -n "${REPO_DIR}" ]] || { echo "--repo-dir is required" >&2; exit 2; }
[[ "${REPOSITORY}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]] \
  || { echo "--repository must be owner/name" >&2; exit 2; }
[[ -n "${ISSUE_ID}" ]] || { echo "--issue-id is required" >&2; exit 2; }
[[ "${ISSUE_ID}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || { echo "--issue-id has invalid characters" >&2; exit 2; }
[[ -z "${PATCH_FILE}" || -f "${PATCH_FILE}" ]] || { echo "patch not found: ${PATCH_FILE}" >&2; exit 2; }

COMMIT_SHA="$(git -C "${REPO_DIR}" rev-parse --verify "${COMMIT}^{commit}")"
[[ -z "${RUN_ID}" ]] && RUN_ID="run-$(date -u +%Y%m%d%H%M%S)-${COMMIT_SHA:0:7}"
[[ "${RUN_ID}" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || { echo "--run-id has invalid characters" >&2; exit 2; }

OWNER="${REPOSITORY%%/*}"
NAME="${REPOSITORY#*/}"
SOURCE_URI="gs://${SANDBOX_BUCKET}/sources/${OWNER}__${NAME}/${COMMIT_SHA}.tar.gz"
PATCH_URI="none"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

TREE="${COMMIT_SHA}"
[[ -n "${SUBDIR}" ]] && TREE="${COMMIT_SHA}:${SUBDIR}"
git -C "${REPO_DIR}" archive --format=tar.gz -o "${TMP_DIR}/source.tar.gz" "${TREE}"

echo "Uploading ${SOURCE_URI}" >&2
gcloud storage cp "${TMP_DIR}/source.tar.gz" "${SOURCE_URI}" --project "${GCP_PROJECT_ID}"

if [[ -n "${PATCH_FILE}" ]]; then
  PATCH_URI="gs://${SANDBOX_BUCKET}/patches/${ISSUE_ID}/${RUN_ID}.diff"
  echo "Uploading ${PATCH_URI}" >&2
  gcloud storage cp "${PATCH_FILE}" "${PATCH_URI}" --project "${GCP_PROJECT_ID}"
fi

cat <<EOF

Inputs staged. Start the validation with:

gcloud run jobs execute ${SANDBOX_JOB_NAME} --project ${GCP_PROJECT_ID} --region ${REGION} \\
  --update-env-vars RUN_ID=${RUN_ID},REPOSITORY=${REPOSITORY},COMMIT_SHA=${COMMIT_SHA},SOURCE_URI=${SOURCE_URI},PATCH_URI=${PATCH_URI},ISSUE_ID=${ISSUE_ID},POC_TEST=${POC_TEST} \\
  --wait

Then read the result:

gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="${SANDBOX_JOB_NAME}" AND jsonPayload.event_type="SANDBOX_RESULT" AND jsonPayload.run_id="${RUN_ID}"' \\
  --project ${GCP_PROJECT_ID} --limit 1 --format json
EOF
