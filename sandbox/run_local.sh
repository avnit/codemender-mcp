#!/usr/bin/env bash
# Run the sandbox runner locally against the sample app. No GCP needed.
#
# Packs the source dir into a tarball, then runs runner.py with file:// URIs.
# Use this to check a patch and PoC before staging inputs for the real job.
#
# Usage (from sandbox/):
#   ./run_local.sh [--patch FILE] [--poc-test PATH] [--issue-id ID]
#                  [--source-dir DIR] [--docker]
#
#   --patch FILE      unified diff to validate (default: none, reproduce only)
#   --poc-test PATH   PoC test path inside the source (default: tests/poc)
#   --issue-id ID     issue id for the result (default: LOCAL-0001)
#   --source-dir DIR  code under test (default: ../sample-app)
#   --docker          run inside the sandbox image with --network none
#                     (build it first: docker build -t codemender-sandbox .)
#
# Without --docker the runner uses your local python3, which needs pytest
# and flask installed. To use unittest instead, export POC_CMD and
# UNIT_TEST_CMD, e.g.:
#   POC_CMD="python3 -m unittest discover -s {poc_test} -t ." \
#   UNIT_TEST_CMD="python3 -m unittest discover -s tests/unit -t ." ./run_local.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}/../sample-app"
PATCH_FILE=""
POC_TEST="tests/poc"
ISSUE_ID="LOCAL-0001"
USE_DOCKER=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --patch) PATCH_FILE="$2"; shift 2 ;;
    --poc-test) POC_TEST="$2"; shift 2 ;;
    --issue-id) ISSUE_ID="$2"; shift 2 ;;
    --source-dir) SOURCE_DIR="$2"; shift 2 ;;
    --docker) USE_DOCKER=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

SOURCE_DIR="$(cd "${SOURCE_DIR}" && pwd)"
WORK_DIR="${SCRIPT_DIR}/.local-run/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "${WORK_DIR}"

# Commit SHA: real one if the source dir is in a git repo, else a placeholder.
if COMMIT_SHA="$(git -C "${SOURCE_DIR}" rev-parse HEAD 2>/dev/null)"; then
  REPO_TOP="$(git -C "${SOURCE_DIR}" rev-parse --show-toplevel)"
  SUBDIR="${SOURCE_DIR#"${REPO_TOP}"}"
  SUBDIR="${SUBDIR#/}"
else
  COMMIT_SHA="0000000000000000000000000000000000000000"
fi

# Pack the working tree as it is on disk (uncommitted edits included).
# COPYFILE_DISABLE stops macOS tar from adding ._* metadata files.
COPYFILE_DISABLE=1 tar -czf "${WORK_DIR}/source.tar.gz" \
  --exclude .git --exclude __pycache__ --exclude '*.pyc' --exclude .venv \
  -C "${SOURCE_DIR}" .
echo "Packed ${SOURCE_DIR} (commit ${COMMIT_SHA:0:12}${SUBDIR:+, subdir ${SUBDIR}})" >&2

PATCH_URI="none"
if [[ -n "${PATCH_FILE}" ]]; then
  cp "${PATCH_FILE}" "${WORK_DIR}/fix.diff"
  PATCH_URI="file://${WORK_DIR}/fix.diff"
fi

RUN_ID="local-$(date +%Y%m%d%H%M%S)"
REPOSITORY="${REPOSITORY:-local/sample-app}"

if [[ "${USE_DOCKER}" == 1 ]]; then
  DOCKER_PATCH_URI="none"
  [[ -n "${PATCH_FILE}" ]] && DOCKER_PATCH_URI="file:///inputs/fix.diff"
  docker_env=(
    -e "RUN_ID=${RUN_ID}"
    -e "REPOSITORY=${REPOSITORY}"
    -e "COMMIT_SHA=${COMMIT_SHA}"
    -e "SOURCE_URI=file:///inputs/source.tar.gz"
    -e "PATCH_URI=${DOCKER_PATCH_URI}"
    -e "ISSUE_ID=${ISSUE_ID}"
    -e "POC_TEST=${POC_TEST}"
    -e "TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-600}"
  )
  [[ -n "${POC_CMD:-}" ]] && docker_env+=(-e "POC_CMD=${POC_CMD}")
  [[ -n "${UNIT_TEST_CMD:-}" ]] && docker_env+=(-e "UNIT_TEST_CMD=${UNIT_TEST_CMD}")
  # --network none mirrors the no-egress job. --read-only plus a tmpfs /tmp
  # mirrors the ephemeral container.
  exec docker run --rm --network none --read-only \
    --tmpfs /tmp:rw,exec,size=1g \
    -v "${WORK_DIR}:/inputs:ro" \
    "${docker_env[@]}" \
    "${IMAGE:-codemender-sandbox}"
fi

env \
  RUN_ID="${RUN_ID}" \
  REPOSITORY="${REPOSITORY}" \
  COMMIT_SHA="${COMMIT_SHA}" \
  SOURCE_URI="file://${WORK_DIR}/source.tar.gz" \
  PATCH_URI="${PATCH_URI}" \
  ISSUE_ID="${ISSUE_ID}" \
  POC_TEST="${POC_TEST}" \
  TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-600}" \
  PYTHONDONTWRITEBYTECODE=1 \
  python3 "${SCRIPT_DIR}/runner/runner.py"
