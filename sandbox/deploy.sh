#!/usr/bin/env bash
# Build the sandbox image and deploy the Cloud Run Job `codemender-sandbox`.
#
# Terraform (infra/terraform/) also creates this job with the same settings.
# Use this script for image builds and quick updates during the lab.
# If you change job settings here, mirror them in Terraform or the next
# `terraform apply` will revert them.
#
# Usage (from sandbox/):
#   cp .env.example .env   # fill in values
#   ./deploy.sh            # build image + deploy job
#   ./deploy.sh --build-only
#   ./deploy.sh --deploy-only
#
# Cloud Run Jobs run only on the gen2 execution environment, so there is no
# --execution-environment flag here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  echo "sandbox/.env not found; copy .env.example to .env and fill it in." >&2
  exit 1
fi

: "${GCP_PROJECT_ID:?set GCP_PROJECT_ID in .env}"
if [[ "${GCP_PROJECT_ID}" == "your-gcp-project-id" ]]; then
  echo "GCP_PROJECT_ID is still the placeholder value." >&2
  exit 1
fi
REGION="${REGION:-us-central1}"
AR_REPO="${AR_REPO:-security-lab}"
IMAGE_NAME="${IMAGE_NAME:-codemender-sandbox}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
SANDBOX_JOB_NAME="${SANDBOX_JOB_NAME:-codemender-sandbox}"
SANDBOX_SA_NAME="${SANDBOX_SA_NAME:-sandbox-runner-sa}"
SANDBOX_NETWORK="${SANDBOX_NETWORK:-sandbox-vpc}"
SANDBOX_SUBNET="${SANDBOX_SUBNET:-sandbox-subnet}"

IMAGE="${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${AR_REPO}/${IMAGE_NAME}:${IMAGE_TAG}"
SA_EMAIL="${SANDBOX_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

DO_BUILD=1
DO_DEPLOY=1
case "${1:-}" in
  --build-only) DO_DEPLOY=0 ;;
  --deploy-only) DO_BUILD=0 ;;
  "") ;;
  *) echo "unknown option: $1 (use --build-only or --deploy-only)" >&2; exit 2 ;;
esac

if [[ "${DO_BUILD}" == 1 ]]; then
  echo "Building ${IMAGE} with Cloud Build"
  # The build runs in Cloud Build (with internet access), not in the sandbox.
  gcloud builds submit . \
    --project "${GCP_PROJECT_ID}" \
    --region "${REGION}" \
    --tag "${IMAGE}"
fi

if [[ "${DO_DEPLOY}" == 1 ]]; then
  echo "Deploying Cloud Run Job ${SANDBOX_JOB_NAME} in ${REGION}"
  # ^|^ switches the env var delimiter to | because values contain spaces.
  gcloud run jobs deploy "${SANDBOX_JOB_NAME}" \
    --project "${GCP_PROJECT_ID}" \
    --region "${REGION}" \
    --image "${IMAGE}" \
    --service-account "${SA_EMAIL}" \
    --network "${SANDBOX_NETWORK}" \
    --subnet "${SANDBOX_SUBNET}" \
    --vpc-egress all-traffic \
    --max-retries 0 \
    --task-timeout 900s \
    --tasks 1 \
    --parallelism 1 \
    --cpu 1 \
    --memory 2Gi \
    --labels component=codemender-sandbox \
    --set-env-vars "^|^POC_TEST=tests/poc|UNIT_TEST_CMD=python -m pytest -q tests/unit|TIMEOUT_SECONDS=600|PATCH_URI=none"

  echo "Done. Job settings:"
  gcloud run jobs describe "${SANDBOX_JOB_NAME}" \
    --project "${GCP_PROJECT_ID}" --region "${REGION}" \
    --format 'value(metadata.name,spec.template.spec.template.spec.serviceAccountName,spec.template.spec.template.spec.maxRetries,spec.template.spec.template.spec.timeoutSeconds)'
fi
