#!/usr/bin/env bash
# Build and deploy security-log-ingestion to Cloud Run.
#
# Prerequisites (created by infra/terraform): Artifact Registry repo security-lab,
# service accounts log-ingestion-sa and pubsub-push-sa, BigQuery datasets
# security_lab and codemender, Pub/Sub topic security-logs and dead-letter topic
# security-logs-dlq. The push subscription security-logs-push is also created
# by Terraform; this script prints the push endpoint to use.
#
# Usage:
#   GCP_PROJECT_ID=your-gcp-project-id ./deploy.sh
#   GCP_PROJECT_ID=your-gcp-project-id PUSH_AUDIENCE=https://.../pubsub/push ./deploy.sh
set -euo pipefail

: "${GCP_PROJECT_ID:?Set GCP_PROJECT_ID (e.g. your-gcp-project-id)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="security-log-ingestion"
SERVICE_ACCOUNT="log-ingestion-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
PUSH_SA="pubsub-push-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
IMAGE="${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/security-lab/${SERVICE_NAME}:${IMAGE_TAG:-latest}"

SECURITY_DATASET="${SECURITY_DATASET:-security_lab}"
SECURITY_EVENTS_TABLE="${SECURITY_EVENTS_TABLE:-security_events}"
SANDBOX_RUNS_TABLE="${SANDBOX_RUNS_TABLE:-sandbox_runs}"
INGESTION_ERRORS_TABLE="${INGESTION_ERRORS_TABLE:-ingestion_errors}"
BQ_DATASET="${BQ_DATASET:-codemender}"
BQ_TABLE="${BQ_TABLE:-findings}"
PUSH_AUDIENCE="${PUSH_AUDIENCE:-}"
PUSH_SERVICE_ACCOUNT="${PUSH_SERVICE_ACCOUNT:-}"

cd "$(dirname "$0")"

echo "Building ${IMAGE}"
gcloud builds submit --project "${GCP_PROJECT_ID}" --tag "${IMAGE}" .

ENV_VARS="GCP_PROJECT_ID=${GCP_PROJECT_ID}"
ENV_VARS+=",SECURITY_DATASET=${SECURITY_DATASET}"
ENV_VARS+=",SECURITY_EVENTS_TABLE=${SECURITY_EVENTS_TABLE}"
ENV_VARS+=",SANDBOX_RUNS_TABLE=${SANDBOX_RUNS_TABLE}"
ENV_VARS+=",INGESTION_ERRORS_TABLE=${INGESTION_ERRORS_TABLE}"
ENV_VARS+=",BQ_DATASET=${BQ_DATASET}"
ENV_VARS+=",BQ_TABLE=${BQ_TABLE}"
ENV_VARS+=",PUSH_AUDIENCE=${PUSH_AUDIENCE}"
ENV_VARS+=",PUSH_SERVICE_ACCOUNT=${PUSH_SERVICE_ACCOUNT}"

echo "Deploying ${SERVICE_NAME}"
gcloud run deploy "${SERVICE_NAME}" \
  --project "${GCP_PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --service-account "${SERVICE_ACCOUNT}" \
  --no-allow-unauthenticated \
  --ingress all \
  --cpu 1 \
  --memory 512Mi \
  --concurrency 80 \
  --max-instances 5 \
  --timeout 60 \
  --set-env-vars "${ENV_VARS}"

echo "Granting roles/run.invoker to ${PUSH_SA}"
gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
  --project "${GCP_PROJECT_ID}" \
  --region "${REGION}" \
  --member "serviceAccount:${PUSH_SA}" \
  --role roles/run.invoker \
  --quiet >/dev/null

URL="$(gcloud run services describe "${SERVICE_NAME}" \
  --project "${GCP_PROJECT_ID}" --region "${REGION}" --format 'value(status.url)')"

echo
echo "Service URL:   ${URL}"
echo "Push endpoint: ${URL}/pubsub/push"
if [[ -z "${PUSH_AUDIENCE}" ]]; then
  echo "PUSH_AUDIENCE is empty: the in-app OIDC check is off (Cloud Run IAM still applies)."
  echo "To turn it on, redeploy with PUSH_AUDIENCE set to the push subscription's audience,"
  echo "which defaults to the push endpoint: PUSH_AUDIENCE=${URL}/pubsub/push ./deploy.sh"
fi
