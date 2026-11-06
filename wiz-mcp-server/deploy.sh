#!/usr/bin/env bash
# ==============================================================================
# Deploy Wiz Security MCP Server to Google Cloud Run
# ==============================================================================
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo "")}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-wiz-mcp-server}"
SA_NAME="${SA_NAME:-wiz-mcp-sa}"
WIZ_SECRET_NAME="${WIZ_SECRET_NAME:-wiz-client-secret}"
ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-false}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Error: PROJECT_ID is not set. Please set PROJECT_ID or configure 'gcloud config set project <PROJECT_ID>'." >&2
  exit 1
fi

echo "============================================================"
echo " Deploying Wiz Security MCP Server to Cloud Run"
echo " Project:     ${PROJECT_ID}"
echo " Region:      ${REGION}"
echo " Service:     ${SERVICE_NAME}"
echo "============================================================"

# 1. Enable required GCP APIs
echo "==> Enabling required GCP APIs..."
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project="${PROJECT_ID}"

# 2. Create dedicated runtime Service Account (least privilege)
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "==> Creating runtime service account: ${SA_EMAIL}..."
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Wiz MCP Server Runtime SA" \
    --project="${PROJECT_ID}"
else
  echo "==> Runtime service account ${SA_EMAIL} already exists."
fi

# 3. Grant Secret Manager accessor on wiz-client-secret if present
SECRETS_FLAG=""
if gcloud secrets describe "${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud secrets add-iam-policy-binding "${WIZ_SECRET_NAME}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
  if gcloud secrets versions access latest --secret="${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    SECRETS_FLAG="--set-secrets=WIZ_CLIENT_SECRET=${WIZ_SECRET_NAME}:latest"
  fi
fi

# 4. Check/re-enable Default Compute Service Account used by Cloud Build
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' 2>/dev/null || echo "")
if [[ -n "${PROJECT_NUMBER}" ]]; then
  DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
  echo "==> Ensuring Cloud Build service account is active..."
  gcloud iam service-accounts enable "${DEFAULT_COMPUTE_SA}" --project="${PROJECT_ID}" 2>/dev/null || true
fi

# 5. Determine auth flag and build service account
AUTH_FLAG="--no-allow-unauthenticated"
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  AUTH_FLAG="--allow-unauthenticated"
fi

BUILD_SA_FLAG=""
if [[ -n "${BUILD_SERVICE_ACCOUNT:-}" ]]; then
  BUILD_SA_FLAG="--build-service-account=${BUILD_SERVICE_ACCOUNT}"
fi

ENV_VARS="GCP_PROJECT_ID=${PROJECT_ID},REGION=${REGION},SERVICE_NAME=${SERVICE_NAME}"
if [[ -n "${WIZ_CLIENT_ID:-}" ]]; then
  ENV_VARS="${ENV_VARS},WIZ_CLIENT_ID=${WIZ_CLIENT_ID}"
fi
if [[ -n "${WIZ_API_ENDPOINT:-}" ]]; then
  ENV_VARS="${ENV_VARS},WIZ_API_ENDPOINT=${WIZ_API_ENDPOINT}"
fi

# 6. Build and deploy container to Cloud Run
echo "==> Building and deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --source="." \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  ${BUILD_SA_FLAG} \
  --set-env-vars="${ENV_VARS}" \
  ${SECRETS_FLAG} \
  --port=8080 \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=0 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300 \
  --session-affinity \
  ${AUTH_FLAG}

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format='value(status.url)')

echo "============================================================"
echo " Deployment Complete!"
echo " Service URL:         ${SERVICE_URL}"
echo " MCP Streamable HTTP: ${SERVICE_URL}/mcp"
echo " MCP SSE Endpoint:    ${SERVICE_URL}/sse"
echo " Health Check:        ${SERVICE_URL}/healthz"
echo "============================================================"
