#!/usr/bin/env bash
# ==============================================================================
# Deploy Code Mender MCP Server to Google Cloud Run
# ==============================================================================
set -euo pipefail

# Configuration with defaults
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo "")}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-codemender-mcp-server}"
BQ_DATASET="${BQ_DATASET:-codemender}"
BQ_TABLE="${BQ_TABLE:-findings}"
SA_NAME="${SA_NAME:-codemender-mcp-sa}"
ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-false}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "Error: PROJECT_ID is not set. Please set PROJECT_ID or configure 'gcloud config set project <PROJECT_ID>'." >&2
  exit 1
fi

echo "============================================================"
echo " Deploying Code Mender MCP Server to Cloud Run"
echo " Project:     ${PROJECT_ID}"
echo " Region:      ${REGION}"
echo " Service:     ${SERVICE_NAME}"
echo " BQ Dataset:  ${BQ_DATASET}"
echo " BQ Table:    ${BQ_TABLE}"
echo "============================================================"

# 1. Enable required GCP APIs
echo "==> Enabling required GCP APIs..."
gcloud services enable \
  run.googleapis.com \
  bigquery.googleapis.com \
  logging.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project="${PROJECT_ID}"

# 2. Create dedicated runtime Service Account (least privilege)
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "==> Creating runtime service account: ${SA_EMAIL}..."
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Code Mender MCP Server Runtime SA" \
    --project="${PROJECT_ID}"
else
  echo "==> Runtime service account ${SA_EMAIL} already exists."
fi

# 3. Grant IAM roles to runtime Service Account
echo "==> Granting IAM roles (BigQuery Data Viewer, Job User, and Logging Viewer)..."
for ROLE in "roles/bigquery.dataViewer" "roles/bigquery.jobUser" "roles/logging.viewer"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None \
    --quiet >/dev/null
done

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

# 6. Build and deploy container to Cloud Run
echo "==> Building and deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --source="." \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  ${BUILD_SA_FLAG} \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE}" \
  --port=8080 \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=0 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300 \
  ${AUTH_FLAG}

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format='value(status.url)')

echo "============================================================"
echo " Deployment Complete!"
echo " Service URL:         ${SERVICE_URL}"
echo " MCP SSE Endpoint:    ${SERVICE_URL}/sse"
echo " Health Check:        ${SERVICE_URL}/healthz"
echo "============================================================"
echo ""
echo "To connect to this MCP server from an MCP client:"
echo ""
echo "Example client config (e.g. in claude_desktop_config.json or jetski/cursor):"
echo "{"
echo "  \"mcpServers\": {"
echo "    \"codemender\": {"
echo "      \"url\": \"${SERVICE_URL}/sse\","
echo "      \"headers\": {"
echo "        \"Authorization\": \"Bearer \$(gcloud auth print-identity-token)\""
echo "      }"
echo "    }"
echo "  }"
echo "}"
