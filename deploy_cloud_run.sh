#!/usr/bin/env bash
# ==============================================================================
# deploy_cloud_run.sh
# 
# Builds and deploys the Code Mender MCP Server to Google Cloud Run.
# Configures the required runtime Service Account with least-privilege IAM
# roles to access BigQuery findings and Cloud Logging traces.
# ==============================================================================
set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

# Configuration options (can be overridden via environment variables or CLI flags)
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo "")}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-codemender-mcp-server}"
BQ_DATASET="${BQ_DATASET:-codemender}"
BQ_TABLE="${BQ_TABLE:-findings}"
SA_NAME="${SA_NAME:-codemender-mcp-sa}"
ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-false}"

print_usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -p, --project PROJECT_ID     GCP Project ID (default: current gcloud project)"
  echo "  -r, --region REGION          GCP Region (default: us-central1)"
  echo "  -s, --service SERVICE_NAME   Cloud Run Service Name (default: codemender-mcp-server)"
  echo "  -d, --dataset DATASET        BigQuery Dataset Name (default: codemender)"
  echo "  -t, --table TABLE            BigQuery Findings Table Name (default: findings)"
  echo "  --allow-unauthenticated      Allow unauthenticated invocations (default: require IAM auth)"
  echo "  -h, --help                   Show this help message"
  echo ""
  echo "Environment variables: PROJECT_ID, REGION, SERVICE_NAME, BQ_DATASET, BQ_TABLE, ALLOW_UNAUTHENTICATED"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--project)
      PROJECT_ID="$2"
      shift 2
      ;;
    -r|--region)
      REGION="$2"
      shift 2
      ;;
    -s|--service)
      SERVICE_NAME="$2"
      shift 2
      ;;
    -d|--dataset)
      BQ_DATASET="$2"
      shift 2
      ;;
    -t|--table)
      BQ_TABLE="$2"
      shift 2
      ;;
    --allow-unauthenticated)
      ALLOW_UNAUTHENTICATED="true"
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${RESET}" >&2
      print_usage
      exit 1
      ;;
  esac
done

# Validate Project ID
if [[ -z "${PROJECT_ID}" ]]; then
  echo -e "${RED}Error: GCP Project ID is required.${RESET}" >&2
  echo "Set it with: export PROJECT_ID=\"your-project-id\" or pass -p \"your-project-id\"" >&2
  exit 1
fi

echo -e "${BLUE}${BOLD}============================================================${RESET}"
echo -e "${BLUE}${BOLD}  Deploying Code Mender MCP Server to GCP Cloud Run        ${RESET}"
echo -e "${BLUE}${BOLD}============================================================${RESET}"
echo -e "  GCP Project:          ${BOLD}${PROJECT_ID}${RESET}"
echo -e "  Region:               ${BOLD}${REGION}${RESET}"
echo -e "  Cloud Run Service:    ${BOLD}${SERVICE_NAME}${RESET}"
echo -e "  BigQuery Dataset:     ${BOLD}${BQ_DATASET}${RESET}"
echo -e "  BigQuery Table:       ${BOLD}${BQ_TABLE}${RESET}"
echo -e "  Allow Public Access:  ${BOLD}${ALLOW_UNAUTHENTICATED}${RESET}"
echo -e "${BLUE}${BOLD}============================================================${RESET}"
echo ""

# 1. Enable required GCP APIs
echo -e "${YELLOW}==> [1/5] Enabling required GCP APIs...${RESET}"
gcloud services enable \
  run.googleapis.com \
  bigquery.googleapis.com \
  logging.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project="${PROJECT_ID}"

# 2. Create runtime Service Account
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo -e "${YELLOW}==> [2/5] Setting up runtime Service Account: ${SA_EMAIL}...${RESET}"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Code Mender MCP Server Runtime SA" \
    --project="${PROJECT_ID}"
  echo -e "${GREEN}    Created service account: ${SA_EMAIL}${RESET}"
else
  echo "    Service account ${SA_EMAIL} already exists."
fi

# 3. Grant IAM roles (least privilege)
echo -e "${YELLOW}==> [3/5] Assigning BigQuery and Cloud Logging IAM permissions...${RESET}"
IAM_ROLES=(
  "roles/bigquery.dataViewer"
  "roles/bigquery.jobUser"
  "roles/logging.viewer"
)

for ROLE in "${IAM_ROLES[@]}"; do
  echo "    Granting ${ROLE}..."
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None \
    --quiet >/dev/null
done

# 4. Authentication configuration
AUTH_FLAG="--no-allow-unauthenticated"
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  AUTH_FLAG="--allow-unauthenticated"
fi

# 5. Build and deploy container to Cloud Run
echo -e "${YELLOW}==> [4/5] Building container and deploying to Cloud Run...${RESET}"
gcloud run deploy "${SERVICE_NAME}" \
  --source="." \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  --set-env-vars="GCP_PROJECT_ID=${PROJECT_ID},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE}" \
  --port=8080 \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=0 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300 \
  ${AUTH_FLAG}

# 6. Retrieve Service URL and verify
echo -e "${YELLOW}==> [5/5] Fetching deployment details...${RESET}"
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format='value(status.url)')

echo ""
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo -e "${GREEN}${BOLD}  Deployment Succeeded!                                     ${RESET}"
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo -e "  Service URL:         ${BOLD}${SERVICE_URL}${RESET}"
echo -e "  Health Check:        ${BOLD}${SERVICE_URL}/healthz${RESET}"
echo -e "  MCP SSE Endpoint:    ${BOLD}${SERVICE_URL}/sse${RESET}"
echo -e "  MCP Messages:        ${BOLD}${SERVICE_URL}/messages${RESET}"
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo ""
echo -e "${BOLD}Next Steps - Test your deployment:${RESET}"
echo ""
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  echo "  curl -f \"${SERVICE_URL}/healthz\""
else
  echo "  curl -f -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" \\"
  echo "    \"${SERVICE_URL}/healthz\""
fi
echo ""
echo -e "${BOLD}Client Configuration for MCP (e.g. Claude Desktop, Cursor, Jetski):${RESET}"
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
