#!/usr/bin/env bash
# ==============================================================================
# deploy_cloud_run.sh
#
# Builds and deploys the Code Mender MCP Server (`codemender-mcp-server`) to
# Google Cloud Run. Configures the dedicated runtime Service Account
# (`codemender-mcp-sa`) with least-privilege IAM roles to access BigQuery
# findings, Cloud Logging traces, and the `codemender-sandbox` Cloud Run Job.
#
# Wiz cloud security tools are deployed separately via `../wiz-mcp-server/deploy_cloud_run.sh`.
# ==============================================================================
set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

# Load settings from .env (same file config.py reads). Override the path with ENV_FILE.
ENV_FILE="${ENV_FILE:-$(dirname "$0")/.env}"
if [[ -f "${ENV_FILE}" ]]; then
  echo "Loading configuration from ${ENV_FILE}"
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

# Configuration options (precedence: CLI flags > .env / environment > defaults)
PROJECT_ID="${PROJECT_ID:-${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo "")}}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-codemender-mcp-server}"
BQ_DATASET="${BQ_DATASET:-codemender}"
BQ_TABLE="${BQ_TABLE:-findings}"
SA_NAME="${SA_NAME:-codemender-mcp-sa}"
ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-false}"
BUILD_SERVICE_ACCOUNT="${BUILD_SERVICE_ACCOUNT:-}"
LOG_NAME_FILTER="${LOG_NAME_FILTER:-codemender}"

# Org policy: open constraints/gcp.resourceLocations for this project before creating
# resources. ORG_POLICY_ALLOWED_LOCATIONS defaults to "global in:<REGION>-locations".
OPEN_ORG_POLICY="${OPEN_ORG_POLICY:-true}"
ORG_POLICY_ALLOWED_LOCATIONS="${ORG_POLICY_ALLOWED_LOCATIONS:-}"

# Security data (BigQuery) and sandbox job settings
SECURITY_DATASET="${SECURITY_DATASET:-security_lab}"
SECURITY_EVENTS_TABLE="${SECURITY_EVENTS_TABLE:-security_events}"
SANDBOX_RUNS_TABLE="${SANDBOX_RUNS_TABLE:-sandbox_runs}"
CODE_TO_CLOUD_TABLE="${CODE_TO_CLOUD_TABLE:-code_to_cloud_map}"
SCC_DATASET="${SCC_DATASET:-scc_export}"
SCC_TABLE="${SCC_TABLE:-findings}"
SECURITY_LOGS_DATASET="${SECURITY_LOGS_DATASET:-security_logs}"
MODEL_ARMOR_TABLE="${MODEL_ARMOR_TABLE:-modelarmor_googleapis_com_sanitize_operations}"
VPCSC_TABLE="${VPCSC_TABLE:-cloudaudit_googleapis_com_policy}"
SANDBOX_JOB_NAME="${SANDBOX_JOB_NAME:-codemender-sandbox}"
SANDBOX_REGION="${SANDBOX_REGION:-}"
SANDBOX_BUCKET="${SANDBOX_BUCKET:-}"

print_usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -p, --project PROJECT_ID          GCP Project ID (default: current gcloud project)"
  echo "  -r, --region REGION               GCP Region (default: us-central1)"
  echo "  -s, --service SERVICE_NAME        Cloud Run Service Name (default: codemender-mcp-server)"
  echo "  -d, --dataset DATASET             BigQuery Dataset Name (default: codemender)"
  echo "  -t, --table TABLE                 BigQuery Findings Table Name (default: findings)"
  echo "  -b, --build-service-account SA    Service Account for Cloud Build (if default compute SA is disabled)"
  echo "  --allow-unauthenticated           Allow unauthenticated invocations (default: require IAM auth)"
  echo "  -h, --help                        Show this help message"
  echo ""
  echo "Settings are read from .env (see .env.example); override the path with ENV_FILE."
  echo "Environment variables: PROJECT_ID/GCP_PROJECT_ID, REGION, SERVICE_NAME, BQ_DATASET, BQ_TABLE, LOG_NAME_FILTER,"
  echo "  BUILD_SERVICE_ACCOUNT, ALLOW_UNAUTHENTICATED, SECURITY_DATASET, SECURITY_EVENTS_TABLE,"
  echo "  SANDBOX_RUNS_TABLE, CODE_TO_CLOUD_TABLE, SCC_DATASET, SCC_TABLE, SECURITY_LOGS_DATASET,"
  echo "  MODEL_ARMOR_TABLE, VPCSC_TABLE, SANDBOX_JOB_NAME, SANDBOX_REGION, SANDBOX_BUCKET"
  echo "Org policy: OPEN_ORG_POLICY (default true), ORG_POLICY_ALLOWED_LOCATIONS"
  echo "  (default \"global in:<REGION>-locations\")"
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
    -b|--build-service-account)
      BUILD_SERVICE_ACCOUNT="$2"
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
echo -e "  Service Account:      ${BOLD}${SA_NAME}${RESET}"
echo -e "  BigQuery Dataset:     ${BOLD}${BQ_DATASET}${RESET}"
echo -e "  BigQuery Table:       ${BOLD}${BQ_TABLE}${RESET}"
echo -e "  Allow Public Access:  ${BOLD}${ALLOW_UNAUTHENTICATED}${RESET}"
echo -e "${BLUE}${BOLD}============================================================${RESET}"
echo ""

# 1. Enable required GCP APIs
echo -e "${YELLOW}==> [1/6] Enabling required GCP APIs...${RESET}"
gcloud services enable \
  run.googleapis.com \
  bigquery.googleapis.com \
  logging.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project="${PROJECT_ID}"

# 1b. Organization policy: allow the locations this deploy creates resources in.
ORG_POLICY_ALLOWED_LOCATIONS="${ORG_POLICY_ALLOWED_LOCATIONS:-global in:${REGION}-locations}"
if [[ "${OPEN_ORG_POLICY}" == "true" ]]; then
  echo -e "${YELLOW}==> Opening constraints/gcp.resourceLocations for ${PROJECT_ID} (${ORG_POLICY_ALLOWED_LOCATIONS})...${RESET}"
  gcloud services enable orgpolicy.googleapis.com --project="${PROJECT_ID}"

  EXISTING_VALUES=$(gcloud org-policies describe gcp.resourceLocations \
    --project="${PROJECT_ID}" \
    --format='value(spec.rules[].values.allowedValues)' 2>/dev/null | tr ';,' '  ' || true)

  POLICY_FILE=$(mktemp "${TMPDIR:-/tmp}/resource-locations-XXXXXX")
  {
    echo "name: projects/${PROJECT_ID}/policies/gcp.resourceLocations"
    echo "spec:"
    echo "  inheritFromParent: true"
    echo "  rules:"
    echo "  - values:"
    echo "      allowedValues:"
    for VALUE in $(echo ${EXISTING_VALUES} ${ORG_POLICY_ALLOWED_LOCATIONS} | tr ' ' '\n' | awk 'NF && !seen[$0]++'); do
      echo "      - ${VALUE}"
    done
  } > "${POLICY_FILE}"

  if gcloud org-policies set-policy "${POLICY_FILE}" >/dev/null; then
    echo -e "${GREEN}    Project policy updated. Changes can take a few minutes to take effect.${RESET}"
  else
    echo -e "${YELLOW}    Could not update the org policy (needs roles/orgpolicy.policyAdmin on the org or folder). Continuing.${RESET}"
  fi
  rm -f "${POLICY_FILE}"
  unset EXISTING_VALUES POLICY_FILE
fi

# 2. Create runtime Service Account
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo -e "${YELLOW}==> [2/6] Setting up runtime Service Account: ${SA_EMAIL}...${RESET}"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Code Mender MCP Server Runtime SA" \
    --project="${PROJECT_ID}"
  echo -e "${GREEN}    Created service account: ${SA_EMAIL}${RESET}"
else
  echo "    Service account ${SA_EMAIL} already exists."
fi

# 3. Grant IAM roles (least privilege: BigQuery, Logging, Cloud Run Job viewer)
echo -e "${YELLOW}==> [3/6] Assigning BigQuery and Cloud Logging IAM permissions...${RESET}"
IAM_ROLES=(
  "roles/bigquery.dataViewer"
  "roles/bigquery.jobUser"
  "roles/logging.viewer"
  "roles/run.viewer"
)

for ROLE in "${IAM_ROLES[@]}"; do
  echo "    Granting ${ROLE}..."
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
  echo -e "${YELLOW}==> [4/6] Ensuring Cloud Build service account is active...${RESET}"
  gcloud iam service-accounts enable "${DEFAULT_COMPUTE_SA}" --project="${PROJECT_ID}" 2>/dev/null || true
fi

# 5. Authentication and Build Service Account configuration
AUTH_FLAG="--no-allow-unauthenticated"
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  AUTH_FLAG="--allow-unauthenticated"
fi

BUILD_SA_FLAG=""
if [[ -n "${BUILD_SERVICE_ACCOUNT}" ]]; then
  BUILD_SA_FLAG="--build-service-account=${BUILD_SERVICE_ACCOUNT}"
fi

# Runtime environment variables
SANDBOX_REGION="${SANDBOX_REGION:-${REGION}}"
SANDBOX_BUCKET="${SANDBOX_BUCKET:-${PROJECT_ID}-sandbox-inputs}"
ENV_VARS="GCP_PROJECT_ID=${PROJECT_ID},REGION=${REGION},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE},LOG_NAME_FILTER=${LOG_NAME_FILTER}"
ENV_VARS="${ENV_VARS},SECURITY_DATASET=${SECURITY_DATASET},SECURITY_EVENTS_TABLE=${SECURITY_EVENTS_TABLE}"
ENV_VARS="${ENV_VARS},SANDBOX_RUNS_TABLE=${SANDBOX_RUNS_TABLE},CODE_TO_CLOUD_TABLE=${CODE_TO_CLOUD_TABLE}"
ENV_VARS="${ENV_VARS},SCC_DATASET=${SCC_DATASET},SCC_TABLE=${SCC_TABLE},SECURITY_LOGS_DATASET=${SECURITY_LOGS_DATASET}"
ENV_VARS="${ENV_VARS},MODEL_ARMOR_TABLE=${MODEL_ARMOR_TABLE},VPCSC_TABLE=${VPCSC_TABLE}"
ENV_VARS="${ENV_VARS},SANDBOX_JOB_NAME=${SANDBOX_JOB_NAME},SANDBOX_REGION=${SANDBOX_REGION},SANDBOX_BUCKET=${SANDBOX_BUCKET}"

# Sandbox job: start_sandbox_validation needs run.jobs.runWithOverrides on the job only.
if gcloud run jobs describe "${SANDBOX_JOB_NAME}" --region="${SANDBOX_REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "    Granting roles/run.developer on job ${SANDBOX_JOB_NAME}..."
  gcloud run jobs add-iam-policy-binding "${SANDBOX_JOB_NAME}" \
    --region="${SANDBOX_REGION}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/run.developer" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
else
  echo "    Sandbox job ${SANDBOX_JOB_NAME} not found in ${SANDBOX_REGION}; skipping job IAM binding (re-run after Module 04)."
fi

# 6. Build and deploy container to Cloud Run
echo -e "${YELLOW}==> [5/6] Building container and deploying ${SERVICE_NAME} to Cloud Run...${RESET}"
if ! gcloud run deploy "${SERVICE_NAME}" \
  --source="." \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  ${BUILD_SA_FLAG} \
  --set-env-vars="${ENV_VARS}" \
  --port=8080 \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=0 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300 \
  --session-affinity \
  ${AUTH_FLAG}; then
  echo ""
  echo -e "${RED}${BOLD}Deployment failed during Cloud Build!${RESET}"
  echo -e "If the error mentions a disabled Compute Engine service account:"
  echo -e "  1. Re-enable the compute service account:"
  echo -e "     ${BOLD}gcloud iam service-accounts enable ${PROJECT_NUMBER}-compute@developer.gserviceaccount.com --project=${PROJECT_ID}${RESET}"
  echo -e "  2. Or specify an active service account for the build:"
  echo -e "     ${BOLD}./deploy_cloud_run.sh -b \"projects/${PROJECT_ID}/serviceAccounts/${SA_EMAIL}\"${RESET}"
  exit 1
fi

# 6b. Let Gemini Enterprise and Vertex AI Agent Engine call the service.
if [[ "${GRANT_GEMINI_ENTERPRISE_INVOKER:-true}" == "true" && -n "${PROJECT_NUMBER}" ]]; then
  DE_AGENT="service-${PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com"
  echo -e "${YELLOW}==> Granting roles/run.invoker to Gemini Enterprise (${DE_AGENT})...${RESET}"
  gcloud beta services identity create --service=discoveryengine.googleapis.com \
    --project="${PROJECT_ID}" >/dev/null 2>&1 || true
  if gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
      --region="${REGION}" \
      --project="${PROJECT_ID}" \
      --member="serviceAccount:${DE_AGENT}" \
      --role="roles/run.invoker" \
      --quiet >/dev/null; then
    echo -e "${GREEN}    Gemini Enterprise can now invoke ${SERVICE_NAME}.${RESET}"
  else
    echo -e "${YELLOW}    Could not grant roles/run.invoker to ${DE_AGENT}. Grant it manually:${RESET}"
    echo "    gcloud run services add-iam-policy-binding ${SERVICE_NAME} --region=${REGION} \\"
    echo "      --member=serviceAccount:${DE_AGENT} --role=roles/run.invoker"
  fi
  unset DE_AGENT

  AE_AGENT="service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
  echo -e "${YELLOW}==> Granting roles/run.invoker to Vertex AI Agent Engine (${AE_AGENT})...${RESET}"
  gcloud beta services identity create --service=aiplatform.googleapis.com \
    --project="${PROJECT_ID}" >/dev/null 2>&1 || true
  gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${AE_AGENT}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null 2>&1 || true
  unset AE_AGENT
fi

# 7. Retrieve Service URL and verify
echo -e "${YELLOW}==> [6/6] Fetching deployment details...${RESET}"
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
echo -e "  MCP Streamable HTTP: ${BOLD}${SERVICE_URL}/mcp${RESET}"
echo -e "  MCP SSE Endpoint:    ${BOLD}${SERVICE_URL}/sse${RESET}"
echo -e "  MCP Messages:        ${BOLD}${SERVICE_URL}/messages${RESET}"
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo ""
echo -e "${BOLD}Next Steps - Set CODEMENDER_MCP_URL in agent/.env:${RESET}"
echo "  CODEMENDER_MCP_URL=${SERVICE_URL}/mcp"
echo ""
echo -e "${BOLD}Test your deployment:${RESET}"
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  echo "  curl -f \"${SERVICE_URL}/healthz\""
else
  echo "  curl -f -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" \\"
  echo "    \"${SERVICE_URL}/healthz\""
fi
