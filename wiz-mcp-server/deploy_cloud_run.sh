#!/usr/bin/env bash
# ==============================================================================
# deploy_cloud_run.sh
#
# Builds and deploys the Wiz Security MCP Server to Google Cloud Run as a
# dedicated microservice (`wiz-mcp-server`).
# Configures a dedicated least-privilege runtime Service Account (`wiz-mcp-sa`)
# whose ONLY permission is Secret Manager access on `wiz-client-secret` (no
# BigQuery, Cloud Logging, GCS, or Cloud Run Job permissions).
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
SERVICE_NAME="${SERVICE_NAME:-wiz-mcp-server}"
SA_NAME="${SA_NAME:-wiz-mcp-sa}"
ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-false}"
BUILD_SERVICE_ACCOUNT="${BUILD_SERVICE_ACCOUNT:-}"

# Wiz settings. WIZ_CLIENT_SECRET is stored in Secret Manager, never as a plain env var.
WIZ_CLIENT_ID="${WIZ_CLIENT_ID:-}"
WIZ_CLIENT_SECRET="${WIZ_CLIENT_SECRET:-}"
WIZ_API_ENDPOINT="${WIZ_API_ENDPOINT:-}"
WIZ_AUTH_URL="${WIZ_AUTH_URL:-https://auth.app.wiz.io/oauth/token}"
WIZ_AUDIENCE="${WIZ_AUDIENCE:-wiz-api}"
WIZ_SECRET_NAME="${WIZ_SECRET_NAME:-wiz-client-secret}"
# Optional: comma-separated regions for user-managed secret replication (e.g. us-central1).
WIZ_SECRET_LOCATIONS="${WIZ_SECRET_LOCATIONS:-}"

# Org policy: open constraints/gcp.resourceLocations for this project before creating
# resources. ORG_POLICY_ALLOWED_LOCATIONS defaults to "global in:<REGION>-locations".
OPEN_ORG_POLICY="${OPEN_ORG_POLICY:-true}"
ORG_POLICY_ALLOWED_LOCATIONS="${ORG_POLICY_ALLOWED_LOCATIONS:-}"

print_usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -p, --project PROJECT_ID          GCP Project ID (default: current gcloud project)"
  echo "  -r, --region REGION               GCP Region (default: us-central1)"
  echo "  -s, --service SERVICE_NAME        Cloud Run Service Name (default: wiz-mcp-server)"
  echo "  -b, --build-service-account SA    Service Account for Cloud Build (if default compute SA is disabled)"
  echo "  --allow-unauthenticated           Allow unauthenticated invocations (default: require IAM auth)"
  echo "  -h, --help                        Show this help message"
  echo ""
  echo "Settings are read from .env (see .env.example); override the path with ENV_FILE."
  echo "Environment variables: PROJECT_ID/GCP_PROJECT_ID, REGION, SERVICE_NAME, SA_NAME,"
  echo "  BUILD_SERVICE_ACCOUNT, ALLOW_UNAUTHENTICATED, WIZ_CLIENT_ID, WIZ_CLIENT_SECRET,"
  echo "  WIZ_API_ENDPOINT, WIZ_AUTH_URL, WIZ_AUDIENCE, WIZ_SECRET_NAME, WIZ_SECRET_LOCATIONS"
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
echo -e "${BLUE}${BOLD}  Deploying Wiz Security MCP Server to GCP Cloud Run        ${RESET}"
echo -e "${BLUE}${BOLD}============================================================${RESET}"
echo -e "  GCP Project:          ${BOLD}${PROJECT_ID}${RESET}"
echo -e "  Region:               ${BOLD}${REGION}${RESET}"
echo -e "  Cloud Run Service:    ${BOLD}${SERVICE_NAME}${RESET}"
echo -e "  Service Account:      ${BOLD}${SA_NAME}${RESET}"
if [[ -n "${WIZ_CLIENT_ID}" && -n "${WIZ_CLIENT_SECRET}" && -n "${WIZ_API_ENDPOINT}" ]]; then
  echo -e "  Wiz API Endpoint:     ${BOLD}${WIZ_API_ENDPOINT}${RESET}"
else
  echo -e "  Wiz API Endpoint:     ${YELLOW}unconfigured (set WIZ_* values in .env to enable live Wiz calls)${RESET}"
fi
echo -e "  Allow Public Access:  ${BOLD}${ALLOW_UNAUTHENTICATED}${RESET}"
echo -e "${BLUE}${BOLD}============================================================${RESET}"
echo ""

# 1. Enable required GCP APIs
echo -e "${YELLOW}==> [1/5] Enabling required GCP APIs...${RESET}"
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  --project="${PROJECT_ID}"

# 1b. Organization policy: allow the locations this deploy creates resources in.
ORG_POLICY_OPENED="false"
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
    ORG_POLICY_OPENED="true"
    echo -e "${GREEN}    Project policy updated. Changes can take a few minutes to take effect.${RESET}"
  else
    echo -e "${YELLOW}    Could not update the org policy (needs roles/orgpolicy.policyAdmin on the org or folder).${RESET}"
    echo -e "${YELLOW}    Continuing: the Wiz secret will be stored in ${REGION} instead of global.${RESET}"
  fi
  rm -f "${POLICY_FILE}"
  unset EXISTING_VALUES POLICY_FILE
fi

# 2. Create dedicated least-privilege runtime Service Account
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo -e "${YELLOW}==> [2/5] Setting up runtime Service Account: ${SA_EMAIL}...${RESET}"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Wiz MCP Server Runtime SA" \
    --project="${PROJECT_ID}"
  echo -e "${GREEN}    Created service account: ${SA_EMAIL}${RESET}"
else
  echo "    Service account ${SA_EMAIL} already exists."
fi

# 3. Check/re-enable Default Compute Service Account used by Cloud Build
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' 2>/dev/null || echo "")
if [[ -n "${PROJECT_NUMBER}" ]]; then
  DEFAULT_COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
  echo -e "${YELLOW}==> [3/5] Ensuring Cloud Build service account is active...${RESET}"
  gcloud iam service-accounts enable "${DEFAULT_COMPUTE_SA}" --project="${PROJECT_ID}" 2>/dev/null || true
fi

# 4. Configure Wiz Secret Manager integration & runtime env vars
AUTH_FLAG="--no-allow-unauthenticated"
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  AUTH_FLAG="--allow-unauthenticated"
fi

BUILD_SA_FLAG=""
if [[ -n "${BUILD_SERVICE_ACCOUNT}" ]]; then
  BUILD_SA_FLAG="--build-service-account=${BUILD_SERVICE_ACCOUNT}"
fi

ENV_VARS="GCP_PROJECT_ID=${PROJECT_ID},REGION=${REGION},SERVICE_NAME=${SERVICE_NAME},WIZ_AUTH_URL=${WIZ_AUTH_URL},WIZ_AUDIENCE=${WIZ_AUDIENCE}"
if [[ -n "${WIZ_CLIENT_ID}" ]]; then
  ENV_VARS="${ENV_VARS},WIZ_CLIENT_ID=${WIZ_CLIENT_ID}"
fi
if [[ -n "${WIZ_API_ENDPOINT}" ]]; then
  ENV_VARS="${ENV_VARS},WIZ_API_ENDPOINT=${WIZ_API_ENDPOINT}"
fi
SECRETS_FLAG=""

if [[ -n "${WIZ_CLIENT_SECRET}" ]]; then
  echo -e "${YELLOW}==> Configuring Wiz secret in Secret Manager (${WIZ_SECRET_NAME})...${RESET}"
  if ! gcloud secrets describe "${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    create_secret() {
      printf '%s' "${WIZ_CLIENT_SECRET}" | gcloud secrets create "${WIZ_SECRET_NAME}" \
        --data-file=- \
        "$@" \
        --project="${PROJECT_ID}" 2>&1 >/dev/null
    }

    if [[ -n "${WIZ_SECRET_LOCATIONS}" ]]; then
      CREATE_OUTPUT=$(create_secret --replication-policy=user-managed --locations="${WIZ_SECRET_LOCATIONS}") || {
        echo "${CREATE_OUTPUT}" >&2; exit 1; }
      echo -e "${GREEN}    Created secret ${WIZ_SECRET_NAME} in ${WIZ_SECRET_LOCATIONS}.${RESET}"
    else
      CREATED="false"
      ATTEMPTS=1
      if [[ "${ORG_POLICY_OPENED}" == "true" ]]; then ATTEMPTS=6; fi
      for ((i = 1; i <= ATTEMPTS; i++)); do
        if CREATE_OUTPUT=$(create_secret --replication-policy=automatic); then
          CREATED="true"
          echo -e "${GREEN}    Created secret ${WIZ_SECRET_NAME} (automatic replication).${RESET}"
          break
        fi
        if [[ "${CREATE_OUTPUT}" != *"gcp.resourceLocations"* ]]; then
          echo "${CREATE_OUTPUT}" >&2; exit 1
        fi
        if (( i < ATTEMPTS )); then
          echo "    Location policy still blocks global (attempt ${i}/${ATTEMPTS}); waiting 30s for the policy change..."
          sleep 30
        fi
      done

      if [[ "${CREATED}" != "true" ]]; then
        echo -e "${YELLOW}    Global location not allowed; creating ${WIZ_SECRET_NAME} with replication in ${REGION}.${RESET}"
        CREATE_OUTPUT=$(create_secret --replication-policy=user-managed --locations="${REGION}") || {
          echo "${CREATE_OUTPUT}" >&2; exit 1; }
        echo -e "${GREEN}    Created secret ${WIZ_SECRET_NAME} in ${REGION}.${RESET}"
      fi
      unset CREATED ATTEMPTS
    fi
    unset CREATE_OUTPUT
  else
    CURRENT_SECRET=$(gcloud secrets versions access latest --secret="${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" 2>/dev/null || echo "")
    if [[ "${CURRENT_SECRET}" != "${WIZ_CLIENT_SECRET}" ]]; then
      printf '%s' "${WIZ_CLIENT_SECRET}" | gcloud secrets versions add "${WIZ_SECRET_NAME}" \
        --data-file=- \
        --project="${PROJECT_ID}" >/dev/null
      echo -e "${GREEN}    Added new version of secret ${WIZ_SECRET_NAME}.${RESET}"
    else
      echo "    Secret ${WIZ_SECRET_NAME} is already up to date."
    fi
    unset CURRENT_SECRET
  fi
fi

# If the secret exists in Secret Manager (either just created or pre-created by Terraform),
# grant wiz-mcp-sa access and mount WIZ_CLIENT_SECRET from Secret Manager.
if gcloud secrets describe "${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud secrets add-iam-policy-binding "${WIZ_SECRET_NAME}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" \
    --quiet >/dev/null
  if gcloud secrets versions access latest --secret="${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    SECRETS_FLAG="--set-secrets=WIZ_CLIENT_SECRET=${WIZ_SECRET_NAME}:latest"
  else
    echo -e "${YELLOW}    Secret ${WIZ_SECRET_NAME} exists but has no version yet; deploying without secret mount until a version is added.${RESET}"
  fi
else
  echo "    Secret ${WIZ_SECRET_NAME} not configured; deploying in unconfigured Wiz mode."
fi

# 5. Build and deploy container to Cloud Run
echo -e "${YELLOW}==> [4/5] Building container and deploying ${SERVICE_NAME} to Cloud Run...${RESET}"
if ! gcloud run deploy "${SERVICE_NAME}" \
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

# 5b. Grant roles/run.invoker to Gemini Enterprise (Discovery Engine) and Agent Engine service agents
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

# 6. Retrieve Service URL and verify
echo -e "${YELLOW}==> [5/5] Fetching deployment details...${RESET}"
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --format='value(status.url)')

echo ""
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo -e "${GREEN}${BOLD}  Wiz MCP Server Deployment Succeeded!                      ${RESET}"
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo -e "  Service URL:         ${BOLD}${SERVICE_URL}${RESET}"
echo -e "  Health Check:        ${BOLD}${SERVICE_URL}/healthz${RESET}"
echo -e "  MCP Streamable HTTP: ${BOLD}${SERVICE_URL}/mcp${RESET}"
echo -e "  MCP SSE Endpoint:    ${BOLD}${SERVICE_URL}/sse${RESET}"
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo ""
echo -e "${BOLD}Next Steps - Set WIZ_MCP_URL in agent/.env:${RESET}"
echo "  WIZ_MCP_URL=${SERVICE_URL}/mcp"
echo ""
echo -e "${BOLD}Test your deployment:${RESET}"
if [[ "${ALLOW_UNAUTHENTICATED}" == "true" ]]; then
  echo "  curl -f \"${SERVICE_URL}/healthz\""
else
  echo "  curl -f -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" \\"
  echo "    \"${SERVICE_URL}/healthz\""
fi
