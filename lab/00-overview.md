# 00 - Overview

**Time:** 10 minutes, after a 10-minute setup check (see [Setup check](#setup-check-10-minutes))

**Learning objectives**

- Describe the two core capabilities: conversational investigation, and remediation with a human in the loop.
- Name the components in the architecture and the module that covers each one.
- Create and source `lab.env` with the variables every later module uses.

**Goal:** Understand what you will build today and set up the environment variables every later module uses.

**Prerequisites:** The Day 1-3 environment (below). `gcloud`, `terraform`, `git`, `gh`, and Python 3.11 or later installed locally.

## Objectives

By the end of the day you will have:

1. Connected the Wiz, Cloud Logging, and GitHub MCP servers to an ADK agent, and seen how each one authenticates with Gemini Enterprise.
2. Deployed two dedicated Cloud Run MCP services: `codemender-mcp-server` (BigQuery security data, CodeMender findings, and sandbox execution) and `wiz-mcp-server` (Wiz OAuth + GraphQL security graph, exposure, excessive permissions, and code-to-cloud attribution).
3. Deployed a validation sandbox: the Cloud Run Job `codemender-sandbox`, with no egress and no permissions.
4. Built a log pipeline: Cloud Logging, then the sink `security-logs-to-pubsub`, then Pub/Sub `security-logs`, then `security-log-ingestion`, then BigQuery.
5. Queried the security datasets with the Data Insights agent in Gemini Enterprise.
6. Added tools and skills to the agent, deployed it to Agent Engine, and registered it in Gemini Enterprise.
7. Run the two core capabilities end to end.

## Use cases

### 1. Conversational cloud security investigation

- "What are our top 5 critical internet-facing vulnerabilities in production right now?"
- "Which IAM service accounts have excessive permissions in the payment service?"
- "Explain the architecture of payment-service in plain language: what is exposed, what it can reach, and what identity it runs as."
- Code-to-cloud attribution: "Which repo, Dockerfile, and commit produced the image running in `payment-service`?"

### 2. Code remediation with a human in the loop

- Root cause analysis from Wiz issue metadata and CodeMender findings.
- A small diff that changes only what the fix needs.
- Sandbox verification: the PoC exploit succeeds before the patch, fails after it, and unit tests pass.
- A pull request with a security justification.
- A human reviews and merges. The agent cannot merge.

## Roles you need

| Who | Role | Used in |
|---|---|---|
| You, in GCP | Project Owner. Or, at minimum: `roles/serviceusage.serviceUsageAdmin`, `roles/iam.serviceAccountAdmin`, `roles/resourcemanager.projectIamAdmin`, `roles/run.admin`, `roles/artifactregistry.admin`, `roles/storage.admin`, `roles/bigquery.admin`, `roles/pubsub.admin`, `roles/logging.configWriter`, `roles/secretmanager.admin`, `roles/compute.networkAdmin`, `roles/dns.admin`, `roles/iam.workloadIdentityPoolAdmin`, `roles/aiplatform.user`, `roles/discoveryengine.admin` (confirm in your environment) | All modules |
| Wiz admin | Tenant admin who can change Settings > Tenant > AI Features and create service accounts (confirm in your environment) | 01 |
| GitHub org admin | Can create repos, set branch protection, and approve fine-grained PATs for the org | 03 |
| Gemini Enterprise admin | Can add connectors and agents to the Gemini Enterprise app | 01, 02, 03, 07 |
| Org policy admin | Only if `discoveryengine.managed.disableCustomMcpServerConnector` is enforced and has to be relaxed for your project | 02 |

## What Days 1-3 already provide

- A GCP project with billing enabled.
- A Wiz tenant with your GCP project connected.
- A GitHub org (`your-github-org` in this lab).
- A Gemini Enterprise app in the GCP project.

Everything else is created today, by Terraform in `infra/terraform/` and by the deploy scripts.

## Architecture

![Architecture](images/architecture.svg)

```mermaid
flowchart TB
    subgraph GE["Gemini Enterprise"]
        user["Analyst"]
        app["Gemini Enterprise app"]
        dia["Data Insights agent"]
        user --> app
        app --> dia
    end

    subgraph AE["Vertex AI Agent Engine"]
        agent["ai_security_agent - ADK root_agent + skills"]
    end

    subgraph Remote["Remote MCP servers"]
        wizremote["Wiz vendor MCP (opt) - https://mcp.app.wiz.io"]
        logmcp["Cloud Logging MCP - https://logging.googleapis.com/mcp"]
        gh["GitHub MCP - https://api.githubcopilot.com/mcp/"]
    end

    subgraph Run["Cloud Run"]
        cm["codemender-mcp-server - SA codemender-mcp-sa"]
        wizrun["wiz-mcp-server - SA wiz-mcp-sa"]
        ing["security-log-ingestion - SA log-ingestion-sa"]
        job["Job codemender-sandbox - gen2, SA sandbox-runner-sa"]
    end

    subgraph Net["sandbox-vpc"]
        fw["sandbox-deny-all-egress + sandbox-allow-restricted-apis 199.36.153.4/30"]
    end

    subgraph Data["BigQuery"]
        bqcm[("codemender.findings")]
        bqsl[("security_lab: security_events, sandbox_runs, code_to_cloud_map, ingestion_errors")]
        bqscc[("scc_export.findings")]
        bqlogs[("security_logs: Model Armor, VPC SC")]
    end

    subgraph GitHub["GitHub your-github-org/payment-service"]
        repo["Repo + CODEOWNERS + branch protection"]
        scan["codemender-scan.yml"]
        val["sandbox-validate.yml"]
    end

    gcs[("GCS your-gcp-project-id-sandbox-inputs")]
    cl["Cloud Logging"]
    sink["Sink security-logs-to-pubsub"]
    topic["Pub/Sub security-logs"]
    dlq["Pub/Sub security-logs-dlq"]
    scc["SCC continuous export"]
    sinks2["Sinks model-armor-to-bq, vpcsc-to-bq"]
    cmapi["CodeMender endpoint or mock mode"]
    wizapi["Wiz GraphQL API"]

    app --> agent
    agent --> wizrun
    agent -.-> wizremote
    agent --> logmcp
    agent --> gh
    agent --> cm
    wizrun --> wizapi
    gh --> repo
    repo --> scan
    repo --> val
    scan --> cmapi
    scan --> cl
    scan --> gcs
    val --> gcs
    val --> job
    cm --> bqcm
    cm --> bqsl
    cm --> bqscc
    cm --> bqlogs
    cm --> job
    job --> fw
    fw --> gcs
    job --> cl
    logmcp --> cl
    cl --> sink
    sink --> topic
    topic -->|"OIDC push /pubsub/push"| ing
    topic --> dlq
    ing --> bqsl
    ing --> bqcm
    cl --> sinks2
    sinks2 --> bqlogs
    scc --> bqscc
    dia --> Data
```

### Remediation flow

```mermaid
sequenceDiagram
    actor U as Analyst
    participant A as ai_security_agent
    participant W as wiz-mcp-server
    participant G as GitHub MCP
    participant C as codemender-mcp-server
    participant S as Cloud Run Job codemender-sandbox
    actor R as Human reviewer

    U->>A: Remediate wiz-issue-0001
    A->>W: get_wiz_issue_details and wiz_trace_code_to_cloud
    W-->>A: Issue, resource, severity
    A->>C: trace_code_to_cloud and list_codemender_issues
    C-->>A: Repo payment-service, app/db.py, CM-0001
    A->>G: get_file_contents app/db.py
    G-->>A: File contents
    A->>A: Root cause and minimal patch
    A->>U: Show diff. Run sandbox validation?
    U->>A: Yes
    A->>C: start_sandbox_validation confirmed=true
    C->>S: Execute job with run_id, commit_sha, patch_uri
    S-->>C: SANDBOX_RESULT verdict PATCH_VERIFIED
    A->>C: get_sandbox_result run_id
    C-->>A: poc_before EXPLOITABLE, poc_after NOT_EXPLOITABLE, tests passed
    A->>U: Verified. Open a pull request?
    U->>A: Yes
    A->>G: create_pull_request with security justification
    G-->>A: PR URL
    A-->>U: PR URL. Merge is a human action.
    R->>G: Review, approve, merge
```

## Module timing and schedule

The lab takes 4 hours (240 minutes), including a setup check, two breaks and a buffer. Times are relative to the start.

| Time | Module | Duration | Mode |
|---|---|---|---|
| 0:00-0:10 | [Setup check](#setup-check-10-minutes) | 10m | Hands-on |
| 0:10-0:20 | 00 Overview | 10m | Walkthrough |
| 0:20-0:40 | [01 Wiz MCP](01-wiz-remote-mcp.md) | 20m | Hands-on |
| 0:40-1:00 | [02 Cloud Logging remote MCP](02-cloud-logging-remote-mcp.md) | 20m | Hands-on |
| 1:00-1:20 | [03 GitHub remote MCP](03-github-remote-mcp.md) | 20m | Hands-on |
| 1:20-1:30 | Break | 10m | |
| 1:30-1:45 | [04 Validation sandbox](04-validation-sandbox.md) | 15m | Deploy and verify |
| 1:45-1:55 | [05 Log ingestion](05-log-ingestion.md) | 10m | Deploy and verify |
| 1:55-2:05 | [06 Data Insights on BigQuery](06-data-insights-bigquery.md) | 10m | Guided |
| 2:05-2:50 | [07 Tools and skills](07-tools-and-skills.md) | 45m | Hands-on |
| 2:50-3:00 | Break | 10m | |
| 3:00-3:40 | [08 Capability exercises](08-capability-exercises.md) | 40m | Hands-on |
| 3:40-3:50 | Buffer | 10m | |
| 3:50-4:00 | Wrap-up and rubric scores | 10m | |

Module time: 190 minutes. Setup check 10, breaks 20, buffer 10, wrap-up 10. Total: 240 minutes.

For Modules 04 and 05, and for the Terraform and infrastructure steps in other modules, the facilitator deploys before the lab. You run the provided scripts or verify with one or two commands. Each module ends with an **Optional / take-home** section for the steps that do not fit the 4 hours.

## Setup check (10 minutes)

Do this at the start, before the overview.

1. Sign in to the GCP console, the Gemini Enterprise app, the Wiz portal and the GitHub org.
2. Check the local tools:

   ```bash
   gcloud --version
   terraform -version
   gh auth status
   python3 --version
   adk --version
   ```

3. Create `lab.env` from the [cheat sheet](#environment-variables-cheat-sheet) below, source it, and run the checks in [Check your work](#check-your-work).

If any sign-in or tool fails, tell the facilitator now.

## Starter vs solution

- The solution code is in the main directories: `mcp-server/`, `wiz-mcp-server/`, `agent/`, `sandbox/`, `log-ingestion/`, `sample-app/`, `infra/terraform/`.
- `starter/` has copies of selected files with `TODO` markers where you write the code yourself.
- To work from the starter, copy the starter file over the solution file it maps to, then fill in the TODOs. The mapping table is in [facilitator-guide.md](facilitator-guide.md).
- If you fall behind, restore the solution file with `git checkout -- <path>` and continue.
- Which starter files are done in class and which are take-home is listed in [starter/README.md](../starter/README.md).

## Environment variables cheat sheet

Create `lab.env` in the repo root. Do not commit it. Put no secrets in it: secrets go in Secret Manager.

```bash
# lab.env - source this in every new shell: source lab.env
export GCP_PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"
export PROJECT_NUMBER="$(gcloud projects describe "$GCP_PROJECT_ID" \
  --format='value(projectNumber)')"
export GITHUB_ORG="your-github-org"
export GITHUB_REPO="payment-service"

# Resources created by Terraform / deploy scripts
export SANDBOX_BUCKET="${GCP_PROJECT_ID}-sandbox-inputs"
export SANDBOX_JOB_NAME="codemender-sandbox"
export AR_REPO="security-lab"
export BQ_DATASET="codemender"
export BQ_TABLE="findings"
export SECURITY_DATASET="security_lab"
export SCC_DATASET="scc_export"
export SECURITY_LOGS_DATASET="security_logs"
export WIZ_SECRET_NAME="wiz-client-secret"

# Endpoints
export CLOUD_LOGGING_MCP_URL="https://logging.googleapis.com/mcp"
export GITHUB_MCP_URL="https://api.githubcopilot.com/mcp/"
# Resolves after mcp-server/deploy_cloud_run.sh and wiz-mcp-server/deploy_cloud_run.sh have run:
CODEMENDER_SERVICE_URL="$(gcloud run services describe codemender-mcp-server \
  --region "$REGION" --format='value(status.url)' 2>/dev/null)"
export CODEMENDER_MCP_URL="${CODEMENDER_SERVICE_URL}/mcp"
WIZ_SERVICE_URL="$(gcloud run services describe wiz-mcp-server \
  --region "$REGION" --format='value(status.url)' 2>/dev/null)"
export WIZ_MCP_URL="${WIZ_SERVICE_URL:-https://mcp.app.wiz.io}${WIZ_SERVICE_URL:+/mcp}"
```

Then:

```bash
source lab.env
gcloud config set project "$GCP_PROJECT_ID"
gcloud auth application-default login
echo "$GCP_PROJECT_ID $PROJECT_NUMBER $REGION"
```

Expected: your project ID, a 12-digit project number, and `us-central1`.

The agent reads its own settings from `agent/.env`. Copy `agent/.env.example` to `agent/.env` and set the same values there (`GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `CODEMENDER_MCP_URL`, `WIZ_MCP_URL`, `GITHUB_ORG`, and so on).

## Check your work

- `source lab.env` prints no errors, and `echo $PROJECT_NUMBER` shows a number.
- `gcloud config get-value project` shows your project.
- You can name the two core capabilities, and you know which module covers each component.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md).

## What you built

A `lab.env` file with the shared variables, and an understanding of the architecture and the remediation flow.
