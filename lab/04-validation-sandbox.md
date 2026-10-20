# Module 04: Validation sandbox

**Goal:** Run a proof-of-concept exploit and a candidate patch inside an isolated Cloud Run Job, and get a verdict back. You will start the job locally, from the command line, from GitHub Actions, and from the agent.

**Time:** 45 minutes

**Prerequisites:**
- Modules 00-03 done.
- `gcloud` authenticated against `your-gcp-project-id`, with `REGION=us-central1`.
- Terraform from `infra/terraform/` applied (the facilitator did this on Days 1-3).
- Docker installed locally (for `run_local.sh`).
- The `payment-service` repo pushed to `your-github-org` from `sample-app/`.

Set these shell variables for the module:

```bash
export GCP_PROJECT_ID=your-gcp-project-id
export REGION=us-central1
export SANDBOX_BUCKET="${GCP_PROJECT_ID}-sandbox-inputs"
export GITHUB_ORG=your-github-org
```

---

## Design

### Why a Cloud Run Job and not gVisor

The brief asked for a gVisor sandbox. Cloud Run Jobs do not offer gVisor. Jobs run only on the second-generation execution environment, which isolates each instance in a microVM. The first-generation environment (gVisor) is available for Cloud Run services only, not jobs.

If you need gVisor specifically, use GKE Sandbox (GKE node pools with `sandbox_config { sandbox_type = "gvisor" }`). This lab does not use GKE.

The sandbox is built from five controls:

| Control | How it is implemented |
|---|---|
| Kernel isolation | Cloud Run Job `codemender-sandbox`, gen2 execution environment (microVM) |
| No internet egress | VPC `sandbox-vpc`, subnet `sandbox-subnet` (10.10.0.0/24). Firewall `sandbox-deny-all-egress` (priority 65000, deny 0.0.0.0/0). Firewall `sandbox-allow-restricted-apis` (priority 1000, allow tcp:443 to 199.36.153.4/30). Direct VPC egress with `vpc_access.egress = ALL_TRAFFIC`. |
| Google APIs only through the restricted VIP | Private Google Access on the subnet. Private DNS zone maps `googleapis.com` to the restricted VIP. |
| No permissions | Service account `sandbox-runner-sa` has no project-level roles. It has only `roles/storage.objectViewer` on `${GCP_PROJECT_ID}-sandbox-inputs`. |
| Ephemeral | Each execution starts from the image, works on a fresh copy of the source, prints a result, and exits. Nothing persists. |

Because there is no internet egress, the job cannot clone from GitHub or install packages at run time. Source and patch are staged in the bucket first:

- Source tarball: `gs://${SANDBOX_BUCKET}/sources/<repo_owner>__<repo_name>/<commit_sha>.tar.gz`
- Patch: `gs://${SANDBOX_BUCKET}/patches/<issue_id>/<run_id>.diff`

All Python dependencies for the sample app and its tests are baked into the image (`sandbox/Dockerfile`).

### What the runner does

`sandbox/runner/runner.py` follows this sequence:

1. Download and extract `SOURCE_URI`.
2. Run the PoC tests in `POC_TEST` (default `tests/poc`). Exit code 0 means the exploit worked: `poc_before=EXPLOITABLE`.
3. Apply `PATCH_URI` with `git apply` (falls back to `patch -p1`). If `PATCH_URI=none`, skip this step.
4. Run the PoC again: `poc_after`.
5. Run `UNIT_TEST_CMD` (default `python -m pytest -q tests/unit`).
6. Print one JSON line with `"event_type": "SANDBOX_RESULT"` to stdout.

Environment variables (overridden per execution): `RUN_ID`, `REPOSITORY`, `COMMIT_SHA`, `SOURCE_URI`, `PATCH_URI`, `ISSUE_ID`, `POC_TEST`, `UNIT_TEST_CMD`, `TIMEOUT_SECONDS` (default 600).

Verdict rules:

| Verdict | Condition |
|---|---|
| `PATCH_VERIFIED` | `poc_before=EXPLOITABLE` and `poc_after=NOT_EXPLOITABLE` and unit tests passed |
| `POC_NOT_REPRODUCED` | `poc_before` is not `EXPLOITABLE` |
| `ERROR` | Infrastructure failure (download failed, timeout, etc.) |
| `PATCH_FAILED` | Anything else (for example, still exploitable after the patch, or unit tests broke) |

PoC convention: a PoC test in `sample-app/tests/poc/test_poc_*.py` **passes** when the exploit works.

---

## Steps

### 1. Inspect the network and job Terraform (5 min)

```bash
cd infra/terraform
grep -n "sandbox-deny-all-egress\|sandbox-allow-restricted-apis\|199.36.153.4" network.tf
grep -rn "codemender-sandbox" *.tf
```

Expected: two firewall rules with priorities 65000 and 1000, the `199.36.153.4/30` range, and a `google_cloud_run_v2_job` resource named `codemender-sandbox`. The exact resource file name for the job may differ; use the `grep -rn` result.

Check these points in the job resource:
- `service_account` is `sandbox-runner-sa@...`
- `vpc_access` has `egress = "ALL_TRAFFIC"` and points at `sandbox-subnet`
- no `execution_environment` setting for gen1 (jobs are gen2 only)

Confirm the deployed firewall rules:

```bash
gcloud compute firewall-rules list \
  --filter="network~sandbox-vpc" \
  --format="table(name,direction,priority,destinationRanges.list(),denied[].IPProtocol.list(),allowed[].map().firewall_rule().list())"
```

Expected (two rows):

```
NAME                           DIRECTION  PRIORITY  DEST_RANGES      ...
sandbox-allow-restricted-apis  EGRESS     1000      199.36.153.4/30
sandbox-deny-all-egress        EGRESS     65000     0.0.0.0/0
```

Confirm the service account has no project-level roles:

```bash
gcloud projects get-iam-policy "$GCP_PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:sandbox-runner-sa@" \
  --format="value(bindings.role)"
```

Expected: no output.

### 2. Build and deploy the image (8 min)

```bash
cd sandbox
./deploy.sh
```

`deploy.sh` builds the image, pushes it to Artifact Registry repo `security-lab` as image `codemender-sandbox`, and updates the job `codemender-sandbox`. Read the script header for the variables it expects (`GCP_PROJECT_ID`, `REGION`).

Expected: the script ends with the job description. Verify:

```bash
gcloud run jobs describe codemender-sandbox --region="$REGION" \
  --format="value(template.template.containers[0].image,template.template.serviceAccount)"
```

Expected: an image path ending in `security-lab/codemender-sandbox:...` and `sandbox-runner-sa@your-gcp-project-id.iam.gserviceaccount.com`.

### 3. Run locally first (7 min)

Run the same container on your machine against the local `sample-app/` so you can see the output format before using the cloud.

```bash
cd sandbox
./run_local.sh
```

The default run uses `CM-0001` and the reference patch `sample-app/patches/CM-0001-sqli.diff`. See `sandbox/README.md` for the flags that select another issue or `none` for the patch.

Expected last line (formatted here for reading; the real output is one line):

```json
{"severity": "INFO", "event_type": "SANDBOX_RESULT", "issue_id": "CM-0001",
 "poc_before": "EXPLOITABLE", "poc_after": "NOT_EXPLOITABLE",
 "patch_applied": true, "unit_tests_passed": true, "verdict": "PATCH_VERIFIED", ...}
```

Now run with no patch. Expected: `"poc_before": "EXPLOITABLE"`, `"poc_after": "EXPLOITABLE"`, `"patch_applied": false`, `"verdict": "PATCH_FAILED"`. The code is still exploitable.

### 4. Stage inputs in the bucket (5 min)

```bash
cd sandbox
export COMMIT_SHA=$(git -C ../sample-app rev-parse HEAD)   # or the SHA of the pushed payment-service repo
export RUN_ID="run-$(date +%Y%m%d%H%M%S)"
./stage_inputs.sh
```

`stage_inputs.sh` creates the source tarball and uploads the patch. Check `sandbox/README.md` for its exact arguments (repository, commit SHA, issue ID, patch file, run ID).

Verify:

```bash
gcloud storage ls "gs://${SANDBOX_BUCKET}/sources/${GITHUB_ORG}__payment-service/"
gcloud storage ls "gs://${SANDBOX_BUCKET}/patches/CM-0001/"
```

Expected: `<COMMIT_SHA>.tar.gz` and `<RUN_ID>.diff`.

### 5. Execute the job with env overrides (5 min)

```bash
gcloud run jobs execute codemender-sandbox \
  --region="$REGION" \
  --update-env-vars="RUN_ID=${RUN_ID},REPOSITORY=${GITHUB_ORG}/payment-service,COMMIT_SHA=${COMMIT_SHA},SOURCE_URI=gs://${SANDBOX_BUCKET}/sources/${GITHUB_ORG}__payment-service/${COMMIT_SHA}.tar.gz,PATCH_URI=gs://${SANDBOX_BUCKET}/patches/CM-0001/${RUN_ID}.diff,ISSUE_ID=CM-0001,POC_TEST=tests/poc" \
  --wait
```

Expected: `Execution [codemender-sandbox-xxxxx] has successfully completed.` Note the execution name.

Run it again with `PATCH_URI=none` and a new `RUN_ID`. The execution still completes successfully (the runner exits 0 after printing a result). The verdict is in the log, not in the exit status. Confirm in your environment whether `runner.py` exits non-zero on `ERROR`.

### 6. Prove egress is blocked (5 min)

Run a one-off execution that overrides the command and tries to reach the internet and a Google API:

```bash
gcloud run jobs execute codemender-sandbox --region="$REGION" --wait \
  --args="-c","import urllib.request as u
for url in ['https://github.com','https://pypi.org/simple/','https://storage.googleapis.com']:
    try:
        u.urlopen(url, timeout=5); print('REACHABLE', url)
    except Exception as e:
        print('BLOCKED', url, type(e).__name__)" \
  --update-env-vars="RUN_ID=egress-test"
```

This assumes the image entrypoint is `python`. If `sandbox/Dockerfile` uses a different entrypoint, add `--command=python` (confirm in your environment). Read the output:

```bash
gcloud logging read \
  'resource.type="cloud_run_job" AND resource.labels.job_name="codemender-sandbox" AND textPayload:("BLOCKED" OR "REACHABLE")' \
  --limit=10 --format="value(textPayload)" --freshness=10m
```

Expected:

```
BLOCKED https://github.com URLError
BLOCKED https://pypi.org/simple/ URLError
REACHABLE https://storage.googleapis.com
```

`storage.googleapis.com` resolves to the restricted VIP and is allowed. The other two time out or fail DNS. A 403/404 HTTP error from storage still counts as reachable.

### 7. Read SANDBOX_RESULT in Cloud Logging (3 min)

```bash
gcloud logging read \
  'resource.type="cloud_run_job" AND resource.labels.job_name="codemender-sandbox" AND jsonPayload.event_type="SANDBOX_RESULT"' \
  --limit=5 --freshness=1h \
  --format="table(timestamp,jsonPayload.run_id,jsonPayload.issue_id,jsonPayload.poc_before,jsonPayload.poc_after,jsonPayload.verdict)"
```

Expected:

| RUN_ID | ISSUE_ID | POC_BEFORE | POC_AFTER | VERDICT |
|---|---|---|---|---|
| run-...(patch) | CM-0001 | EXPLOITABLE | NOT_EXPLOITABLE | PATCH_VERIFIED |
| run-...(none) | CM-0001 | EXPLOITABLE | EXPLOITABLE | PATCH_FAILED |

The entries also carry the label `component=codemender-sandbox`. The log sink `security-logs-to-pubsub` forwards these to ingestion (Module 05).

### 8. Trigger from GitHub via Workload Identity Federation (5 min)

The workflow `sandbox-validate.yml` in `payment-service` authenticates with WIF (pool `github-pool`, provider `github-provider`, SA `github-actions-sa`). No JSON key is used.

Set repository variables (Settings > Secrets and variables > Actions > Variables):

| Variable | Value |
|---|---|
| `GCP_WIF_PROVIDER` | `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider` |
| `GCP_SA_EMAIL` | `github-actions-sa@your-gcp-project-id.iam.gserviceaccount.com` |
| `GCP_PROJECT_ID` | `your-gcp-project-id` |
| `GCP_REGION` | `us-central1` |
| `SANDBOX_BUCKET` | `your-gcp-project-id-sandbox-inputs` |

Run it:

```bash
gh workflow run sandbox-validate.yml \
  --repo "${GITHUB_ORG}/payment-service" \
  -f issue_id=CM-0001 \
  -f commit_sha="${COMMIT_SHA}" \
  -f patch_path=patches/CM-0001-sqli.diff
gh run watch --repo "${GITHUB_ORG}/payment-service"
```

The workflow uploads the patch, runs `gcloud run jobs execute codemender-sandbox --update-env-vars ... --wait`, and writes the verdict to the job summary (and a PR comment when run for a PR).

Expected: run succeeds; job summary shows `PATCH_VERIFIED`.

### 9. Trigger from the agent (2 min)

The custom MCP tool `start_sandbox_validation(repository, commit_sha, patch_uri, issue_id, poc_test="tests/poc", confirmed=False)` is an action tool. Without `confirmed=True` it returns:

```json
{"error": "confirmation_required", ...}
```

The agent must show you what it will run and wait for your "yes". Only then does it call again with `confirmed=True`. The tool returns a `run_id` and an execution name. `get_sandbox_result(run_id=...)` returns the execution status and the `sandbox_runs` row.

In the agent (ADK web UI or Gemini Enterprise, after Module 07), type:

```
Validate the reference patch for CM-0001 in the sandbox. The patch is at
gs://your-gcp-project-id-sandbox-inputs/patches/CM-0001/<RUN_ID>.diff and the commit is <COMMIT_SHA>.
```

Expected: the agent describes the run and asks for confirmation. Reply `yes`. It starts the job, then reports `PATCH_VERIFIED` once `get_sandbox_result` returns a finished run.

If you have not finished Module 07 yet, come back to this step later. Module 08 Part 2 repeats it.

---

## Check your work

- [ ] Firewall list shows deny-all at 65000 and restricted-VIP allow at 1000.
- [ ] `sandbox-runner-sa` has no project-level roles.
- [ ] Local run: `PATCH_VERIFIED` with the reference patch, `PATCH_FAILED` with `none`.
- [ ] Cloud run: the same two verdicts appear in Cloud Logging as `SANDBOX_RESULT` entries.
- [ ] Egress test: github.com and pypi.org blocked; storage.googleapis.com reachable.
- [ ] `sandbox-validate.yml` ran through WIF and reported `PATCH_VERIFIED`.
- [ ] The agent asked for confirmation before calling `start_sandbox_validation` with `confirmed=True`.

## Troubleshooting pointers

See [troubleshooting.md](troubleshooting.md#sandbox-cloud-run-job) for: job cannot read GCS, `iam.serviceAccountUser` errors, timeouts, missing dependencies. For WIF errors see [troubleshooting.md](troubleshooting.md#workload-identity-federation).

## What you built

- An isolated validation sandbox: Cloud Run Job (gen2 microVM), no internet egress, no IAM permissions, ephemeral.
- A staging convention (source tarball + patch in GCS) that works without egress.
- Three ways to start a validation run: CLI, GitHub Actions through WIF, and the agent with human confirmation.
- A structured `SANDBOX_RESULT` log line that the ingestion pipeline turns into `security_lab.sandbox_runs` rows in the next module.
