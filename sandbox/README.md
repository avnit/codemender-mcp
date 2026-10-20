# sandbox/ — CodeMender patch validation

The sandbox is the Cloud Run Job `codemender-sandbox`. One execution takes one
commit, one PoC test and one patch, and answers: is the code exploitable before
the patch, is it still exploitable after, and do the unit tests still pass?
It prints one `SANDBOX_RESULT` JSON line to stdout. Cloud Logging turns it into
`jsonPayload`, the log sink sends it to Pub/Sub, and `log-ingestion/` writes it
to the BigQuery table `sandbox_runs`.

## gVisor correction

The brief asked for gVisor. Cloud Run Jobs do not offer it: jobs run only on
the second-generation execution environment, which is a microVM sandbox.
gVisor is the first-generation environment and is available only for Cloud Run
services. This lab does not claim gVisor isolation.

Isolation in this lab comes from these controls together:

- gen2 microVM per task (Cloud Run Jobs default; cannot be changed).
- Direct VPC egress with `ALL_TRAFFIC` on `sandbox-vpc` / `sandbox-subnet`.
  The VPC firewall denies all egress except TCP 443 to the restricted Google
  APIs VIP `199.36.153.4/30`, used only to read inputs from GCS.
- Dedicated service account `sandbox-runner-sa` with no project roles. Its only
  grant is `roles/storage.objectViewer` on the inputs bucket.
- Ephemeral container per execution; nothing persists between runs.
- Non-root user (UID 10001) in the image.
- Task timeout 900 s, plus a runner timeout (`TIMEOUT_SECONDS`, default 600)
  that kills the PoC/test process group.
- `maxRetries: 0`, so a failing or hostile run is not retried.

If your security requirements specifically call for gVisor, run the runner as
a Kubernetes Job on a GKE node pool with GKE Sandbox enabled
(`runtimeClassName: gvisor`), keep the same egress-deny network policy and a
Workload Identity service account with the same single bucket grant. The
runner image and result format work unchanged; only the launcher changes. That
setup is outside this lab.

## Files

| File | Purpose |
|---|---|
| `runner/runner.py` | Validates inputs, fetches source + patch, runs PoC / patch / PoC / unit tests, prints the result. |
| `Dockerfile` | `python:3.12.7-slim-bookworm`, git + patch, pytest + Flask baked in, non-root. |
| `requirements.txt` | Packages baked into the image. There is no egress at runtime, so add any packages the code under test needs here. |
| `job.yaml` | Reference Cloud Run Job spec (`gcloud run jobs replace`). Terraform creates the real job. |
| `deploy.sh` | Builds the image to Artifact Registry `security-lab/codemender-sandbox` and deploys the job. For image builds and quick updates; Terraform in `infra/terraform/` owns the job definition. |
| `run_local.sh` | Runs the runner on your machine against `../sample-app` with `file://` URIs. No GCP. |
| `stage_inputs.sh` | `git archive` + upload source and patch to the inputs bucket, then prints the `gcloud run jobs execute` command. |
| `egress-check/` | A tiny test repo that proves egress is blocked (see below). |
| `tests/` | Runner tests (`unittest`, no network). |
| `.env.example` | Settings for the scripts. Copy to `.env`. |

## Runner contract

Environment variables per execution (set with `--update-env-vars`):

| Variable | Required | Notes |
|---|---|---|
| `RUN_ID` | yes | `[A-Za-z0-9._:-]{1,128}`. Generated if missing (ad-hoc runs only). |
| `REPOSITORY` | yes | `owner/name`. |
| `COMMIT_SHA` | yes | 7-40 hex characters. |
| `SOURCE_URI` | yes | `gs://BUCKET/sources/<owner>__<name>/<commit_sha>.tar.gz`, or a local path / `file://` URI for local runs. Nothing else is accepted. |
| `PATCH_URI` | no | `gs://BUCKET/patches/<issue_id>/<run_id>.diff`, local path, or `none` (reproduce only). |
| `ISSUE_ID` | no | CodeMender issue id. |
| `POC_TEST` | no | Relative path in the source, default `tests/poc`. |
| `UNIT_TEST_CMD` | no | Default `python -m pytest -q tests/unit`. Split with `shlex`, never run through a shell. |
| `TIMEOUT_SECONDS` | no | Total budget for all steps, default 600, max 3600. Keep it below the 900 s task timeout. |
| `POC_CMD` | no | Added by this implementation. Default `python -m pytest -q {poc_test}`; `{poc_test}` is replaced by `POC_TEST`. Used by the local tests, which run without pytest. |
| `CLOUD_RUN_EXECUTION` | set by Cloud Run | Reported as `execution_name`. |

A leading `python` or `python3` in `POC_CMD` / `UNIT_TEST_CMD` is replaced by
the runner's own interpreter, so the baked-in packages are used.

Steps and how each outcome is classified:

1. Validate inputs. Any failure: verdict `ERROR`.
2. Download the source tarball and patch (GCS JSON API with the job's
   service-account token, or local file). Size limits: 200 MB tarball, 5 MB patch.
3. Extract safely. Rejected: absolute paths, `..` components, symlinks or hard
   links pointing outside the source dir, device files, FIFOs, more than 50,000
   entries or 1 GB expanded. A shipped `.git/` directory is dropped. On
   Python 3.12+ the `data` extraction filter also applies.
4. Check the patch: rejects absolute paths, `..`, and symlink creation.
5. PoC before patch. Exit 0 = `EXPLOITABLE`; exit 1 or other failure =
   `NOT_EXPLOITABLE`; exit 2-5 (pytest usage/internal error, no tests
   collected), timeout, missing test module = `ERROR`.
6. Apply the patch with `git apply` (or `patch -p1` if git is missing). A patch
   that does not apply gives `patch_applied=false`, no second PoC run, and
   verdict `PATCH_FAILED`.
7. PoC after patch.
8. Unit tests. `tests_total` / `tests_failed` are parsed from the pytest or
   unittest summary; `null` if the output has no recognizable summary.

Verdict (NAMING.md):

- `PATCH_VERIFIED`: poc_before=`EXPLOITABLE`, poc_after=`NOT_EXPLOITABLE`, unit tests passed.
- `POC_NOT_REPRODUCED`: poc_before is not `EXPLOITABLE`.
- `ERROR`: infrastructure failure (bad input, download/extraction failure,
  run deadline hit during setup). This implementation also returns `ERROR`
  when poc_before itself is `ERROR`, because the PoC never ran.
- `PATCH_FAILED`: everything else.

Exit code: 0 for every completed run (any verdict other than `ERROR`), 1 for
`ERROR`. With `maxRetries: 0`, an `ERROR` run marks the execution failed and is
not retried. Progress messages go to stderr; stdout carries only the result line.

## Result example

```json
{"severity":"INFO","message":"Sandbox run run-20261020-0001: PATCH_VERIFIED","event_type":"SANDBOX_RESULT","run_id":"run-20261020-0001","execution_name":"codemender-sandbox-x7k2p","repository":"your-github-org/sample-app","commit_sha":"3f9c2a1b7d4e5f60718293a4b5c6d7e8f9012345","patch_ref":"gs://your-gcp-project-id-sandbox-inputs/patches/CM-0001/run-20261020-0001.diff","issue_id":"CM-0001","poc_test":"tests/poc/test_poc_sql_injection.py","started_at":"2026-10-20T21:04:11.512Z","finished_at":"2026-10-20T21:04:19.870Z","poc_before":"EXPLOITABLE","poc_after":"NOT_EXPLOITABLE","patch_applied":true,"unit_tests_passed":true,"tests_total":12,"tests_failed":0,"verdict":"PATCH_VERIFIED","log_excerpt":"run_id=run-20261020-0001 ...\n--- poc before patch: -m pytest -q tests/poc/test_poc_sql_injection.py (exit 0) ---\n1 passed in 0.21s\n...","logging.googleapis.com/labels":{"component":"codemender-sandbox"}}
```

`log_excerpt` is capped at 4,000 characters (the tail is kept).

## Threat model

The code under test is untrusted: the PoC is designed to attack it, and the
patch was machine-generated. Assume anything in the source tree can run.

| Threat | Blocked by |
|---|---|
| Exfiltrating code or data to the internet | Direct VPC egress `ALL_TRAFFIC` + deny-all egress firewall on `sandbox-vpc`. Only `199.36.153.4/30:443` is allowed. |
| Downloading tools or second-stage payloads | Same firewall. pip/git clone cannot reach the internet; dependencies are baked into the image. |
| Using Google APIs to move laterally | `sandbox-runner-sa` has no project roles. Its only grant is objectViewer on the inputs bucket. The restricted VIP only serves APIs that support VPC Service Controls. |
| Escaping to the host or other workloads | gen2 microVM per task; ephemeral container; non-root UID 10001. |
| Path traversal / symlink tricks in the tarball or patch | Runner extraction and patch checks (see Steps 3-4). |
| Shell injection through env vars | Strict input validation; commands split with `shlex` and run without a shell. |
| Hanging or fork-bombing tests | Runner timeout kills the whole process group; 900 s task timeout; 1 vCPU / 2 GiB. |
| Retry loops on hostile input | `maxRetries: 0`. |
| Persistence between runs | New container per execution; source lives in in-memory `/tmp`. |

Residual risks, stated plainly:

- The PoC runs in the same container as the runner, so it can call the
  metadata server and get a token for `sandbox-runner-sa`. With the grants
  above, that token can only read objects in the inputs bucket.
- Test code can write to the container's stdout (for example via
  `/proc/1/fd/1`) and print a forged `SANDBOX_RESULT` line. Consumers should
  match on `run_id` and `execution_name` and treat a run with more than one
  result line as suspect.
- DNS queries to the VPC resolver are still possible. Without egress they
  cannot complete a connection, but a DNS lookup of an attacker domain could
  leak a small amount of data. Add a Cloud DNS response policy if this matters.
  Confirm in your environment.

## Run locally (no GCP)

```bash
cd sandbox
pip install -r requirements.txt   # pytest + flask for the sample app
./run_local.sh                                   # reproduce only
./run_local.sh --patch ../path/to/fix.diff --poc-test tests/poc/test_poc_sql_injection.py --issue-id CM-0001
```

To match the job more closely, build the image and run it with no network:

```bash
docker build -t codemender-sandbox .
./run_local.sh --docker --patch ../path/to/fix.diff
```

`--docker` uses `--network none`, `--read-only` and a tmpfs `/tmp`.

## Deploy and run

```bash
cd sandbox
cp .env.example .env    # set GCP_PROJECT_ID, REGION, SANDBOX_BUCKET
./deploy.sh             # build image + deploy job (Terraform also manages the job)

./stage_inputs.sh --repo-dir ../sample-app --subdir sample-app \
  --repository your-github-org/sample-app --commit HEAD \
  --patch /path/to/fix.diff --issue-id CM-0001 \
  --poc-test tests/poc/test_poc_sql_injection.py
# prints: gcloud run jobs execute codemender-sandbox --region ... --update-env-vars RUN_ID=...,... --wait
```

Use `--subdir` when the app is a folder inside a larger repo (it archives
`<commit>:<subdir>`). If an env var value ever contains a comma, use gcloud's
delimiter syntax: `--update-env-vars "^|^A=1,2|B=3"`.

Read the result:

```bash
gcloud logging read 'resource.type="cloud_run_job" AND resource.labels.job_name="codemender-sandbox" AND jsonPayload.event_type="SANDBOX_RESULT"' --limit 5 --format json
```

## Verify that egress is blocked

`egress-check/` is a tiny repo. Its PoC test tries
`socket.create_connection(("example.com", 443))`, `1.1.1.1:443` and
`github.com:443`, and passes only if one of them connects. Its unit tests
check that `storage.googleapis.com` resolves into `199.36.153.4/30` and is
reachable on 443.

```bash
cd sandbox
source .env
COPYFILE_DISABLE=1 tar -czf /tmp/egress-check.tar.gz -C egress-check .
SRC="gs://${SANDBOX_BUCKET}/sources/lab__egress-check/0000000.tar.gz"
gcloud storage cp /tmp/egress-check.tar.gz "$SRC"
gcloud run jobs execute codemender-sandbox --region "$REGION" \
  --update-env-vars RUN_ID=egress-check-001,REPOSITORY=lab/egress-check,COMMIT_SHA=0000000,SOURCE_URI=$SRC,PATCH_URI=none,ISSUE_ID=EGRESS-CHECK,POC_TEST=tests/poc \
  --wait
```

Expected result:

- `poc_before`: `NOT_EXPLOITABLE` (the log excerpt shows `egress blocked: ...` with timeouts or connection errors).
- `unit_tests_passed`: `true` (the GCS path works).
- `verdict`: `POC_NOT_REPRODUCED`.

If `poc_before` is `EXPLOITABLE`, the job has internet egress: check that the
job uses `--vpc-egress all-traffic` and that the deny-all egress firewall rule
exists on `sandbox-vpc`. If the unit tests fail, check the private DNS zone for
`googleapis.com` and the allow rule for `199.36.153.4/30`.

## Tests

```bash
cd sandbox
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

The tests build a small fake repo (a vulnerable function, a PoC test, unit
tests, patches) in a temp dir and run the runner end to end with `file://`
URIs. They use `python3 -m unittest` through `POC_CMD` / `UNIT_TEST_CMD`, so
pytest is not required. They need `git` or `patch` on the PATH.
