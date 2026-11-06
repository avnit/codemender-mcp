# payment-service (INTENTIONALLY VULNERABLE - LAB / SANDBOX USE ONLY)

> **Warning:** this app contains deliberate security flaws. It is the target
> for the "Build an AI Security Agent on Gemini Enterprise integrated with Wiz,
> Cloud Logging, GitHub, CodeMender, and BigQuery" lab. Do not deploy it to
> production or expose it to untrusted networks. It binds to `127.0.0.1` by
> default and logs a warning at startup.

A small Flask payment service with a SQLite transactions table and a receipts
endpoint. The PoCs are local and benign: the SQL injection returns extra rows
from a local SQLite file built from seed rows, and the path traversal reads
`data/not_a_secret.txt`, a dummy file. No real data or credentials.

## Vulnerabilities

| ID | CWE | File | Description |
|---|---|---|---|
| CM-0001 | CWE-89 | `app/db.py:73` | `get_transactions()` builds SQL with an f-string. `account=' OR '1'='1` returns every account's rows. |
| CM-0002 | CWE-22 | `app/receipts.py:23` | `read_receipt()` joins `data/receipts/` and user input without normalizing. `file=../not_a_secret.txt` reads outside the directory. |
| CM-0003 | CWE-250 | `terraform/main.tf:32` | Service account `payment-service-sa` has `roles/editor` on the project. |
| CM-0004 | CWE-1104 | `Dockerfile:7` | End-of-life base image `python:3.8-slim-buster`. |

The matching seed findings are in `.codemender/mock-findings.json` (Wiz issues
`wiz-issue-0001` to `wiz-issue-0004`). Reference fixes for CM-0001 and CM-0002
are in `patches/`. These are the answer key. The agent is expected to produce
equivalent diffs.

## Layout

```
app/                 Flask app (create_app), db.py (CM-0001), receipts.py (CM-0002)
data/                receipts/receipt-0001.txt, not_a_secret.txt (dummy)
tests/unit/          pass before and after a correct fix
tests/poc/           test_poc_*.py: PASS while the exploit works, FAIL after the fix
patches/             reference fixes (apply with git apply or patch -p1)
terraform/           Cloud Run service + over-permissioned SA (CM-0003)
.codemender/         mock findings for codemender-scan mode=mock
.github/             workflows, PR template, CODEOWNERS
docs/                branch protection settings
```

## Run locally

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m app.main            # http://127.0.0.1:8080 (set HOST/PORT to change)
curl 'http://127.0.0.1:8080/health'
curl 'http://127.0.0.1:8080/api/transactions?account=ACC-1001'
curl 'http://127.0.0.1:8080/api/receipts?file=receipt-0001.txt'
```

The SQLite file defaults to `data/payments.db` (override with `DB_PATH`) and is
re-seeded at startup with accounts ACC-1001, ACC-1002, ACC-1003.

Tests (unittest; also run under pytest). Flask route tests skip if Flask is
not installed. Tests use `data/test_payments.db` (override with `TEST_DB_PATH`).

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python -m pytest -q tests/unit          # what the sandbox runs
python -m pytest -q tests/poc           # exit 0 = exploit reproduced
```

To check a fix by hand:

```bash
git apply patches/CM-0001-sqli.diff
python -m pytest -q tests/poc/test_poc_sqli.py   # now fails: not exploitable
python -m pytest -q tests/unit                   # still passes
```

## Push to your GitHub org

The contents of this directory become the root of
`your-github-org/payment-service`.

```bash
cd sample-app
git init -b main
git add .
git commit -m "Initial import of payment-service lab app (intentionally vulnerable)"
git remote add origin https://github.com/your-github-org/payment-service.git
git push -u origin main
```

Then set these under **Settings > Secrets and variables > Actions**:

| Kind | Name | Example |
|---|---|---|
| Variable | `GCP_PROJECT_ID` | `your-gcp-project-id` |
| Variable | `GCP_REGION` | `us-central1` |
| Variable | `SANDBOX_BUCKET` | `your-gcp-project-id-sandbox-inputs` |
| Variable | `GCP_WIF_PROVIDER` | `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider` |
| Variable | `GCP_SA_EMAIL` | `github-actions-sa@your-gcp-project-id.iam.gserviceaccount.com` |
| Secret | `CODEMENDER_API_URL` | live mode only |
| Secret | `CODEMENDER_API_TOKEN` | live mode only |

## How the lab uses the workflows

Both workflows authenticate to GCP with Workload Identity Federation (no
service account keys).

### `codemender-scan` (workflow_dispatch)

Inputs: `mode` (`mock` default, or `live`), `commit_sha` (default: the
dispatched commit).

1. Stages `git archive` of the commit to
   `gs://SANDBOX_BUCKET/sources/<owner>__<name>/<sha>.tar.gz`.
2. Gets findings. `mock` reads `.codemender/mock-findings.json`. `live` POSTs
   to `CODEMENDER_API_URL`. CodeMender has no public API, so this is a
   pluggable endpoint you provide. The request/response contract is in the
   workflow header.
3. Writes `CODEMENDER_SCAN_STARTED`, one `CODEMENDER_FINDING` per finding, and
   `CODEMENDER_SCAN_COMPLETED` to log ID `codemender`. The log sink sends these
   to Pub/Sub, and the ingestion service loads them into BigQuery.
4. Writes a findings table to the job summary.

### `sandbox-validate` (workflow_dispatch)

Inputs: `issue_id`, `commit_sha` (base commit), exactly one of `patch_path` or
`branch`, optional `pr_number`, optional `poc_test`.

- `patch_path`: a diff in the repo, e.g. `patches/CM-0001-sqli.diff`.
- `branch`: the agent pushes its fix to `security/<finding-id>-<slug>` and
  dispatches the workflow with that branch. The patch is
  `git diff <commit_sha>...origin/<branch>`.

The workflow uploads the patch to
`gs://SANDBOX_BUCKET/patches/<issue_id>/<run_id>.diff` (run_id =
`<github.run_id>-<github.run_attempt>`), stages the source if missing, runs the
`codemender-sandbox` Cloud Run Job against the base commit, reads the
`SANDBOX_RESULT` log entry, and posts it to the job summary and (if
`pr_number` is set) as a PR comment. It fails unless the verdict is
`PATCH_VERIFIED`, so it can be a required status check.

If `poc_test` is empty, CM-0001 uses `tests/poc/test_poc_sqli.py`, CM-0002
uses `tests/poc/test_poc_path_traversal.py`, and anything else uses
`tests/poc`.

The sandbox is a Cloud Run Job on the second-generation execution environment
(microVM), in an egress-denied VPC, with a service account that has no
permissions except reading the inputs bucket. The original brief asked for
gVisor. Cloud Run Jobs do not offer gen1 (gVisor), so gen2 is used.

## Branch protection

The agent may open PRs. A human must review and merge them. Summary:

1. Require a pull request before merging, 1 approval, Code Owner review
   (`.github/CODEOWNERS` = `@your-github-org/security-reviewers`).
2. Dismiss stale approvals on new commits.
3. Require status checks (`validate` from `sandbox-validate`) and up-to-date
   branches.
4. No bypass for anyone. Restrict who can push to `main`.
5. The agent's PAT or GitHub App must not have admin, maintain, or bypass
   rights.

Full settings: [docs/branch-protection.md](docs/branch-protection.md).

## Terraform

`terraform/` defines Cloud Run service `payment-service` with service account
`payment-service-sa` granted `roles/editor` at the project level (CM-0003).
**Do not apply it in the lab unless the facilitator tells you to.** It is a
scan target for code-to-cloud attribution.
