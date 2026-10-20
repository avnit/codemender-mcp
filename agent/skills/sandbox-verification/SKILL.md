---
name: sandbox-verification
description: Validate a proposed patch in the isolated codemender-sandbox Cloud Run Job (gen2, no internet egress) by running the PoC before and after the patch plus unit tests, and interpret the verdict.
---

## When to use
- After root-cause-and-patch produced a diff and the user wants proof it works.
- When the user asks for the result of an earlier sandbox run.

## Environment facts
- The sandbox is a Cloud Run Job named `codemender-sandbox` on the second-generation execution environment (microVM). Cloud Run Jobs do not offer gVisor (gen1); the original brief asked for gVisor.
- It has no internet egress and cannot clone from GitHub. Source and patch are read from `gs://<GCP_PROJECT_ID>-sandbox-inputs` through Private Google Access.
  - Source: `gs://BUCKET/sources/<repo_owner>__<repo_name>/<commit_sha>.tar.gz` (staged by the `codemender-scan.yml` workflow).
  - Patch: `gs://BUCKET/patches/<issue_id>/<run_id>.diff`.
- The service account `sandbox-runner-sa` has no project roles.

## Steps
1. Make sure you have: `repository` ("owner/name"), `commit_sha`, `patch_uri` (gs:// path of the diff), `issue_id`, and `poc_test` (default `tests/poc`). If the patch is not in the bucket yet, use the `sandbox-validate.yml` workflow (inputs `issue_id`, `commit_sha`, `patch_path` or `branch`), which uploads it. Running that workflow also needs confirmation.
2. Show the user what will run: the inputs above and the diff. Ask for confirmation.
3. Call `start_sandbox_validation(repository, commit_sha, patch_uri, issue_id, poc_test)`. The guardrail sets `confirmed=True` only after the user confirms. If the tool returns `confirmation_required`, ask the user; do not retry on your own.
4. Record `run_id` and `execution_name`. Poll `get_sandbox_result(run_id=...)` at most every 30 seconds, up to the job timeout (default 600 seconds).
5. Report the verdict with its evidence.

## Runner contract
Steps inside the job: download and extract source, run PoC (exit 0 means the exploit reproduced, `EXPLOITABLE`), apply patch (`git apply` or `patch -p1`), run PoC again, run unit tests (`python -m pytest -q tests/unit`), print one `SANDBOX_RESULT` JSON line. The ingestion service writes it to `security_lab.sandbox_runs` and `security_lab.security_events`.

## Verdicts
- `PATCH_VERIFIED`: `poc_before=EXPLOITABLE`, `poc_after=NOT_EXPLOITABLE`, unit tests passed. The patch can go to pr-creation.
- `PATCH_FAILED`: the exploit still works after the patch, or unit tests failed. Read `log_excerpt`, `tests_failed`, `patch_applied`. Revise the patch once.
- `POC_NOT_REPRODUCED`: the PoC did not succeed on the unpatched code. The test proves nothing. Check `poc_test` path and commit; do not claim the patch works.
- `ERROR`: infrastructure failure (download, extraction, patch apply, timeout). Report the error; do not retry more than once.

## When to stop
- Stop after two `PATCH_FAILED` results for the same finding and hand over to a human with both diffs and log excerpts.
- Stop after one repeated `ERROR` and report it.
- Stop immediately if the user rejects the run.

## Tools
- CodeMender MCP: `start_sandbox_validation` (action, confirmation required), `get_sandbox_result`, `query_security_events(event_type="SANDBOX_RESULT", issue_id=...)`.
- GitHub MCP: `run_workflow` for `sandbox-validate.yml` (action, confirmation required).

## Output format
```
Sandbox run: <run_id> (<execution_name>)
Inputs: <repository>@<commit_sha>, patch <patch_uri>, PoC <poc_test>
PoC before: <value>  PoC after: <value>  Patch applied: <bool>
Unit tests: <passed>/<total> (failed <n>)
Verdict: <verdict> - <one-sentence meaning>
Evidence: get_sandbox_result run_id=<id>
```

## Do not
- Do not start a run without user confirmation.
- Do not call PATCH_VERIFIED anything other than PATCH_VERIFIED.
- Do not change PoC tests to get a better verdict.
