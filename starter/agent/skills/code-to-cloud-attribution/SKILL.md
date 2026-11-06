---
name: code-to-cloud-attribution
description: Connect a cloud resource or Wiz issue to the repository, file, commit and owner that produced it, and connect a code finding to the deployed resource it affects.
---

<!--
STARTER FILE (Module 07, step B2). Keep the front matter above unchanged:
`name` must match the folder name, and `description` is what the agent uses to
decide when this skill applies. Replace the two TODO sections below.
Solution: agent/skills/code-to-cloud-attribution/SKILL.md.
No unit test checks the body. Check it with the Module 07 B4 prompt:
  "Where did the container image behind wiz-issue-0004 come from? Give me the
   repo, Dockerfile, base image and Terraform file."
With a complete skill the agent calls trace_code_to_cloud, then reads the
Dockerfile through GitHub MCP, and names your-github-org/payment-service,
Dockerfile, python:3.8-slim-buster and the Terraform path.
-->

## When to use
- "Which code deployed this Cloud Run service?"
- "Is CM-0004 actually running in production?"
- Before patching a cloud issue, to find where the fix belongs (app code, Dockerfile or Terraform).

## Steps
TODO(lab-07): Write numbered steps the agent follows. Cover:
1. Where to start: a resource ID -> `trace_code_to_cloud(resource_id=...)`; a finding or Wiz issue ID -> `trace_code_to_cloud(issue_id=...)`. Give an example resource ID for `payment-service`.
2. `trace_code_to_cloud` asks Wiz first and falls back to `security_lab.code_to_cloud_map`. Tell the agent to report which one answered (the tool's `source` field: `wiz` or `bigquery`).
3. Which mapping fields to read: `repository`, `commit_sha`, `image`, `image_digest`, `base_image`, `dockerfile_path`, `terraform_path`.
4. How to confirm in GitHub: `get_file_contents` for the Dockerfile or Terraform file at `commit_sha` (not `main`), and the image label `org.opencontainers.image.source`.
5. How to decide where the fix lives: base image / OS package -> `Dockerfile` (CWE-1104); over-permissioned service account -> `terraform/main.tf` (CWE-250/CWE-732); application bug -> the file in the finding (`app/db.py`, `app/receipts.py`).
6. How to find the owner: `.github/CODEOWNERS`.

## Tools
- CodeMender MCP: `trace_code_to_cloud`, `query_codemender_bigquery` (read-only SQL on the mapping if needed).
- Wiz MCP: resource and code-to-cloud graph.
- GitHub MCP: `get_file_contents`, `list_commits`.

## Output format
TODO(lab-07): Write a fixed answer template (in a code block) with one line each for:
- the resource ID,
- what it was built from: repository@commit_sha, image@digest, base image,
- the fix location and the reason,
- the owner from CODEOWNERS,
- the evidence (tool names and IDs) and which mapping source answered.

## Do not
- Do not assume `main` is what is deployed. Use the commit SHA from the mapping.
- Do not invent a mapping when both Wiz and the table return nothing; say it is unmapped.
