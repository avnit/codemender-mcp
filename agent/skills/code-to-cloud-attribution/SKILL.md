---
name: code-to-cloud-attribution
description: Connect a cloud resource or Wiz issue to the repository, file, commit and owner that produced it, and connect a code finding to the deployed resource it affects.
---

## When to use
- "Which code deployed this Cloud Run service?"
- "Is CM-0004 actually running in production?"
- Before patching a cloud issue, to find where the fix belongs (app code, Dockerfile or Terraform).

## Steps
1. Start from what you have:
   - Resource ID (for example `//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/services/payment-service`): call `wiz_trace_code_to_cloud(resource_id=...)` on Wiz MCP (`wiz-mcp-server`) if connected, and/or `trace_code_to_cloud(resource_id=...)` on CodeMender MCP (`codemender-mcp-server`).
   - Finding or Wiz issue ID: call `wiz_trace_code_to_cloud(issue_id=...)` on Wiz MCP first if connected; if Wiz is not connected or returns `found=False`, call `trace_code_to_cloud(issue_id=...)` on CodeMender MCP (`security_lab.code_to_cloud_map` + `codemender.findings`).
2. Report which MCP service answered (`source: wiz` from `wiz_trace_code_to_cloud` vs `source: bigquery` from `trace_code_to_cloud`).
3. Read the mapping fields: `repository`, `commit_sha`, `image`, `image_digest`, `base_image`, `dockerfile_path`, `terraform_path`.
4. Confirm in GitHub: `get_file_contents` for the Dockerfile or Terraform file at `commit_sha`. Check the image label `org.opencontainers.image.source=https://github.com/<github_org>/payment-service`.
5. Decide where the fix lives:
   - Base image or OS package issue: `Dockerfile` (CWE-1104).
   - Over-permissioned service account: `terraform/main.tf` (CWE-250/CWE-732).
   - Application vulnerability: the file in the finding (`app/db.py`, `app/receipts.py`).
6. Find the owner from CODEOWNERS (`get_file_contents` on `.github/CODEOWNERS`).

## Tools
- Wiz MCP (`wiz-mcp-server` on Cloud Run): `wiz_trace_code_to_cloud`, `get_wiz_issue_details`, `query_wiz_graphql`.
- CodeMender MCP (`codemender-mcp-server` on Cloud Run): `trace_code_to_cloud`, `query_codemender_bigquery` (read-only SQL on `security_lab.code_to_cloud_map` if needed).
- GitHub MCP: `get_file_contents`, `list_commits`.

## Output format
```
Resource: <resource_id>
Built from: <repository>@<commit_sha>   image <image>@<digest>, base <base_image>
Fix location: <path> (<reason>)
Owner: <CODEOWNERS entry>
Evidence: <tool + IDs>; mapping source: wiz | bigquery (the `source` field returned by wiz_trace_code_to_cloud / trace_code_to_cloud)
```

## Do not
- Do not assume `main` is what is deployed. Use the commit SHA from the mapping.
- Do not invent a mapping when both Wiz and the table return nothing; say it is unmapped.
