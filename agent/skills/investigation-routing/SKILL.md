---
name: investigation-routing
description: Choose the right source and tool (Wiz MCP, Cloud Logging MCP, GitHub MCP, CodeMender MCP, BigQuery or the Data Insights agent) for a security question before calling anything.
---

## When to use
- At the start of every investigation question.
- When a tool returned nothing and you need a second source.

## Steps
1. Classify the question with the table below.
2. Call the primary tool. Keep filters narrow (project, severity, last 7 days, limit 25).
3. If the primary source is not connected or returns nothing, use the fallback and say you did.
4. Combine answers only after each source has been cited separately.

| Question type | Primary source | Tool | Fallback |
|---|---|---|---|
| Top critical internet-facing vulnerabilities in production | CodeMender MCP (Wiz helper) | `wiz_top_internet_facing_vulnerabilities(environment="production", severity="CRITICAL", limit=5)` | Wiz MCP issue search |
| Identities with excessive permissions | CodeMender MCP (Wiz helper) | `wiz_excessive_permission_identities(service=..., project=...)` | Wiz MCP graph query |
| Any Wiz issue detail or graph question | Wiz MCP | Wiz MCP tools | `get_wiz_issue_details`, `query_wiz_graphql` |
| Who changed IAM, when, from where | Cloud Logging MCP | `list_log_entries` with filter `protoPayload.methodName="SetIamPolicy"` | `query_security_events(event_type="IAM_POLICY_CHANGE")` |
| Which logs exist in the project | Cloud Logging MCP | `list_log_names` | none |
| What did CodeMender find | CodeMender MCP | `list_codemender_issues`, `get_issue_details`, `get_issues_summary` | `query_codemender_bigquery` |
| CodeMender log lines for an issue | CodeMender MCP | `get_issue_logs`, `search_codemender_logs` | Cloud Logging `list_log_entries` with `logName:"logs/codemender"` |
| SCC findings | CodeMender MCP | `query_scc_findings` | GE Data Insights agent on `scc_export.findings` |
| Model Armor blocks or matches | CodeMender MCP | `query_model_armor_logs` | Data Insights agent on `security_logs` |
| VPC Service Controls violations | CodeMender MCP | `query_vpcsc_violations` | Data Insights agent on `security_logs` |
| Security event timeline (scans, patches, sandbox, IAM) | CodeMender MCP | `query_security_events` | Data Insights agent on `security_lab.security_events` |
| Which repo/commit built this cloud resource | CodeMender MCP | `trace_code_to_cloud(resource_id=...)` | Wiz MCP code-to-cloud |
| Show the vulnerable code | GitHub MCP | `get_file_contents` | none |
| Did the patch work | CodeMender MCP | `get_sandbox_result(run_id=...)` | `query_security_events(event_type="SANDBOX_RESULT")` |
| Trend or aggregate questions across tables | GE Data Insights agent | natural-language question | bigquery-data-insights SQL |

## Tools
All tools named in the table. Cloud Logging MCP takes one resource project per call (`projects/your-gcp-project-id`).

## Output format
Start the answer with one line: `Sources: <source> via <tool>[, ...]`. Then the answer, with IDs inline.

## Do not
- Do not query every source "just in case".
- Do not answer a data question from memory when a source exists.
- Do not widen time ranges past 30 days without telling the user.
