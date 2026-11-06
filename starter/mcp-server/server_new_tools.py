"""Starter: MCP tool registrations for query_security_events and trace_code_to_cloud (Module 07).

How to use this file
--------------------
These two functions are the @mcp.tool() registrations you add to the CodeMender
MCP server (`codemender-mcp-server`). Fill in the TODO bodies here, then paste
both functions into mcp-server/server.py, next to the other tools in the
"MCP Tools" sections. In server.py the names `mcp` and `security_data_service`
already exist (they are created near the top of the file), so paste only the
functions.

Note: Wiz GraphQL code-to-cloud attribution (`wiz_trace_code_to_cloud`) lives in
the separate `wiz-mcp-server/` Cloud Run service. Here in `codemender-mcp-server`,
`trace_code_to_cloud` queries BigQuery (`codemender.findings` +
`security_lab.code_to_cloud_map`).

The finished versions are in mcp-server/server.py in the solution. If you fall
behind, compare against them or copy them.

This file is standalone so it compiles and imports on its own. The placeholders
below (`mcp`, `security_data_service`) stand in for the objects server.py
creates. Do not deploy this file.

The service methods these tools call are in
starter/mcp-server/services/security_data_service.py (query_security_events,
get_finding_repository, get_code_to_cloud).

Tests (run from mcp-server/ after pasting into server.py):
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
    - TestServerTools.test_trace_code_to_cloud_by_issue_id
    - TestServerTools.test_trace_code_to_cloud_by_resource_id
    - TestServerTools.test_trace_code_to_cloud_unresolvable_issue
    - TestServerTools.test_trace_code_to_cloud_requires_input
    - TestServerTools.test_pass_through_tools
    - TestServerTools.test_tools_and_prompt_registered
"""

from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP

# Placeholders. In mcp-server/server.py these are:
#   mcp = FastMCP(...)
#   security_data_service = SecurityDataService()
mcp = FastMCP("codemender-mcp-server-starter")
security_data_service: Any = None


@mcp.tool()
def query_security_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    issue_id: Optional[str] = None,
    days: int = 7,
    limit: int = 25,
) -> Dict[str, Any]:
    """Query normalized security events written by the log ingestion service (read-only).

    Args:
        event_type: CODEMENDER_SCAN_STARTED, CODEMENDER_SCAN_COMPLETED, CODEMENDER_FINDING,
            CODEMENDER_PATCH, SANDBOX_RESULT, IAM_POLICY_CHANGE or OTHER_SECURITY.
        severity: Finding severity (CRITICAL, HIGH, ...) or log severity (INFO, ERROR, ...).
        issue_id: Code Mender finding/issue ID, e.g. 'CM-0001'.
        days: Lookback window in days (default 7, max 90).
        limit: Max rows (default 25, max 200).
    """
    # TODO(lab-07): Return security_data_service.query_security_events(...) and pass every
    #   argument through by keyword: event_type, severity, issue_id, days, limit.
    #   Do not validate here; the service validates and parameterizes the query.
    #   The docstring above is what the agent sees as the tool description. Keep it.
    # Checked by: mcp-server/tests/test_new_tools.py TestServerTools.test_pass_through_tools
    #             and TestServerTools.test_tools_and_prompt_registered
    return {"error": "TODO"}


@mcp.tool()
def trace_code_to_cloud(issue_id: Optional[str] = None, resource_id: Optional[str] = None) -> Dict[str, Any]:
    """Map a Code Mender finding, Wiz issue ID, or cloud resource to its container image and source repository via BigQuery.

    Queries the BigQuery code_to_cloud_map table (and the Code Mender findings table to
    resolve a finding or issue ID to a repository). For live Wiz GraphQL code-to-cloud
    attribution, use `wiz_trace_code_to_cloud` on the Wiz MCP server (`wiz-mcp-server`).

    Args:
        issue_id: Code Mender finding ID (e.g. 'CM-0003') or Wiz issue ID (e.g. 'wiz-issue-0001').
        resource_id: Cloud provider resource ID
            (e.g. '//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/services/payment-service').
    """
    # TODO(lab-07): Implement BigQuery lookup over codemender.findings + security_lab.code_to_cloud_map.
    #   1. If neither issue_id nor resource_id is given, return {"error": "Provide issue_id or resource_id."}.
    #   2. Start with lookup_resource = resource_id, repository = None, finding = None.
    #   3. If issue_id is given without lookup_resource, call
    #      security_data_service.get_finding_repository(issue_id). If it returns an "error",
    #      return {"source": "bigquery", "found": False, "error": <error>}. If it returns rows
    #      in "data", take finding = rows[0] and repository = finding.get("repository").
    #   4. If there is still no lookup_resource and no repository, return
    #      {"source": "bigquery", "found": False, "finding": finding, "mappings": [],
    #       "message": "No resource or repository could be resolved for this issue."}.
    #   5. bq_result = security_data_service.get_code_to_cloud(resource_id=lookup_resource, repository=repository).
    #      On "error" return {"source": "bigquery", "found": False, "error": bq_result["error"]}.
    #   6. Otherwise let mappings = bq_result.get("data") or [] and return
    #      {"source": "bigquery", "found": bool(mappings), "issue_id": issue_id,
    #       "finding": finding, "filters_applied": bq_result.get("filters_applied"),
    #       "mappings": mappings}.
    # Checked by: mcp-server/tests/test_new_tools.py TestServerTools.test_trace_code_to_cloud_by_issue_id,
    #             test_trace_code_to_cloud_by_resource_id,
    #             test_trace_code_to_cloud_unresolvable_issue,
    #             test_trace_code_to_cloud_requires_input
    return {"error": "TODO"}
