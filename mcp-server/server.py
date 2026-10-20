import json
import logging
import os
from typing import Any, Dict, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
import uvicorn
from mcp.server.fastmcp import FastMCP

from config import settings
from services.bigquery_service import BigQueryService
from services.logging_service import LoggingService
from services.wiz_service import WizService
from services.security_data_service import SecurityDataService
from services.sandbox_service import SandboxService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("codemender-mcp-server")

# Initialize services
bq_service = BigQueryService()
logging_service = LoggingService()
wiz_service = WizService()
security_data_service = SecurityDataService()
sandbox_service = SandboxService()

# Initialize FastMCP Server (stateless_http=True for serverless Cloud Run & Gemini Enterprise)
mcp = FastMCP(
    name="Code Mender Security MCP Server",
    instructions=(
        "You have access to Google Cloud BigQuery and Cloud Logging tools to search, "
        "inspect, and triage security findings and automated remediation jobs generated "
        "by Code Mender. Use these tools to find issues, review generated patches, inspect "
        "sandbox/execution logs, and diagnose remediation failures. You also have read-only "
        "access to Wiz cloud security issues (toxic combinations, threat detections, and "
        "cloud configuration findings) via the Wiz tools, including internet-facing "
        "vulnerabilities (wiz_top_internet_facing_vulnerabilities) and identities with "
        "admin or high privileges (wiz_excessive_permission_identities). "
        "Use trace_code_to_cloud to map a Wiz issue or cloud resource to its container image "
        "and source repository. Use query_scc_findings, query_model_armor_logs, "
        "query_vpcsc_violations and query_security_events for read-only BigQuery views of "
        "Security Command Center findings, Model Armor sanitize logs, VPC Service Controls "
        "denials, and ingested security events. "
        "start_sandbox_validation is the only action tool: it runs the codemender-sandbox "
        "Cloud Run Job. Before calling it with confirmed=True, show the user the repository, "
        "commit, patch and issue and get explicit approval. Use get_sandbox_result to read "
        "the execution status and verdict. Never merge pull requests; a human approves them."
    ),
    stateless_http=True,
)


# ============================================================================
# MCP Tools: BigQuery (Issues & Findings)
# ============================================================================

@mcp.tool()
def list_codemender_issues(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    repository: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    session_id: Optional[str] = None,
    search_query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 25,
    offset: int = 0,
    dataset: Optional[str] = None,
    table: Optional[str] = None,
) -> Dict[str, Any]:
    """List and filter security issues/findings published by Code Mender in BigQuery.

    Args:
        severity: Filter by severity (e.g. 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        status: Filter by status (e.g. 'DETECTED', 'OPEN', 'PATCH_GENERATED', 'VERIFIED', 'APPLIED', 'FIXED', 'FAILED').
        repository: Filter by code repository name or substring.
        vulnerability_type: Filter by vulnerability name or CWE (e.g. 'SQL_INJECTION', 'CWE-79').
        session_id: Filter by Code Mender session or run ID.
        search_query: Text search across title, description, or file path.
        start_date: Filter for findings created on or after this ISO date/timestamp (e.g. '2026-09-01').
        end_date: Filter for findings created on or before this ISO date/timestamp.
        limit: Max number of findings to return (default: 25, max: 200).
        offset: Offset for pagination.
        dataset: Optional BigQuery dataset override.
        table: Optional BigQuery table override.
    """
    return bq_service.list_issues(
        severity=severity,
        status=status,
        repository=repository,
        vulnerability_type=vulnerability_type,
        session_id=session_id,
        search_query=search_query,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
        dataset=dataset,
        table=table,
    )


@mcp.tool()
def get_issue_details(
    issue_id: str,
    dataset: Optional[str] = None,
    table: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve full details for a specific Code Mender issue or finding from BigQuery.

    Returns the complete record including file location, vulnerability description,
    suggested patch / diff, verification results, and remediation status.

    Args:
        issue_id: The unique finding ID or issue ID from Code Mender.
        dataset: Optional BigQuery dataset override.
        table: Optional BigQuery table override.
    """
    return bq_service.get_issue_details(issue_id=issue_id, dataset=dataset, table=table)


@mcp.tool()
def get_issues_summary(
    repository: Optional[str] = None,
    days: int = 30,
    dataset: Optional[str] = None,
    table: Optional[str] = None,
) -> Dict[str, Any]:
    """Get aggregated metrics and statistics on Code Mender findings.

    Returns total issues, open vs resolved counts, breakdown by severity,
    and top 5 most frequent vulnerability types within the specified period.

    Args:
        repository: Optional repository filter.
        days: Lookback window in days (default: 30).
        dataset: Optional BigQuery dataset override.
        table: Optional BigQuery table override.
    """
    return bq_service.get_issues_summary(
        repository=repository, days=days, dataset=dataset, table=table
    )


@mcp.tool()
def get_bigquery_schema(
    dataset: Optional[str] = None,
    table: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect the schema and metadata of the Code Mender BigQuery table.

    Useful for discovering available columns, data types, and row counts before
    constructing custom queries.

    Args:
        dataset: BigQuery dataset (defaults to configured dataset).
        table: BigQuery table (defaults to configured table).
    """
    return bq_service.get_table_schema(dataset=dataset, table=table)


@mcp.tool()
def query_codemender_bigquery(
    query: str,
    limit: int = 50,
) -> Dict[str, Any]:
    """Execute a safe, read-only SQL query against the Code Mender BigQuery dataset.

    Only SELECT and WITH statements are permitted. Mutations (INSERT, UPDATE, DELETE,
    DROP, ALTER, CREATE) will be rejected.

    Args:
        query: Standard SQL read-only query string.
        limit: Maximum rows to return (default: 50, capped at max_query_limit).
    """
    return bq_service.execute_read_query(query=query, limit=limit)


# ============================================================================
# MCP Tools: Cloud Logging (Traces & Diagnostics)
# ============================================================================

@mcp.tool()
def get_issue_logs(
    issue_id: Optional[str] = None,
    session_id: Optional[str] = None,
    min_severity: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Fetch Cloud Logging entries correlated with a specific issue or session ID.

    Searches across jsonPayload, labels, and textPayload for matching identifiers.
    Useful for inspecting scanner decisions, patch generation traces, verification output,
    and runtime exceptions for a specific finding.

    Args:
        issue_id: Finding ID or issue ID to correlate.
        session_id: Code Mender session or run ID to correlate.
        min_severity: Minimum log level (e.g. 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        start_time: Earliest timestamp in ISO format (e.g. '2026-09-10T00:00:00Z').
        end_time: Latest timestamp in ISO format.
        limit: Maximum log entries to retrieve (default: 50, max: 200).
    """
    return logging_service.get_issue_logs(
        issue_id=issue_id,
        session_id=session_id,
        min_severity=min_severity,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )


@mcp.tool()
def search_codemender_logs(
    query: Optional[str] = None,
    min_severity: Optional[str] = None,
    hours_ago: int = 24,
    resource_type: Optional[str] = None,
    log_name: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Search Cloud Logging for Code Mender logs, errors, or sandbox events.

    Args:
        query: Free text or field search expression (e.g. 'sandbox denial' or 'failed to compile').
        min_severity: Minimum log level ('DEFAULT', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        hours_ago: Number of hours in the past to search (default: 24).
        resource_type: Cloud resource type (e.g. 'cloud_run_job', 'cloud_run_revision').
        log_name: Specific log name or suffix filter.
        limit: Maximum log entries to return (default: 50, max: 200).
    """
    return logging_service.search_logs(
        query=query,
        min_severity=min_severity,
        hours_ago=hours_ago,
        resource_type=resource_type,
        log_name=log_name,
        limit=limit,
    )


# ============================================================================
# MCP Tools: Wiz (Cloud Security Issues)
# ============================================================================

@mcp.tool()
def list_wiz_issues(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    issue_type: Optional[str] = None,
    project_id: Optional[str] = None,
    search_query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    entity_id: Optional[str] = None,
    limit: int = 25,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List and filter security issues from Wiz, newest first.

    Args:
        severity: Comma-separated severities: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'.
        status: Comma-separated statuses: 'OPEN', 'IN_PROGRESS', 'RESOLVED', 'REJECTED'.
        issue_type: Comma-separated types: 'TOXIC_COMBINATION', 'THREAT_DETECTION', 'CLOUD_CONFIGURATION'.
        project_id: Comma-separated Wiz project IDs.
        search_query: Free-text search across issues.
        start_date: Issues created on or after this ISO timestamp (e.g. '2026-09-01T00:00:00Z').
        end_date: Issues created on or before this ISO timestamp.
        entity_id: Only issues related to this Wiz entity (resource) ID.
        limit: Max issues to return (default: 25, max: 200).
        cursor: Pagination cursor from a previous call's `next_cursor`.
    """
    return wiz_service.list_issues(
        severity=severity,
        status=status,
        issue_type=issue_type,
        project_id=project_id,
        search_query=search_query,
        start_date=start_date,
        end_date=end_date,
        entity_id=entity_id,
        limit=limit,
        cursor=cursor,
    )


@mcp.tool()
def get_wiz_issue_details(issue_id: str) -> Dict[str, Any]:
    """Retrieve full details for a single Wiz issue.

    Returns the source rule/control (with description and remediation guidance),
    the affected cloud resource, projects, linked service tickets, and notes.

    Args:
        issue_id: The Wiz issue ID.
    """
    return wiz_service.get_issue_details(issue_id=issue_id)


@mcp.tool()
def get_wiz_issues_summary(
    status: Optional[str] = "OPEN,IN_PROGRESS",
    project_id: Optional[str] = None,
    issue_type: Optional[str] = None,
    days: Optional[int] = None,
) -> Dict[str, Any]:
    """Get counts of Wiz issues broken down by severity.

    Args:
        status: Comma-separated statuses to include (default: 'OPEN,IN_PROGRESS').
        project_id: Optional comma-separated Wiz project IDs.
        issue_type: Optional comma-separated issue types.
        days: Optional lookback window in days (by creation date).
    """
    return wiz_service.get_issues_summary(
        status=status, project_id=project_id, issue_type=issue_type, days=days
    )


@mcp.tool()
def query_wiz_graphql(
    query: str,
    variables: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute a read-only GraphQL query against the Wiz API.

    Mutations and subscriptions are rejected. Use this for data the other Wiz
    tools don't cover (e.g. cloudResources, vulnerabilityFindings, projects).

    Args:
        query: GraphQL query document.
        variables: Optional GraphQL variables.
    """
    return wiz_service.execute_read_query(query=query, variables=variables)


# ============================================================================
# Lab tools: Wiz posture, code-to-cloud, security data, sandbox
# ============================================================================

@mcp.tool()
def wiz_top_internet_facing_vulnerabilities(
    environment: Optional[str] = "production",
    project: Optional[str] = None,
    severity: Optional[str] = "CRITICAL",
    limit: int = 5,
) -> Dict[str, Any]:
    """List the top open vulnerabilities on internet-exposed assets from Wiz (read-only).

    Results are ranked by severity, CISA KEV exploit, known exploit, then score.

    Args:
        environment: Asset environment: 'production', 'staging', 'development', 'testing', 'other'.
            Pass an empty string for all environments.
        project: Optional Wiz project ID.
        severity: Comma-separated severities (default 'CRITICAL').
        limit: Number of vulnerabilities to return (default 5, max 50).
    """
    return wiz_service.top_internet_facing_vulnerabilities(
        environment=environment, project=project, severity=severity, limit=limit
    )


@mcp.tool()
def wiz_excessive_permission_identities(
    service: Optional[str] = None,
    project: Optional[str] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    """List identities (service accounts and users) Wiz flags with admin or high privileges (read-only).

    Args:
        service: Optional substring of the identity name, e.g. 'payment-service'.
        project: Optional Wiz project ID (default: all projects).
        limit: Max identities to return (default 25, max 100).
    """
    return wiz_service.excessive_permission_identities(service=service, project=project, limit=limit)


@mcp.tool()
def trace_code_to_cloud(issue_id: Optional[str] = None, resource_id: Optional[str] = None) -> Dict[str, Any]:
    """Map a Wiz issue or cloud resource to its container image and source repository.

    Asks Wiz first (image digest, image labels such as org.opencontainers.image.source,
    repository fields). If Wiz is not configured, errors, or returns no repository, falls
    back to the BigQuery code_to_cloud_map table (and the Code Mender findings table to
    resolve an issue ID to a repository).

    Args:
        issue_id: Wiz issue ID (e.g. 'wiz-issue-0001') or Code Mender finding ID (e.g. 'CM-0003').
        resource_id: Wiz resource ID or cloud provider resource ID
            (e.g. '//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/services/payment-service').
    """
    if not issue_id and not resource_id:
        return {"error": "Provide issue_id or resource_id."}

    wiz_result = wiz_service.trace_code_to_cloud(issue_id=issue_id, resource_id=resource_id)
    if wiz_result.get("found"):
        return wiz_result

    wiz_status = wiz_result.get("error") or wiz_result.get("reason") or "Wiz returned no repository."
    lookup_resource = resource_id or (wiz_result.get("resource") or {}).get("provider_id")
    repository = None
    finding = None
    if issue_id and not resource_id:
        finding_res = security_data_service.get_finding_repository(issue_id)
        rows = finding_res.get("data") or []
        if rows:
            finding = rows[0]
            repository = finding.get("repository")
        elif finding_res.get("error") and not lookup_resource:
            return {"source": "bigquery", "found": False, "wiz_status": wiz_status, "error": finding_res["error"]}

    if not lookup_resource and not repository:
        return {
            "source": "bigquery",
            "found": False,
            "wiz_status": wiz_status,
            "finding": finding,
            "mappings": [],
            "message": "No resource or repository could be resolved for this issue.",
        }

    bq_result = security_data_service.get_code_to_cloud(resource_id=lookup_resource, repository=repository)
    if bq_result.get("error"):
        return {"source": "bigquery", "found": False, "wiz_status": wiz_status, "error": bq_result["error"]}
    mappings = bq_result.get("data") or []
    return {
        "source": "bigquery",
        "found": bool(mappings),
        "wiz_status": wiz_status,
        "issue_id": issue_id,
        "finding": finding,
        "filters_applied": bq_result.get("filters_applied"),
        "mappings": mappings,
    }


@mcp.tool()
def query_scc_findings(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    state: Optional[str] = "ACTIVE",
    project: Optional[str] = None,
    days: int = 7,
    limit: int = 25,
) -> Dict[str, Any]:
    """Query Security Command Center findings from the SCC BigQuery export (read-only).

    Returns the latest state of each finding.

    Args:
        severity: 'CRITICAL', 'HIGH', 'MEDIUM' or 'LOW'.
        category: SCC category, e.g. 'PUBLIC_BUCKET_ACL' or 'OPEN_FIREWALL'.
        state: 'ACTIVE' (default) or 'INACTIVE'. Pass an empty string for all.
        project: Project display name.
        days: Lookback window in days (default 7, max 90).
        limit: Max rows (default 25, max 200).
    """
    return security_data_service.query_scc_findings(
        severity=severity, category=category, state=state, project=project, days=days, limit=limit
    )


@mcp.tool()
def query_model_armor_logs(
    match_state: Optional[str] = None,
    filter_type: Optional[str] = None,
    days: int = 7,
    limit: int = 25,
) -> Dict[str, Any]:
    """Query Model Armor sanitize operation logs exported to BigQuery (read-only).

    Args:
        match_state: 'MATCH_FOUND' or 'NO_MATCH_FOUND'.
        filter_type: 'rai', 'pi_and_jailbreak', 'malicious_uris', 'sdp' or 'csam'.
        days: Lookback window in days (default 7, max 90).
        limit: Max rows (default 25, max 200).
    """
    return security_data_service.query_model_armor_logs(
        match_state=match_state, filter_type=filter_type, days=days, limit=limit
    )


@mcp.tool()
def query_vpcsc_violations(
    perimeter: Optional[str] = None,
    principal: Optional[str] = None,
    service: Optional[str] = None,
    days: int = 7,
    limit: int = 25,
) -> Dict[str, Any]:
    """Query VPC Service Controls violations from the Cloud Audit policy log in BigQuery (read-only).

    Args:
        perimeter: Perimeter name or substring of accessPolicies/<id>/servicePerimeters/<name>.
        principal: Caller email (user or service account).
        service: API service name, e.g. 'storage.googleapis.com'.
        days: Lookback window in days (default 7, max 90).
        limit: Max rows (default 25, max 200).
    """
    return security_data_service.query_vpcsc_violations(
        perimeter=perimeter, principal=principal, service=service, days=days, limit=limit
    )


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
    return security_data_service.query_security_events(
        event_type=event_type, severity=severity, issue_id=issue_id, days=days, limit=limit
    )


@mcp.tool()
def start_sandbox_validation(
    repository: str,
    commit_sha: str,
    patch_uri: str,
    issue_id: str,
    poc_test: str = "tests/poc",
    confirmed: bool = False,
) -> Dict[str, Any]:
    """ACTION TOOL: run the codemender-sandbox Cloud Run Job to validate a patch.

    This starts a job execution. The agent MUST show the user the repository, commit,
    patch URI and issue, and get explicit user confirmation before calling with
    confirmed=True. With confirmed=False (the default) nothing runs; the tool returns
    {"error": "confirmation_required", "planned_run": {...}}.

    The sandbox runs the PoC test before and after applying the patch, then the unit tests.
    Source is read from gs://<SANDBOX_BUCKET>/sources/<owner>__<name>/<commit_sha>.tar.gz.

    Args:
        repository: GitHub repository as owner/name, e.g. 'your-github-org/payment-service'.
        commit_sha: Git commit SHA (7-40 hex characters).
        patch_uri: gs://<SANDBOX_BUCKET>/patches/<issue_id>/<run_id>.diff, or 'none' to run without a patch.
        issue_id: Code Mender finding ID or Wiz issue ID, e.g. 'CM-0001'.
        poc_test: Relative path of the PoC tests in the repository (default 'tests/poc').
        confirmed: Must be True, after explicit user approval, to start the job.

    Returns run_id and execution_name on success.
    """
    return sandbox_service.start_validation(
        repository=repository,
        commit_sha=commit_sha,
        patch_uri=patch_uri,
        issue_id=issue_id,
        poc_test=poc_test,
        confirmed=confirmed,
    )


@mcp.tool()
def get_sandbox_result(run_id: Optional[str] = None, execution_name: Optional[str] = None) -> Dict[str, Any]:
    """Get the Cloud Run execution status and the sandbox_runs result row for a sandbox run.

    The verdict (PATCH_VERIFIED, PATCH_FAILED, POC_NOT_REPRODUCED, ERROR) appears once the
    log ingestion service has written the SANDBOX_RESULT row, usually a minute or two after
    the execution finishes.

    Args:
        run_id: run_id returned by start_sandbox_validation.
        execution_name: Cloud Run execution name (short name or full resource name).
    """
    if not run_id and not execution_name:
        return {"error": "Provide run_id or execution_name."}

    sandbox_run: Optional[Dict[str, Any]] = None
    notes = []
    if run_id:
        row_res = security_data_service.get_sandbox_run(run_id=run_id)
        if row_res.get("error"):
            notes.append(f"sandbox_runs lookup: {row_res['error']}")
        elif row_res.get("data"):
            sandbox_run = row_res["data"][0]

    exec_name = execution_name or (sandbox_run or {}).get("execution_name")
    if exec_name:
        execution = sandbox_service.get_execution(exec_name)
    elif run_id:
        execution = sandbox_service.find_execution_by_run_id(run_id)
    else:
        execution = {"error": "No execution name available."}

    if not exec_name and not execution.get("error"):
        exec_name = execution.get("execution_name")
    if sandbox_run is None and exec_name:
        row_res = security_data_service.get_sandbox_run(execution_name=exec_name)
        if row_res.get("error"):
            notes.append(f"sandbox_runs lookup: {row_res['error']}")
        elif row_res.get("data"):
            sandbox_run = row_res["data"][0]

    if sandbox_run is None:
        notes.append("No sandbox_runs row yet. If the execution finished, wait for log ingestion and retry.")

    return {
        "run_id": run_id or (sandbox_run or {}).get("run_id"),
        "execution_name": exec_name,
        "execution": execution,
        "sandbox_run": sandbox_run,
        "verdict": (sandbox_run or {}).get("verdict"),
        "notes": notes,
    }


# ============================================================================
# MCP Resources
# ============================================================================

@mcp.resource("codemender://schema")
def resource_schema() -> str:
    """BigQuery schema for the Code Mender findings table."""
    schema_info = bq_service.get_table_schema()
    return json.dumps(schema_info, indent=2)


@mcp.resource("codemender://critical-issues")
def resource_critical_issues() -> str:
    """Latest unresolved CRITICAL and HIGH severity issues from Code Mender."""
    issues = bq_service.list_issues(
        severity="CRITICAL",
        limit=10,
    )
    return json.dumps(issues, indent=2)


@mcp.resource("wiz://critical-issues")
def resource_wiz_critical_issues() -> str:
    """Latest open CRITICAL issues from Wiz."""
    issues = wiz_service.list_issues(
        severity="CRITICAL",
        status="OPEN,IN_PROGRESS",
        limit=10,
    )
    return json.dumps(issues, indent=2)


# ============================================================================
# MCP Prompts
# ============================================================================

@mcp.prompt()
def triage_issue(issue_id: str) -> str:
    """Prompt template for triaging a Code Mender security issue."""
    return (
        f"Please triage the Code Mender security issue '{issue_id}':\n"
        f"1. Call `get_issue_details(issue_id='{issue_id}')` to retrieve the vulnerability "
        f"information, file path, line number, and any generated patch.\n"
        f"2. Call `get_issue_logs(issue_id='{issue_id}')` to check for execution logs, "
        f"verification runs, or sandbox errors.\n"
        f"3. Analyze whether the patch resolves the vulnerability without introducing regressions.\n"
        f"4. Provide a concise summary with root cause, patch evaluation, and recommended next steps."
    )


@mcp.prompt()
def diagnose_remediation_failure(session_id: str) -> str:
    """Prompt template for diagnosing why Code Mender failed a patch or verification run."""
    return (
        f"Please diagnose the failed Code Mender run for session ID '{session_id}':\n"
        f"1. Call `get_issue_logs(session_id='{session_id}', min_severity='WARNING')` "
        f"to inspect errors, compiler messages, or sandbox denials.\n"
        f"2. Call `list_codemender_issues(session_id='{session_id}')` to see the status "
        f"of findings associated with this run.\n"
        f"3. Identify why the remediation could not be completed (e.g. syntax error, "
        f"failing test, timeout, or security sandbox constraint).\n"
        f"4. Recommend how to fix the issue or adjust the Code Mender configuration."
    )


@mcp.prompt()
def triage_wiz_issue(issue_id: str) -> str:
    """Prompt template for triaging a Wiz cloud security issue."""
    return (
        f"Please triage the Wiz issue '{issue_id}':\n"
        f"1. Call `get_wiz_issue_details(issue_id='{issue_id}')` to retrieve the source rule, "
        f"affected resource, projects, and remediation guidance.\n"
        f"2. If the affected resource maps to a code repository, call `list_codemender_issues` "
        f"with that repository to check for related Code Mender findings or patches.\n"
        f"3. Assess exposure and impact based on the resource type, cloud platform, and severity.\n"
        f"4. Provide a concise summary with root cause, risk, and recommended remediation steps."
    )


@mcp.prompt()
def remediate_wiz_issue(issue_id: str) -> str:
    """Prompt template for taking a Wiz issue from triage to a validated patch and PR."""
    return (
        f"Remediate the Wiz issue '{issue_id}':\n"
        f"1. Call `get_wiz_issue_details(issue_id='{issue_id}')` to get the rule, affected resource and severity.\n"
        f"2. Call `trace_code_to_cloud(issue_id='{issue_id}')` to find the container image and source repository.\n"
        f"3. Call `list_codemender_issues(repository=<repository>)` and `get_issue_details` to find the "
        f"matching Code Mender finding and its patch. Note the finding ID and commit SHA.\n"
        f"4. Explain the root cause and the proposed patch to the user.\n"
        f"5. Call `start_sandbox_validation` with confirmed=False to show the planned run. Ask the user "
        f"for explicit approval. Only after the user approves, call it again with confirmed=True.\n"
        f"6. Call `get_sandbox_result(run_id=<run_id>)` until a verdict is available. Report poc_before, "
        f"poc_after, unit test results and the verdict.\n"
        f"7. If the verdict is PATCH_VERIFIED, offer to open a pull request with the patch, the sandbox "
        f"verdict and a link to the Wiz issue. Ask before creating it. Never merge; a human reviewer approves the PR."
    )


# Disable DNS rebinding protection so Cloud Run hostnames (*.run.app) and internal proxies are allowed
mcp.settings.transport_security.enable_dns_rebinding_protection = False


# ============================================================================
# Cloud Run HTTP Custom Endpoints (Health Check & Info)
# ============================================================================

async def health_check(request: Request) -> Response:
    """Health check endpoint for Cloud Run startup and liveness probes."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": "codemender-mcp-server",
            "project": bq_service.project_id or "auto-detected",
            "dataset": bq_service.dataset,
            "table": bq_service.table,
            "wiz_configured": wiz_service.is_configured,
        }
    )


async def root_info(request: Request) -> Response:
    """Root info endpoint."""
    return JSONResponse(
        {
            "service": "Code Mender MCP Server",
            "description": "Model Context Protocol server for Code Mender, Wiz, Cloud Logging, BigQuery security data and the sandbox Cloud Run Job.",
            "mcp_streamable_endpoint": "/mcp",
            "mcp_sse_endpoint": "/sse",
            "mcp_messages_endpoint": "/messages",
            "healthz_endpoint": "/healthz",
            "tools": [
                "list_codemender_issues",
                "get_issue_details",
                "get_issues_summary",
                "get_bigquery_schema",
                "query_codemender_bigquery",
                "get_issue_logs",
                "search_codemender_logs",
                "list_wiz_issues",
                "get_wiz_issue_details",
                "get_wiz_issues_summary",
                "query_wiz_graphql",
                "wiz_top_internet_facing_vulnerabilities",
                "wiz_excessive_permission_identities",
                "trace_code_to_cloud",
                "query_scc_findings",
                "query_model_armor_logs",
                "query_vpcsc_violations",
                "query_security_events",
                "start_sandbox_validation",
                "get_sandbox_result",
            ],
            "prompts": [
                "triage_issue",
                "diagnose_remediation_failure",
                "triage_wiz_issue",
                "remediate_wiz_issue",
            ],
        }
    )


# ============================================================================
# Multi-Transport ASGI Application Setup (Streamable HTTP + SSE)
# ============================================================================

from starlette.types import Scope, Receive, Send
from starlette.routing import Route
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware


class MCPCompatibilityMiddleware:
    """Ensures complete compatibility with Gemini Enterprise, browsers, and MCP clients:
    1. Responds to CORS preflight OPTIONS requests with 204 No Content.
    2. Handles DELETE requests (explicit session termination) with 200 OK.
    3. Handles HEAD requests with 200 OK.
    4. Normalizes Accept headers to satisfy FastMCP Streamable HTTP requirements
       ('application/json, text/event-stream').
    """
    def __init__(self, inner_app):
        self.inner_app = inner_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            method = scope.get("method", "")

            # Handle CORS preflight OPTIONS requests cleanly without hitting FastMCP 405
            if method == "OPTIONS":
                response = Response(
                    status_code=204,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS, HEAD",
                        "Access-Control-Allow-Headers": "*",
                    },
                )
                await response(scope, receive, send)
                return

            # Handle explicit session termination DELETE requests gracefully
            if method == "DELETE":
                response = JSONResponse(
                    {"status": "session terminated"},
                    status_code=200,
                    headers={"Access-Control-Allow-Origin": "*"},
                )
                await response(scope, receive, send)
                return

            # Handle HEAD probes gracefully
            if method == "HEAD":
                response = Response(status_code=200, headers={"Access-Control-Allow-Origin": "*"})
                await response(scope, receive, send)
                return

            # Normalize Accept header so clients sending */* or application/json do not receive 406
            headers = dict(scope.get("headers", []))
            accept = headers.get(b"accept", b"").decode("utf-8", "ignore")
            if not ("application/json" in accept and "text/event-stream" in accept):
                new_headers = [(k, v) for k, v in scope.get("headers", []) if k != b"accept"]
                new_headers.append((b"accept", b"application/json, text/event-stream"))
                scope["headers"] = new_headers

        await self.inner_app(scope, receive, send)


def create_app() -> Any:
    """Build a unified Starlette application supporting:
    1. /mcp: Streamable HTTP (POST, GET) - used by Gemini Enterprise & Agent Gateway.
    2. /: Root endpoint (GET for info, POST routed to MCP Streamable HTTP).
    3. /sse: SSE endpoint (GET for SSE stream, POST routed to MCP Streamable HTTP).
    4. /messages: SSE message transport (POST).
    5. /healthz: Cloud Run health checks (GET).
    """
    http_app = mcp.streamable_http_app()
    sse_app = mcp.sse_app()
    streamable_mcp_handler = http_app.routes[0].endpoint

    routes = [
        # Health check
        Route("/healthz", health_check, methods=["GET"]),
        # Streamable HTTP (/mcp) for Gemini Enterprise / Discovery Engine
        http_app.routes[0],
        # SSE endpoints (/sse GET and /messages POST) for Claude / Cursor
        sse_app.routes[0],
        sse_app.routes[1],
        # Root endpoint (GET for service info, POST routed to MCP handler)
        Route("/", root_info, methods=["GET"]),
        Route("/", endpoint=streamable_mcp_handler, methods=["POST"]),
        # Fallback: if a client POSTs to /sse, handle it with Streamable HTTP instead of 405
        Route("/sse", endpoint=streamable_mcp_handler, methods=["POST"]),
    ]

    base_app = Starlette(
        routes=routes,
        lifespan=lambda app: mcp.session_manager.run(),
    )
    # Layer CORS and compatibility middleware
    cors_app = CORSMiddleware(
        base_app,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return MCPCompatibilityMiddleware(cors_app)


# Export ASGI application for Uvicorn
app = create_app()

if __name__ == "__main__":
    logger.info("Starting Code Mender MCP Server on %s:%d", settings.host, settings.port)
    uvicorn.run(
        "server:app",
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
