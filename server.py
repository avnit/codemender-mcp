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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("codemender-mcp-server")

# Initialize services
bq_service = BigQueryService()
logging_service = LoggingService()

# Initialize FastMCP Server (stateless_http=True for serverless Cloud Run & Gemini Enterprise)
mcp = FastMCP(
    name="Code Mender Security MCP Server",
    instructions=(
        "You have access to Google Cloud BigQuery and Cloud Logging tools to search, "
        "inspect, and triage security findings and automated remediation jobs generated "
        "by Code Mender. Use these tools to find issues, review generated patches, inspect "
        "sandbox/execution logs, and diagnose remediation failures."
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
        }
    )


async def root_info(request: Request) -> Response:
    """Root info endpoint."""
    return JSONResponse(
        {
            "service": "Code Mender MCP Server",
            "description": "Model Context Protocol server for Code Mender BigQuery and Cloud Logging data.",
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
