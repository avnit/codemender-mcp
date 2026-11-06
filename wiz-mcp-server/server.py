import json
import logging
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send
import uvicorn

from config import settings
from services.wiz_service import WizService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wiz-mcp-server")

# Initialize service
wiz_service = WizService()

# Initialize FastMCP Server (stateless_http=True for serverless Cloud Run & Gemini Enterprise)
mcp = FastMCP(
    name="Wiz Security MCP Server",
    instructions=(
        "You have read-only access to Wiz cloud security posture data via the Wiz GraphQL API. "
        "Use these tools to list and inspect Wiz issues (toxic combinations, threat detections, "
        "and cloud configuration findings), rank top internet-facing vulnerabilities "
        "(wiz_top_internet_facing_vulnerabilities), audit identities with admin or high privileges "
        "(wiz_excessive_permission_identities), trace a Wiz issue or cloud resource back to its "
        "container image digest and source repository (wiz_trace_code_to_cloud), or run custom "
        "read-only Wiz GraphQL queries (query_wiz_graphql). All tools are strictly read-only; "
        "GraphQL mutations and subscriptions are rejected."
    ),
    stateless_http=True,
)


# ============================================================================
# MCP Tools: Wiz (Cloud Security Issues, Posture & Code-to-Cloud)
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
    return wiz_service.excessive_permission_identities(
        service=service, project=project, limit=limit
    )


@mcp.tool()
def wiz_trace_code_to_cloud(
    issue_id: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Map a Wiz issue or cloud resource to its container image digest and source repository via Wiz.

    Queries Wiz for the affected resource's graph entity properties (imageDigest, OCI
    org.opencontainers.image.source label, and repository fields). If Wiz returns found=False
    or is not configured, use trace_code_to_cloud on the CodeMender MCP server to query the
    BigQuery code_to_cloud_map table.

    Args:
        issue_id: Wiz issue ID (e.g. 'wiz-issue-0001').
        resource_id: Wiz resource ID or cloud provider resource ID
            (e.g. '//run.googleapis.com/projects/your-gcp-project-id/locations/us-central1/services/payment-service').
    """
    return wiz_service.trace_code_to_cloud(issue_id=issue_id, resource_id=resource_id)


# ============================================================================
# MCP Resources
# ============================================================================

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
def triage_wiz_issue(issue_id: str) -> str:
    """Prompt template for triaging a Wiz cloud security issue."""
    return (
        f"Please triage the Wiz issue '{issue_id}':\n"
        f"1. Call `get_wiz_issue_details(issue_id='{issue_id}')` to retrieve the source rule, "
        f"affected resource, projects, and remediation guidance.\n"
        f"2. Call `wiz_trace_code_to_cloud(issue_id='{issue_id}')` (and if needed, `trace_code_to_cloud` "
        f"on the Code Mender MCP server) to resolve the container image and source repository.\n"
        f"3. If the affected resource maps to a code repository, call `list_codemender_issues` "
        f"with that repository to check for related Code Mender findings or patches.\n"
        f"4. Assess exposure and impact based on the resource type, cloud platform, and severity.\n"
        f"5. Provide a concise summary with root cause, risk, and recommended remediation steps."
    )


@mcp.prompt()
def remediate_wiz_issue(issue_id: str) -> str:
    """Prompt template for taking a Wiz issue from triage to a validated patch and PR."""
    return (
        f"Remediate the Wiz issue '{issue_id}':\n"
        f"1. Call `get_wiz_issue_details(issue_id='{issue_id}')` to get the rule, affected resource and severity.\n"
        f"2. Call `wiz_trace_code_to_cloud(issue_id='{issue_id}')` (falling back to `trace_code_to_cloud(issue_id='{issue_id}')` "
        f"on the Code Mender MCP server if needed) to find the container image and source repository.\n"
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
            "service": "wiz-mcp-server",
            "project": settings.gcp_project_id or "auto-detected",
            "wiz_configured": wiz_service.is_configured,
        }
    )


async def root_info(request: Request) -> Response:
    """Root info endpoint."""
    return JSONResponse(
        {
            "service": "Wiz Security MCP Server",
            "description": "Dedicated Model Context Protocol server on Cloud Run for Wiz cloud security issues, vulnerabilities, identity posture, and code-to-cloud attribution.",
            "mcp_streamable_endpoint": "/mcp",
            "mcp_sse_endpoint": "/sse",
            "mcp_messages_endpoint": "/messages",
            "healthz_endpoint": "/healthz",
            "tools": [
                "list_wiz_issues",
                "get_wiz_issue_details",
                "get_wiz_issues_summary",
                "query_wiz_graphql",
                "wiz_top_internet_facing_vulnerabilities",
                "wiz_excessive_permission_identities",
                "wiz_trace_code_to_cloud",
            ],
            "prompts": [
                "triage_wiz_issue",
                "remediate_wiz_issue",
            ],
        }
    )


# ============================================================================
# Multi-Transport ASGI Application Setup (Streamable HTTP + SSE)
# ============================================================================

_SECURITY_HEADERS = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store"),
)


class MCPCompatibilityMiddleware:
    """Ensures complete compatibility with Gemini Enterprise, browsers, and MCP clients:
    1. Responds to CORS preflight OPTIONS requests with 204 No Content.
    2. Handles DELETE requests (explicit session termination) with 200 OK.
    3. Handles HEAD requests with 200 OK.
    4. Normalizes Accept headers to satisfy FastMCP Streamable HTTP requirements
       ('application/json, text/event-stream').
    5. Adds baseline HTTP security headers (nosniff, frame-ancestors/DENY, no-store).
    """

    def __init__(self, inner_app):
        self.inner_app = inner_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k, v) for k, v in _SECURITY_HEADERS if k not in existing]
                if extra:
                    message = {**message, "headers": list(message.get("headers", [])) + extra}
            await send(message)

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
                await response(scope, receive, send_with_security_headers)
                return

            # Handle explicit session termination DELETE requests gracefully
            if method == "DELETE":
                response = JSONResponse(
                    {"status": "session terminated"},
                    status_code=200,
                    headers={"Access-Control-Allow-Origin": "*"},
                )
                await response(scope, receive, send_with_security_headers)
                return

            # Handle HEAD probes gracefully
            if method == "HEAD":
                response = Response(status_code=200, headers={"Access-Control-Allow-Origin": "*"})
                await response(scope, receive, send_with_security_headers)
                return

            # Normalize Accept header so clients sending */* or application/json do not receive 406
            headers = dict(scope.get("headers", []))
            accept = headers.get(b"accept", b"").decode("utf-8", "ignore")
            if not ("application/json" in accept and "text/event-stream" in accept):
                new_headers = [(k, v) for k, v in scope.get("headers", []) if k != b"accept"]
                new_headers.append((b"accept", b"application/json, text/event-stream"))
                scope["headers"] = new_headers

        await self.inner_app(scope, receive, send_with_security_headers)


def create_app() -> Any:
    """Build a unified Starlette application supporting:
    1. /mcp: Streamable HTTP (POST, GET) - used by Gemini Enterprise & Agent Engine.
    2. /: Root endpoint (GET for info, POST routed to MCP Streamable HTTP).
    3. /sse: SSE endpoint (GET for SSE stream, POST routed to MCP Streamable HTTP).
    4. /messages: SSE message transport (POST).
    5. /healthz: Cloud Run health checks (GET).
    """
    http_app = mcp.streamable_http_app()
    sse_app = mcp.sse_app()
    streamable_mcp_handler = http_app.routes[0].endpoint

    routes = [
        Route("/healthz", health_check, methods=["GET"]),
        http_app.routes[0],
        sse_app.routes[0],
        sse_app.routes[1],
        Route("/", root_info, methods=["GET"]),
        Route("/", endpoint=streamable_mcp_handler, methods=["POST"]),
        Route("/sse", endpoint=streamable_mcp_handler, methods=["POST"]),
    ]

    base_app = Starlette(
        routes=routes,
        lifespan=lambda app: mcp.session_manager.run(),
    )
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
    logger.info("Starting Wiz Security MCP Server on %s:%d", settings.host, settings.port)
    uvicorn.run(
        "server:app",
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
