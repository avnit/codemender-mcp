import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"}
VALID_TYPES = {"TOXIC_COMBINATION", "THREAT_DETECTION", "CLOUD_CONFIGURATION"}

ISSUE_FIELDS = """
  id
  type
  status
  severity
  createdAt
  updatedAt
  resolvedAt
  dueAt
  statusChangedAt
  sourceRule {
    __typename
    ... on Control {
      id
      name
      controlDescription: description
      resolutionRecommendation
    }
    ... on CloudEventRule {
      id
      name
      cloudEventRuleDescription: description
    }
    ... on CloudConfigurationRule {
      id
      name
      cloudConfigurationRuleDescription: description
      remediationInstructions
    }
  }
  entitySnapshot {
    id
    type
    nativeType
    name
    status
    cloudPlatform
    providerId
    region
    resourceGroupExternalId
    subscriptionExternalId
    subscriptionName
    externalId
  }
  projects {
    id
    name
  }
  serviceTickets {
    externalId
    name
    url
  }
"""

LIST_ISSUES_QUERY = (
    """
query ListWizIssues($filterBy: IssueFilters, $first: Int, $after: String, $orderBy: IssueOrder) {
  issuesV2(filterBy: $filterBy, first: $first, after: $after, orderBy: $orderBy) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
"""
    + ISSUE_FIELDS
    + """
    }
  }
}
"""
)

ISSUE_DETAILS_QUERY = (
    """
query GetWizIssue($filterBy: IssueFilters) {
  issuesV2(filterBy: $filterBy, first: 1) {
    nodes {
"""
    + ISSUE_FIELDS
    + """
      notes {
        createdAt
        updatedAt
        text
        user {
          name
          email
        }
        serviceAccount {
          name
        }
      }
    }
  }
}
"""
)

SUMMARY_QUERY = """
query WizIssuesSummary($base: IssueFilters, $critical: IssueFilters, $high: IssueFilters,
                       $medium: IssueFilters, $low: IssueFilters, $info: IssueFilters) {
  total: issuesV2(filterBy: $base, first: 1) { totalCount }
  critical: issuesV2(filterBy: $critical, first: 1) { totalCount }
  high: issuesV2(filterBy: $high, first: 1) { totalCount }
  medium: issuesV2(filterBy: $medium, first: 1) { totalCount }
  low: issuesV2(filterBy: $low, first: 1) { totalCount }
  informational: issuesV2(filterBy: $info, first: 1) { totalCount }
}
"""


def _split_csv(value: Optional[str]) -> List[str]:
    """Turn 'HIGH, critical' into ['HIGH', 'CRITICAL']."""
    if not value:
        return []
    return [v.strip().upper() for v in value.split(",") if v.strip()]


class WizService:
    """Client for the Wiz GraphQL API (read-only access to Wiz Issues).

    Authenticates with a Wiz service account using the OAuth 2.0 client
    credentials flow and caches the access token until shortly before expiry.
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        auth_url: Optional[str] = None,
        audience: Optional[str] = None,
        timeout: float = 30.0,
        http_client: Optional[httpx.Client] = None,
    ):
        self.client_id = client_id or settings.wiz_client_id
        self.client_secret = client_secret or settings.wiz_client_secret
        self.api_endpoint = api_endpoint or settings.wiz_api_endpoint
        self.auth_url = auth_url or settings.wiz_auth_url
        self.audience = audience or settings.wiz_audience
        self._http = http_client or httpx.Client(timeout=timeout)
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Auth & transport
    # ------------------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.api_endpoint)

    def _not_configured_error(self) -> Dict[str, Any]:
        return {
            "error": (
                "Wiz integration is not configured. Set WIZ_CLIENT_ID, "
                "WIZ_CLIENT_SECRET and WIZ_API_ENDPOINT "
                "(e.g. https://api.us17.app.wiz.io/graphql)."
            )
        }

    def _get_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._token_expiry - 60:
                return self._token

            resp = self._http.post(
                self.auth_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": self.audience,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            body = resp.json()
            token = body.get("access_token")
            if not token:
                raise RuntimeError("Wiz auth response did not include an access_token.")
            self._token = token
            self._token_expiry = time.time() + int(body.get("expires_in", 3600))
            return token

    def _graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run a GraphQL request and return the `data` object.

        Raises RuntimeError on GraphQL errors and httpx errors on transport failures.
        Retries once with a fresh token on HTTP 401.
        """
        payload = {"query": query, "variables": variables or {}}
        for attempt in range(2):
            token = self._get_token()
            resp = self._http.post(
                self.api_endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code == 401 and attempt == 0:
                with self._lock:
                    self._token = None
                continue
            resp.raise_for_status()
            body = resp.json()
            if body.get("errors"):
                messages = "; ".join(e.get("message", str(e)) for e in body["errors"])
                raise RuntimeError(f"Wiz GraphQL error: {messages}")
            return body.get("data") or {}
        raise RuntimeError("Wiz API rejected the access token (HTTP 401).")

    def _run(self, fn, *args, **kwargs) -> Dict[str, Any]:
        """Wrap a call with config checks and uniform error handling."""
        if not self.is_configured:
            return self._not_configured_error()
        try:
            return fn(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            logger.exception("Wiz API HTTP error: %s", e)
            return {"error": f"Wiz API HTTP {e.response.status_code}: {e.response.text[:500]}"}
        except httpx.HTTPError as e:
            logger.exception("Wiz API transport error: %s", e)
            return {"error": f"Wiz API request failed: {e}"}
        except Exception as e:
            logger.exception("Wiz API error: %s", e)
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    @staticmethod
    def build_issue_filters(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        issue_type: Optional[str] = None,
        project_id: Optional[str] = None,
        search_query: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        entity_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a Wiz `IssueFilters` input object. Raises ValueError on bad enums."""
        filters: Dict[str, Any] = {}

        severities = _split_csv(severity)
        bad = [s for s in severities if s not in VALID_SEVERITIES]
        if bad:
            raise ValueError(f"Invalid severity {bad}. Allowed: {sorted(VALID_SEVERITIES)}")
        if severities:
            filters["severity"] = severities

        statuses = _split_csv(status)
        bad = [s for s in statuses if s not in VALID_STATUSES]
        if bad:
            raise ValueError(f"Invalid status {bad}. Allowed: {sorted(VALID_STATUSES)}")
        if statuses:
            filters["status"] = statuses

        types = _split_csv(issue_type)
        bad = [t for t in types if t not in VALID_TYPES]
        if bad:
            raise ValueError(f"Invalid issue_type {bad}. Allowed: {sorted(VALID_TYPES)}")
        if types:
            filters["type"] = types

        if project_id:
            filters["project"] = [p.strip() for p in project_id.split(",") if p.strip()]
        if search_query:
            filters["search"] = search_query
        if entity_id:
            filters["relatedEntity"] = {"id": entity_id}

        created_at: Dict[str, str] = {}
        if start_date:
            created_at["after"] = start_date
        if end_date:
            created_at["before"] = end_date
        if created_at:
            filters["createdAt"] = created_at

        return filters

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    def list_issues(
        self,
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
        def _do() -> Dict[str, Any]:
            try:
                filters = self.build_issue_filters(
                    severity=severity,
                    status=status,
                    issue_type=issue_type,
                    project_id=project_id,
                    search_query=search_query,
                    start_date=start_date,
                    end_date=end_date,
                    entity_id=entity_id,
                )
            except ValueError as ve:
                return {"error": str(ve)}

            first = max(1, min(int(limit or settings.default_query_limit), settings.max_query_limit))
            variables: Dict[str, Any] = {
                "filterBy": filters,
                "first": first,
                "orderBy": {"direction": "DESC", "field": "CREATED_AT"},
            }
            if cursor:
                variables["after"] = cursor

            data = self._graphql(LIST_ISSUES_QUERY, variables)
            result = data.get("issuesV2") or {}
            page_info = result.get("pageInfo") or {}
            nodes = result.get("nodes") or []
            return {
                "source": "wiz",
                "total_issues": result.get("totalCount", len(nodes)),
                "returned": len(nodes),
                "has_next_page": page_info.get("hasNextPage", False),
                "next_cursor": page_info.get("endCursor"),
                "filters_applied": filters,
                "issues": nodes,
            }

        return self._run(_do)

    def get_issue_details(self, issue_id: str) -> Dict[str, Any]:
        def _do() -> Dict[str, Any]:
            if not issue_id:
                return {"error": "issue_id is required."}
            data = self._graphql(ISSUE_DETAILS_QUERY, {"filterBy": {"id": [issue_id]}})
            nodes = (data.get("issuesV2") or {}).get("nodes") or []
            if not nodes:
                return {"error": f"Wiz issue '{issue_id}' not found."}
            return {"source": "wiz", "issue": nodes[0]}

        return self._run(_do)

    def get_issues_summary(
        self,
        status: Optional[str] = "OPEN,IN_PROGRESS",
        project_id: Optional[str] = None,
        issue_type: Optional[str] = None,
        days: Optional[int] = None,
    ) -> Dict[str, Any]:
        def _do() -> Dict[str, Any]:
            start_date = None
            if days:
                start_date = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - int(days) * 86400)
                )
            try:
                base = self.build_issue_filters(
                    status=status,
                    project_id=project_id,
                    issue_type=issue_type,
                    start_date=start_date,
                )
            except ValueError as ve:
                return {"error": str(ve)}

            def with_sev(sev: str) -> Dict[str, Any]:
                return {**base, "severity": [sev]}

            data = self._graphql(
                SUMMARY_QUERY,
                {
                    "base": base,
                    "critical": with_sev("CRITICAL"),
                    "high": with_sev("HIGH"),
                    "medium": with_sev("MEDIUM"),
                    "low": with_sev("LOW"),
                    "info": with_sev("INFORMATIONAL"),
                },
            )

            def count(key: str) -> int:
                return (data.get(key) or {}).get("totalCount", 0)

            return {
                "source": "wiz",
                "filters_applied": base,
                "total_issues": count("total"),
                "severity_breakdown": {
                    "CRITICAL": count("critical"),
                    "HIGH": count("high"),
                    "MEDIUM": count("medium"),
                    "LOW": count("low"),
                    "INFORMATIONAL": count("informational"),
                },
            }

        return self._run(_do)

    def execute_read_query(
        self, query: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run an arbitrary read-only GraphQL query. Mutations and subscriptions are rejected."""

        def _do() -> Dict[str, Any]:
            if not query or not query.strip():
                return {"error": "query is required."}
            # Strip comments and string literals before checking the operation type.
            stripped = re.sub(r"#.*", "", query)
            stripped = re.sub(r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"', '""', stripped)
            if re.search(r"\b(mutation|subscription)\b", stripped, re.IGNORECASE):
                return {"error": "Only read-only GraphQL queries are permitted (no mutations or subscriptions)."}
            data = self._graphql(query, variables or {})
            return {"source": "wiz", "data": data}

        return self._run(_do)
