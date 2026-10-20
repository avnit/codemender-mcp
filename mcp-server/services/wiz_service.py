import json
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


# ----------------------------------------------------------------------
# Queries used by the lab tools (vulnerabilities, identities, code-to-cloud).
# Fields marked "verify against your tenant's schema" are not confirmed for
# every Wiz tenant/API version. Check them in the Wiz GraphQL explorer
# (Wiz portal > Settings > API / GraphQL explorer) and remove any that fail.
# ----------------------------------------------------------------------

VALID_ENVIRONMENTS = {"PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING", "OTHER"}
WIZ_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
WIZ_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9._:/@\-]{1,512}$")
SERVICE_FILTER_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,128}$")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0, "NONE": 0}
MAX_VULN_LIMIT = 50
MAX_IDENTITY_LIMIT = 100

TOP_VULNS_QUERY = """
query TopInternetFacingVulnerabilities($filterBy: VulnerabilityFindingFilters, $first: Int) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first) {
    totalCount
    nodes {
      id
      portalUrl
      name
      detailedName
      severity                  # verify against your tenant's schema
      vendorSeverity            # verify against your tenant's schema
      score
      exploitabilityScore       # verify against your tenant's schema
      hasExploit                # verify against your tenant's schema
      hasCisaKevExploit         # verify against your tenant's schema
      status
      version
      fixedVersion
      remediation
      firstDetectedAt
      lastDetectedAt
      projects {                # verify against your tenant's schema
        id
        name
      }
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          type
          name
          region
          providerUniqueId
          cloudPlatform
          subscriptionExternalId
          subscriptionName
          tags                          # verify against your tenant's schema
          hasLimitedInternetExposure    # verify against your tenant's schema
          hasWideInternetExposure       # verify against your tenant's schema
        }
        ... on VulnerableAssetContainerImage {
          imageId                       # verify against your tenant's schema
        }
      }
    }
  }
}
"""

EXCESSIVE_IDENTITIES_QUERY = """
query ExcessivePermissionIdentities($adminQuery: GraphEntityQueryInput, $highQuery: GraphEntityQueryInput,
                                    $projectId: String!, $first: Int) {
  admin: graphSearch(query: $adminQuery, projectId: $projectId, first: $first) {
    totalCount
    nodes {
      entities {
        id
        name
        type
        properties    # JSON; keys hasAdminPrivileges / hasHighPrivileges: verify against your tenant's schema
      }
    }
  }
  high: graphSearch(query: $highQuery, projectId: $projectId, first: $first) {
    totalCount
    nodes {
      entities {
        id
        name
        type
        properties
      }
    }
  }
}
"""

ISSUE_ENTITY_QUERY = """
query IssueEntity($filterBy: IssueFilters) {
  issuesV2(filterBy: $filterBy, first: 1) {
    nodes {
      id
      severity
      entitySnapshot {
        id
        type
        nativeType
        name
        providerId
        externalId
        cloudPlatform
      }
    }
  }
}
"""

CODE_TO_CLOUD_QUERY = """
query CodeToCloud($filterBy: CloudResourceFilters, $first: Int) {
  cloudResources(filterBy: $filterBy, first: $first) {     # verify against your tenant's schema
    nodes {
      id
      name
      type
      providerId                # verify against your tenant's schema
      graphEntity {             # verify against your tenant's schema
        id
        type
        properties              # JSON; image digest, imageLabels, repository keys: verify against your tenant's schema
      }
    }
  }
}
"""

# Keys read from graphEntity.properties (all: verify against your tenant's schema).
IMAGE_DIGEST_KEYS = ("imageDigest", "digest", "imageId")
IMAGE_LABEL_KEYS = ("imageLabels", "labels")
REPOSITORY_KEYS = ("codeRepository", "repository", "repositoryUrl", "sourceRepository")
OCI_SOURCE_LABEL = "org.opencontainers.image.source"


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

    # ------------------------------------------------------------------
    # Lab tools: internet-facing vulnerabilities
    # ------------------------------------------------------------------

    @staticmethod
    def build_vulnerability_variables(
        environment: Optional[str] = "production",
        project: Optional[str] = None,
        severity: Optional[str] = "CRITICAL",
        limit: int = 5,
    ) -> Dict[str, Any]:
        """Build variables for TOP_VULNS_QUERY. Raises ValueError on bad input.

        filterBy keys vendorSeverity, status, hasWideInternetExposure, projectId and
        environment: verify against your tenant's schema.
        """
        severities = _split_csv(severity) or ["CRITICAL"]
        bad = [s for s in severities if s not in VALID_SEVERITIES]
        if bad:
            raise ValueError(f"Invalid severity: {bad}. Use {sorted(VALID_SEVERITIES)}.")
        try:
            limit_int = int(limit if limit is not None else 5)
        except (TypeError, ValueError):
            raise ValueError("limit must be an integer.")
        limit_int = max(1, min(limit_int, MAX_VULN_LIMIT))

        filter_by: Dict[str, Any] = {
            "vendorSeverity": severities,        # verify against your tenant's schema
            "status": ["OPEN"],
            "hasWideInternetExposure": True,     # verify against your tenant's schema
        }
        if environment:
            env = environment.strip().upper()
            if env not in VALID_ENVIRONMENTS:
                raise ValueError(f"Invalid environment '{environment}'. Use {sorted(VALID_ENVIRONMENTS)}.")
            filter_by["environment"] = [env]     # verify against your tenant's schema
        if project:
            if not WIZ_ID_RE.match(project):
                raise ValueError("Invalid project. Use a Wiz project ID.")
            filter_by["projectId"] = [project]   # verify against your tenant's schema

        # Fetch extra rows so client-side ranking (exploit, KEV, score) has room to work.
        return {"filterBy": filter_by, "first": min(limit_int * 4, 100), "_limit": limit_int}

    @staticmethod
    def _flatten_vulnerability(node: Dict[str, Any]) -> Dict[str, Any]:
        asset = node.get("vulnerableAsset") or {}
        wide = asset.get("hasWideInternetExposure")
        limited = asset.get("hasLimitedInternetExposure")
        exposure = "wide" if wide else ("limited" if limited else ("none" if wide is False else "unknown"))
        return {
            "id": node.get("id"),
            "cve": node.get("name"),
            "detailed_name": node.get("detailedName"),
            "severity": node.get("vendorSeverity") or node.get("severity"),
            "score": node.get("score"),
            "exploitability_score": node.get("exploitabilityScore"),
            "has_exploit": node.get("hasExploit"),
            "has_cisa_kev_exploit": node.get("hasCisaKevExploit"),
            "status": node.get("status"),
            "version": node.get("version"),
            "fixed_version": node.get("fixedVersion"),
            "remediation": node.get("remediation"),
            "first_detected_at": node.get("firstDetectedAt"),
            "last_detected_at": node.get("lastDetectedAt"),
            "portal_url": node.get("portalUrl"),
            "projects": [p.get("name") for p in (node.get("projects") or []) if isinstance(p, dict)],
            "asset": {
                "id": asset.get("id"),
                "name": asset.get("name"),
                "type": asset.get("type"),
                "cloud_platform": asset.get("cloudPlatform"),
                "provider_unique_id": asset.get("providerUniqueId"),
                "region": asset.get("region"),
                "subscription": asset.get("subscriptionName") or asset.get("subscriptionExternalId"),
                "image_id": asset.get("imageId"),
                "internet_exposure": exposure,
            },
        }

    @staticmethod
    def _vuln_sort_key(v: Dict[str, Any]):
        return (
            SEVERITY_RANK.get(str(v.get("severity") or "").upper(), 0),
            1 if v.get("has_cisa_kev_exploit") else 0,
            1 if v.get("has_exploit") else 0,
            float(v.get("score") or 0),
        )

    def top_internet_facing_vulnerabilities(
        self,
        environment: Optional[str] = "production",
        project: Optional[str] = None,
        severity: Optional[str] = "CRITICAL",
        limit: int = 5,
    ) -> Dict[str, Any]:
        def _do() -> Dict[str, Any]:
            try:
                variables = self.build_vulnerability_variables(environment, project, severity, limit)
            except ValueError as ve:
                return {"error": str(ve)}
            top_n = variables.pop("_limit")
            data = self._graphql(TOP_VULNS_QUERY, variables)
            result = data.get("vulnerabilityFindings") or {}
            flat = [self._flatten_vulnerability(n) for n in (result.get("nodes") or [])]
            # Safety net in case the exposure filter is ignored: drop assets Wiz marks as not exposed.
            flat = [v for v in flat if v["asset"]["internet_exposure"] != "none"]
            flat.sort(key=self._vuln_sort_key, reverse=True)
            return {
                "source": "wiz",
                "filters_applied": variables["filterBy"],
                "total_matching": result.get("totalCount", len(flat)),
                "returned": min(len(flat), top_n),
                "vulnerabilities": flat[:top_n],
            }

        return self._run(_do)

    # ------------------------------------------------------------------
    # Lab tools: identities with excessive permissions
    # ------------------------------------------------------------------

    @staticmethod
    def build_identity_variables(
        service: Optional[str] = None,
        project: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Build variables for EXCESSIVE_IDENTITIES_QUERY. Raises ValueError on bad input.

        Entity types and the hasAdminPrivileges / hasHighPrivileges property names:
        verify against your tenant's schema.
        """
        try:
            limit_int = int(limit if limit is not None else 25)
        except (TypeError, ValueError):
            raise ValueError("limit must be an integer.")
        limit_int = max(1, min(limit_int, MAX_IDENTITY_LIMIT))

        def entity_query(privilege_field: str) -> Dict[str, Any]:
            where: Dict[str, Any] = {privilege_field: {"EQUALS": [True]}}
            if service:
                where["name"] = {"CONTAINS": [service]}
            return {
                "type": ["SERVICE_ACCOUNT", "USER_ACCOUNT"],   # verify against your tenant's schema
                "select": True,
                "where": where,
            }

        if service and not SERVICE_FILTER_RE.match(service):
            raise ValueError("Invalid service. Use letters, digits, '.', '_', '@', '-' (max 128 chars).")
        if project and not WIZ_ID_RE.match(project):
            raise ValueError("Invalid project. Use a Wiz project ID.")

        return {
            "adminQuery": entity_query("hasAdminPrivileges"),   # verify against your tenant's schema
            "highQuery": entity_query("hasHighPrivileges"),     # verify against your tenant's schema
            "projectId": project or "*",
            "first": limit_int,
        }

    @staticmethod
    def _parse_properties(raw: Any) -> Dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except ValueError:
                return {}
        return {}

    def excessive_permission_identities(
        self,
        service: Optional[str] = None,
        project: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        def _do() -> Dict[str, Any]:
            try:
                variables = self.build_identity_variables(service, project, limit)
            except ValueError as ve:
                return {"error": str(ve)}
            data = self._graphql(EXCESSIVE_IDENTITIES_QUERY, variables)
            merged: Dict[str, Dict[str, Any]] = {}
            for alias, flag in (("admin", "has_admin_privileges"), ("high", "has_high_privileges")):
                for node in ((data.get(alias) or {}).get("nodes") or []):
                    for ent in node.get("entities") or []:
                        if not isinstance(ent, dict) or not ent.get("id"):
                            continue
                        props = self._parse_properties(ent.get("properties"))
                        item = merged.setdefault(ent["id"], {
                            "id": ent["id"],
                            "name": ent.get("name"),
                            "type": ent.get("type"),
                            "cloud_platform": props.get("cloudPlatform"),
                            "native_type": props.get("nativeType"),
                            "external_id": props.get("externalId") or props.get("providerUniqueId"),
                            "has_admin_privileges": bool(props.get("hasAdminPrivileges")),
                            "has_high_privileges": bool(props.get("hasHighPrivileges")),
                        })
                        item[flag] = True
            identities = sorted(
                merged.values(),
                key=lambda i: (i["has_admin_privileges"], i["has_high_privileges"], i.get("name") or ""),
                reverse=True,
            )[: variables["first"]]
            return {
                "source": "wiz",
                "filters_applied": {"service": service, "project": variables["projectId"]},
                "returned": len(identities),
                "identities": identities,
            }

        return self._run(_do)

    # ------------------------------------------------------------------
    # Lab tools: code-to-cloud trace (Wiz part; BigQuery fallback lives in the server tool)
    # ------------------------------------------------------------------

    @staticmethod
    def build_code_to_cloud_filter(resource_id: str) -> Dict[str, Any]:
        """Wiz internal IDs are UUID-like; cloud provider IDs contain '/'.

        filterBy keys id / providerUniqueId: verify against your tenant's schema.
        """
        if "/" in resource_id:
            return {"providerUniqueId": [resource_id]}
        return {"id": [resource_id]}

    @staticmethod
    def _labels_to_dict(raw: Any) -> Dict[str, str]:
        if isinstance(raw, dict):
            return {str(k): str(v) for k, v in raw.items()}
        labels: Dict[str, str] = {}
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict) and "key" in item:
                    labels[str(item["key"])] = str(item.get("value", ""))
                elif isinstance(item, str) and "=" in item:
                    k, v = item.split("=", 1)
                    labels[k] = v
        return labels

    @classmethod
    def extract_code_origin(cls, properties: Dict[str, Any]) -> Dict[str, Any]:
        digest = next((properties[k] for k in IMAGE_DIGEST_KEYS if properties.get(k)), None)
        labels: Dict[str, str] = {}
        for k in IMAGE_LABEL_KEYS:
            if properties.get(k):
                labels = cls._labels_to_dict(properties[k])
                break
        repository = next((properties[k] for k in REPOSITORY_KEYS if properties.get(k)), None)
        if not repository and labels.get(OCI_SOURCE_LABEL):
            repository = labels[OCI_SOURCE_LABEL]
        return {"image_digest": digest, "image_labels": labels, "repository": repository}

    def trace_code_to_cloud(
        self,
        issue_id: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolve a Wiz issue or resource to its image and source repository.

        Returns {"found": True, ...} when Wiz yields a repository, {"found": False, ...}
        when it does not, or {"error": ...} on configuration/API errors.
        """
        if not issue_id and not resource_id:
            return {"error": "Provide issue_id or resource_id."}
        if issue_id and not WIZ_ID_RE.match(issue_id):
            return {"error": "Invalid issue_id. Use letters, digits, '.', '_', ':', '-' (max 128 chars)."}
        if resource_id and not WIZ_RESOURCE_ID_RE.match(resource_id):
            return {"error": "Invalid resource_id."}

        def _do() -> Dict[str, Any]:
            rid = resource_id
            entity: Dict[str, Any] = {}
            if issue_id and not rid:
                data = self._graphql(ISSUE_ENTITY_QUERY, {"filterBy": {"id": [issue_id]}})
                nodes = (data.get("issuesV2") or {}).get("nodes") or []
                if not nodes:
                    return {"found": False, "source": "wiz", "issue_id": issue_id,
                            "reason": f"Wiz issue '{issue_id}' not found."}
                entity = nodes[0].get("entitySnapshot") or {}
                rid = entity.get("providerId") or entity.get("externalId") or entity.get("id")
                if not rid:
                    return {"found": False, "source": "wiz", "issue_id": issue_id,
                            "reason": "Wiz issue has no affected resource."}

            filter_by = self.build_code_to_cloud_filter(rid)
            data = self._graphql(CODE_TO_CLOUD_QUERY, {"filterBy": filter_by, "first": 5})
            nodes = (data.get("cloudResources") or {}).get("nodes") or []
            for node in nodes:
                ge = node.get("graphEntity") or {}
                origin = self.extract_code_origin(self._parse_properties(ge.get("properties")))
                if origin["repository"] or origin["image_digest"]:
                    return {
                        "found": bool(origin["repository"]),
                        "source": "wiz",
                        "issue_id": issue_id,
                        "resource": {
                            "id": node.get("id"),
                            "name": node.get("name"),
                            "type": node.get("type"),
                            "provider_id": node.get("providerId") or rid,
                        },
                        **origin,
                    }
            return {
                "found": False,
                "source": "wiz",
                "issue_id": issue_id,
                "resource": {"provider_id": rid, "name": entity.get("name"), "type": entity.get("type")},
                "reason": "Wiz returned no image or repository for this resource.",
            }

        return self._run(_do)
