"""Read-only BigQuery queries over the security datasets used by the lab.

Covers the SCC findings export, Model Armor and VPC Service Controls log sink
tables, and the security_lab tables written by the log ingestion service
(security_events, sandbox_runs, code_to_cloud_map).

Every query is a fixed SELECT. User input only reaches BigQuery through query
parameters; table names come from settings and are validated as identifiers.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from google.cloud import bigquery
from google.cloud.exceptions import GoogleCloudError, NotFound

from config import settings
from services.bigquery_service import serialize_row

logger = logging.getLogger(__name__)

SCC_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "SEVERITY_UNSPECIFIED"}
SCC_STATES = {"ACTIVE", "INACTIVE", "STATE_UNSPECIFIED"}
MODEL_ARMOR_MATCH_STATES = {"MATCH_FOUND", "NO_MATCH_FOUND"}
MODEL_ARMOR_FILTER_TYPES = {"rai", "pi_and_jailbreak", "malicious_uris", "sdp", "csam"}
SECURITY_EVENT_TYPES = {
    "CODEMENDER_SCAN_STARTED",
    "CODEMENDER_SCAN_COMPLETED",
    "CODEMENDER_FINDING",
    "CODEMENDER_PATCH",
    "SANDBOX_RESULT",
    "IAM_POLICY_CHANGE",
    "OTHER_SECURITY",
}
# security_events.severity holds either a finding severity or a log severity.
SECURITY_EVENT_SEVERITIES = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL",
    "DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "ALERT", "EMERGENCY",
}

ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9._:/@\-]{1,512}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_\-]{1,1024}$")
CATEGORY_RE = re.compile(r"^[A-Za-z0-9_.:\- ]{1,256}$")
PROJECT_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._%+\-:@/]{1,320}$")
SERVICE_RE = re.compile(r"^[a-z0-9.\-]{1,253}$")
PERIMETER_RE = re.compile(r"^[A-Za-z0-9_./\-]{1,512}$")


def _p(name: str, type_: str, value: Any) -> bigquery.ScalarQueryParameter:
    return bigquery.ScalarQueryParameter(name, type_, value)


class SecurityDataService:
    """Parameterized, read-only queries over the lab's security tables."""

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or settings.gcp_project_id
        self._client: Optional[bigquery.Client] = None

    @property
    def client(self) -> bigquery.Client:
        """Lazy BigQuery client using Application Default Credentials."""
        if self._client is None:
            logger.info("Initializing BigQuery client (security data) for project: %s", self.project_id)
            self._client = bigquery.Client(project=self.project_id)
        return self._client

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _table(self, dataset: str, table: str) -> str:
        """Fully qualified table name. Dataset/table come from settings, not users."""
        project = self.client.project
        for part in (project, dataset, table):
            if not part or not IDENTIFIER_RE.match(str(part)):
                raise ValueError(f"Invalid BigQuery identifier in settings: {part!r}")
        return f"`{project}.{dataset}.{table}`"

    @staticmethod
    def _limit(limit: Optional[int]) -> int:
        try:
            value = int(limit if limit is not None else settings.default_query_limit)
        except (TypeError, ValueError):
            value = settings.default_query_limit
        return max(1, min(value, settings.max_query_limit))

    @staticmethod
    def _days(days: Optional[int]) -> int:
        try:
            value = int(days if days is not None else 7)
        except (TypeError, ValueError):
            value = 7
        return max(1, min(value, settings.max_lookback_days))

    def _run_query(
        self,
        sql: str,
        params: List[bigquery.ScalarQueryParameter],
        filters: Dict[str, Any],
        target: str,
    ) -> Dict[str, Any]:
        try:
            job_config = bigquery.QueryJobConfig(query_parameters=params)
            rows = [serialize_row(r) for r in self.client.query(sql, job_config=job_config).result()]
            return {"row_count": len(rows), "filters_applied": filters, "data": rows}
        except NotFound:
            return {"error": f"Table {target} not found. Check the dataset/table settings and that the sink or export has written data."}
        except GoogleCloudError as gce:
            logger.exception("BigQuery query error: %s", gce)
            return {"error": f"BigQuery error: {getattr(gce, 'message', str(gce))}"}
        except Exception as e:
            logger.exception("Unexpected BigQuery error: %s", e)
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Security Command Center findings export
    # ------------------------------------------------------------------

    def query_scc_findings(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        state: Optional[str] = "ACTIVE",
        project: Optional[str] = None,
        days: int = 7,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Latest state of each SCC finding exported to BigQuery."""
        filters: Dict[str, Any] = {}
        params = [_p("days", "INT64", self._days(days)), _p("limit", "INT64", self._limit(limit))]
        where: List[str] = []

        if severity:
            sev = severity.strip().upper()
            if sev not in SCC_SEVERITIES:
                return {"error": f"Invalid severity '{severity}'. Use one of {sorted(SCC_SEVERITIES)}."}
            where.append("severity = @severity")
            params.append(_p("severity", "STRING", sev))
            filters["severity"] = sev
        if state:
            st = state.strip().upper()
            if st not in SCC_STATES:
                return {"error": f"Invalid state '{state}'. Use one of {sorted(SCC_STATES)}."}
            where.append("state = @state")
            params.append(_p("state", "STRING", st))
            filters["state"] = st
        if category:
            if not CATEGORY_RE.match(category):
                return {"error": "Invalid category. Use letters, digits, spaces, '_', '-', '.', ':'."}
            where.append("UPPER(category) = UPPER(@category)")
            params.append(_p("category", "STRING", category.strip()))
            filters["category"] = category.strip()
        if project:
            if not PROJECT_RE.match(project):
                return {"error": "Invalid project. Use a GCP project ID or display name."}
            where.append("project = @project")
            params.append(_p("project", "STRING", project.strip()))
            filters["project"] = project.strip()

        try:
            target = self._table(settings.scc_dataset, settings.scc_table)
        except ValueError as ve:
            return {"error": str(ve)}
        outer_where = f"WHERE {' AND '.join(where)}" if where else ""
        sql = f"""
            WITH latest AS (
                SELECT
                    finding_id,
                    event_time,
                    finding.name AS finding_name,
                    finding.category AS category,
                    finding.severity AS severity,
                    finding.state AS state,
                    finding.finding_class AS finding_class,
                    finding.resource_name AS resource_name,
                    finding.description AS description,
                    finding.external_uri AS external_uri,
                    finding.create_time AS create_time,
                    resource.display_name AS resource_display_name,
                    resource.type AS resource_type,
                    resource.project_display_name AS project
                FROM {target}
                WHERE event_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)
                QUALIFY ROW_NUMBER() OVER (PARTITION BY finding.name ORDER BY event_time DESC) = 1
            )
            SELECT * FROM latest
            {outer_where}
            ORDER BY event_time DESC
            LIMIT @limit
        """
        return self._run_query(sql, params, filters, target)

    # ------------------------------------------------------------------
    # Model Armor sanitize operations (log sink table)
    # ------------------------------------------------------------------

    def query_model_armor_logs(
        self,
        match_state: Optional[str] = None,
        filter_type: Optional[str] = None,
        days: int = 7,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Model Armor sanitize operations. Field names: confirm in your environment."""
        filters: Dict[str, Any] = {}
        params = [_p("days", "INT64", self._days(days)), _p("limit", "INT64", self._limit(limit))]
        where = ["timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]

        if match_state:
            ms = match_state.strip().upper()
            if ms not in MODEL_ARMOR_MATCH_STATES:
                return {"error": f"Invalid match_state '{match_state}'. Use one of {sorted(MODEL_ARMOR_MATCH_STATES)}."}
            where.append("jsonPayload.filter_match_state = @match_state")
            params.append(_p("match_state", "STRING", ms))
            filters["match_state"] = ms
        if filter_type:
            ft = filter_type.strip().lower()
            if ft not in MODEL_ARMOR_FILTER_TYPES:
                return {"error": f"Invalid filter_type '{filter_type}'. Use one of {sorted(MODEL_ARMOR_FILTER_TYPES)}."}
            where.append("@filter_type IN UNNEST(SPLIT(LOWER(IFNULL(jsonPayload.matched_filters, '')), ','))")
            params.append(_p("filter_type", "STRING", ft))
            filters["filter_type"] = ft

        try:
            target = self._table(settings.security_logs_dataset, settings.model_armor_table)
        except ValueError as ve:
            return {"error": str(ve)}
        sql = f"""
            SELECT
                timestamp,
                insertId AS insert_id,
                severity,
                resource.labels.project_id AS project_id,
                resource.labels.location AS location,
                jsonPayload.operation_type AS operation_type,
                jsonPayload.filter_match_state AS filter_match_state,
                jsonPayload.matched_filters AS matched_filters,
                jsonPayload.template AS template,
                jsonPayload.invocation_result AS invocation_result,
                jsonPayload.client_name AS client_name
            FROM {target}
            WHERE {' AND '.join(where)}
            ORDER BY timestamp DESC
            LIMIT @limit
        """
        return self._run_query(sql, params, filters, target)

    # ------------------------------------------------------------------
    # VPC Service Controls violations (cloudaudit policy log sink table)
    # ------------------------------------------------------------------

    def query_vpcsc_violations(
        self,
        perimeter: Optional[str] = None,
        principal: Optional[str] = None,
        service: Optional[str] = None,
        days: int = 7,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """VPC Service Controls denials from the Cloud Audit policy log."""
        filters: Dict[str, Any] = {}
        params = [_p("days", "INT64", self._days(days)), _p("limit", "INT64", self._limit(limit))]
        where = ["timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]

        if perimeter:
            if not PERIMETER_RE.match(perimeter):
                return {"error": "Invalid perimeter. Use a perimeter name or accessPolicies/<id>/servicePerimeters/<name>."}
            where.append(
                "LOWER(IFNULL(JSON_VALUE(protopayload_auditlog.metadataJson, "
                "'$.securityPolicyInfo.servicePerimeterName'), '')) LIKE LOWER(@perimeter)"
            )
            params.append(_p("perimeter", "STRING", f"%{perimeter.strip()}%"))
            filters["perimeter"] = perimeter.strip()
        if principal:
            if not PRINCIPAL_RE.match(principal):
                return {"error": "Invalid principal. Use an email address (user or service account)."}
            where.append("LOWER(protopayload_auditlog.authenticationInfo.principalEmail) = LOWER(@principal)")
            params.append(_p("principal", "STRING", principal.strip()))
            filters["principal"] = principal.strip()
        if service:
            svc = service.strip().lower()
            if not SERVICE_RE.match(svc):
                return {"error": "Invalid service. Use an API service name such as storage.googleapis.com."}
            where.append("LOWER(protopayload_auditlog.serviceName) = @service")
            params.append(_p("service", "STRING", svc))
            filters["service"] = svc

        try:
            target = self._table(settings.security_logs_dataset, settings.vpcsc_table)
        except ValueError as ve:
            return {"error": str(ve)}
        sql = f"""
            SELECT
                timestamp,
                insertId AS insert_id,
                severity,
                resource.labels.project_id AS project_id,
                protopayload_auditlog.serviceName AS service_name,
                protopayload_auditlog.methodName AS method_name,
                protopayload_auditlog.resourceName AS resource_name,
                protopayload_auditlog.authenticationInfo.principalEmail AS principal_email,
                protopayload_auditlog.requestMetadata.callerIp AS caller_ip,
                JSON_VALUE(protopayload_auditlog.metadataJson, '$.violationReason') AS violation_reason,
                JSON_VALUE(protopayload_auditlog.metadataJson, '$.securityPolicyInfo.servicePerimeterName') AS perimeter
            FROM {target}
            WHERE {' AND '.join(where)}
            ORDER BY timestamp DESC
            LIMIT @limit
        """
        return self._run_query(sql, params, filters, target)

    # ------------------------------------------------------------------
    # security_lab.security_events
    # ------------------------------------------------------------------

    def query_security_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        issue_id: Optional[str] = None,
        days: int = 7,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Normalized events written by the log ingestion service."""
        # TODO(lab-07): Implement this read-only query over security_lab.security_events.
        #   1. Start with params [_p("days", "INT64", self._days(days)), _p("limit", "INT64", self._limit(limit))]
        #      and where = ["event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"].
        #   2. event_type: strip + upper-case it; if not in SECURITY_EVENT_TYPES return
        #      {"error": "Invalid event_type '<value>'. Use one of [...]"}; else add "event_type = @event_type".
        #   3. severity: strip + upper-case; must be in SECURITY_EVENT_SEVERITIES (else "Invalid severity ...");
        #      add "UPPER(severity) = @severity".
        #   4. issue_id: must match ID_RE (else "Invalid issue_id. ..."); add "issue_id = @issue_id".
        #   5. Record each accepted filter in a `filters` dict (it is returned as filters_applied).
        #   6. target = self._table(settings.security_dataset, settings.security_events_table)
        #      (return {"error": str(ve)} on ValueError).
        #   7. SELECT insert_id, event_timestamp, event_type, source, severity, project_id, resource_type,
        #      resource_name, principal, repository, commit_sha, issue_id, session_id, run_id, status,
        #      summary, log_name FROM {target} WHERE <AND-joined where> ORDER BY event_timestamp DESC LIMIT @limit
        #   8. return self._run_query(sql, params, filters, target)
        # User input must only reach BigQuery as query parameters, never in the SQL string.
        # Checked by: mcp-server/tests/test_new_tools.py TestSecurityDataService.test_security_events
        #             and TestSecurityDataService.test_query_errors_become_error_dicts
        return {"error": "TODO"}

    # ------------------------------------------------------------------
    # security_lab.code_to_cloud_map and codemender.findings lookups
    # ------------------------------------------------------------------

    def get_code_to_cloud(
        self,
        resource_id: Optional[str] = None,
        repository: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Look up resource-to-repository mappings by resource ID or repository."""
        # TODO(lab-07): Implement the BigQuery fallback used by trace_code_to_cloud when Wiz has no answer.
        #   1. If neither resource_id nor repository is given, return {"error": "Provide resource_id or repository."}.
        #   2. params = [_p("limit", "INT64", self._limit(limit))]; build an OR-joined where list.
        #   3. resource_id: must match RESOURCE_ID_RE (else {"error": "Invalid resource_id."});
        #      add "(resource_id = @resource_id OR resource_name = @resource_id)".
        #   4. repository: must match REPOSITORY_RE (else {"error": "Invalid repository. Use owner/name."});
        #      add "LOWER(repository) LIKE LOWER(@repository)" with the parameter value f"%{repository}".
        #   5. Record accepted filters in `filters`.
        #   6. target = self._table(settings.security_dataset, settings.code_to_cloud_table)
        #      (return {"error": str(ve)} on ValueError).
        #   7. SELECT resource_id, resource_name, cloud_platform, image, image_digest, base_image, repository,
        #      dockerfile_path, terraform_path, commit_sha, updated_at FROM {target}
        #      WHERE <OR-joined where> ORDER BY updated_at DESC LIMIT @limit
        #   8. return self._run_query(sql, params, filters, target)
        # Checked by: mcp-server/tests/test_new_tools.py TestSecurityDataService.test_code_to_cloud_and_finding_lookup
        #             and TestServerTools.test_trace_code_to_cloud_falls_back_to_bigquery
        return {"error": "TODO"}

    def get_finding_repository(self, issue_id: str) -> Dict[str, Any]:
        """Find the repository for a Code Mender finding ID, issue ID or Wiz issue ID."""
        if not issue_id or not ID_RE.match(issue_id):
            return {"error": "Invalid issue_id. Use letters, digits, '.', '_', ':', '-' (max 128 chars)."}
        try:
            target = self._table(settings.bq_dataset, settings.bq_table)
        except ValueError as ve:
            return {"error": str(ve)}
        sql = f"""
            SELECT finding_id, issue_id, wiz_issue_id, repository, commit_sha, file_path, title, severity, status
            FROM {target}
            WHERE finding_id = @issue_id OR issue_id = @issue_id OR wiz_issue_id = @issue_id
            ORDER BY created_at DESC
            LIMIT 1
        """
        params = [_p("issue_id", "STRING", issue_id)]
        return self._run_query(sql, params, {"issue_id": issue_id}, target)

    # ------------------------------------------------------------------
    # security_lab.sandbox_runs
    # ------------------------------------------------------------------

    def get_sandbox_run(
        self,
        run_id: Optional[str] = None,
        execution_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return the newest sandbox_runs row for a run ID or execution name."""
        if not run_id and not execution_name:
            return {"error": "Provide run_id or execution_name."}
        where: List[str] = []
        params: List[bigquery.ScalarQueryParameter] = []
        filters: Dict[str, Any] = {}
        if run_id:
            if not ID_RE.match(run_id):
                return {"error": "Invalid run_id."}
            where.append("run_id = @run_id")
            params.append(_p("run_id", "STRING", run_id))
            filters["run_id"] = run_id
        if execution_name:
            short = execution_name.rsplit("/", 1)[-1]
            if not ID_RE.match(short):
                return {"error": "Invalid execution_name."}
            where.append("execution_name = @execution_name")
            params.append(_p("execution_name", "STRING", short))
            filters["execution_name"] = short

        try:
            target = self._table(settings.security_dataset, settings.sandbox_runs_table)
        except ValueError as ve:
            return {"error": str(ve)}
        sql = f"""
            SELECT
                run_id, execution_name, repository, commit_sha, patch_ref, issue_id, poc_test,
                started_at, finished_at, poc_before, poc_after, patch_applied,
                unit_tests_passed, tests_total, tests_failed, verdict, log_excerpt
            FROM {target}
            WHERE {' OR '.join(where)}
            ORDER BY finished_at DESC
            LIMIT 1
        """
        return self._run_query(sql, params, filters, target)
