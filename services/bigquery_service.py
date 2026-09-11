import datetime
import decimal
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from google.cloud import bigquery
from google.cloud.exceptions import NotFound, GoogleCloudError

from config import settings

logger = logging.getLogger(__name__)


def serialize_bq_val(val: Any) -> Any:
    """Convert BigQuery data types to JSON-serializable Python types."""
    if val is None:
        return None
    if isinstance(val, (datetime.datetime, datetime.date, datetime.time)):
        return val.isoformat()
    if isinstance(val, decimal.Decimal):
        return float(val)
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return val.hex()
    if isinstance(val, dict):
        return {k: serialize_bq_val(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [serialize_bq_val(v) for v in val]
    return val


def serialize_row(row: bigquery.Row) -> Dict[str, Any]:
    """Convert a BigQuery Row to a serializable dictionary."""
    return {key: serialize_bq_val(val) for key, val in row.items()}


class BigQueryService:
    """Service for querying and analyzing Code Mender issues in BigQuery."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ):
        self.project_id = project_id or settings.gcp_project_id
        self.dataset = dataset or settings.bq_dataset
        self.table = table or settings.bq_table
        self._client: Optional[bigquery.Client] = None

    @property
    def client(self) -> bigquery.Client:
        """Lazy initialization of BigQuery client using Application Default Credentials."""
        if self._client is None:
            logger.info("Initializing BigQuery client for project: %s", self.project_id)
            self._client = bigquery.Client(project=self.project_id)
        return self._client

    @property
    def full_table_id(self) -> str:
        """Returns the fully qualified table name `project.dataset.table`."""
        project = self.client.project
        return f"`{project}.{self.dataset}.{self.table}`"

    def get_table_schema(
        self, dataset: Optional[str] = None, table: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch schema information for the specified BigQuery table."""
        ds = dataset or self.dataset
        tb = table or self.table
        project = self.client.project
        table_ref = f"{project}.{ds}.{tb}"

        try:
            table_obj = self.client.get_table(table_ref)
            columns = [
                {
                    "name": field.name,
                    "type": field.field_type,
                    "mode": field.mode,
                    "description": field.description or "",
                }
                for field in table_obj.schema
            ]
            return {
                "table_ref": table_ref,
                "num_rows": table_obj.num_rows,
                "num_bytes": table_obj.num_bytes,
                "created": table_obj.created.isoformat() if table_obj.created else None,
                "modified": table_obj.modified.isoformat() if table_obj.modified else None,
                "columns": columns,
            }
        except NotFound:
            return {"error": f"Table '{table_ref}' not found."}
        except Exception as e:
            logger.exception("Failed to get table schema: %s", e)
            return {"error": str(e)}

    def list_issues(
        self,
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
        """List Code Mender issues from BigQuery with flexible filtering.

        Args:
            severity: Filter by severity (e.g. CRITICAL, HIGH, MEDIUM, LOW).
            status: Filter by status (e.g. DETECTED, OPEN, PATCH_GENERATED, VERIFIED, APPLIED, FIXED, FAILED).
            repository: Filter by repository name or path.
            vulnerability_type: Filter by vulnerability type or CWE ID.
            session_id: Filter by Code Mender session/run ID.
            search_query: Search string within title, description, or file_path.
            start_date: Filter for issues created on or after this ISO date/timestamp.
            end_date: Filter for issues created on or before this ISO date/timestamp.
            limit: Maximum number of records to return (capped at settings.max_query_limit).
            offset: Offset for pagination.
            dataset: Optional dataset override.
            table: Optional table override.
        """
        limit = min(max(1, limit), settings.max_query_limit)
        offset = max(0, offset)

        ds = dataset or self.dataset
        tb = table or self.table
        target_table = f"`{self.client.project}.{ds}.{tb}`"

        where_clauses: List[str] = []
        query_params: List[bigquery.ScalarQueryParameter] = []

        if severity:
            where_clauses.append("UPPER(CAST(severity AS STRING)) = UPPER(@severity)")
            query_params.append(bigquery.ScalarQueryParameter("severity", "STRING", severity))

        if status:
            where_clauses.append("UPPER(CAST(status AS STRING)) = UPPER(@status)")
            query_params.append(bigquery.ScalarQueryParameter("status", "STRING", status))

        if repository:
            where_clauses.append("LOWER(CAST(repository AS STRING)) LIKE LOWER(@repository)")
            query_params.append(bigquery.ScalarQueryParameter("repository", "STRING", f"%{repository}%"))

        if vulnerability_type:
            where_clauses.append(
                "(LOWER(CAST(vulnerability_type AS STRING)) LIKE LOWER(@vuln_type) OR "
                "LOWER(CAST(cwe_id AS STRING)) LIKE LOWER(@vuln_type))"
            )
            query_params.append(bigquery.ScalarQueryParameter("vuln_type", "STRING", f"%{vulnerability_type}%"))

        if session_id:
            where_clauses.append("CAST(session_id AS STRING) = @session_id")
            query_params.append(bigquery.ScalarQueryParameter("session_id", "STRING", session_id))

        if search_query:
            where_clauses.append(
                "(LOWER(CAST(title AS STRING)) LIKE LOWER(@search) OR "
                "LOWER(CAST(description AS STRING)) LIKE LOWER(@search) OR "
                "LOWER(CAST(file_path AS STRING)) LIKE LOWER(@search))"
            )
            query_params.append(bigquery.ScalarQueryParameter("search", "STRING", f"%{search_query}%"))

        if start_date:
            where_clauses.append("created_at >= TIMESTAMP(@start_date)")
            query_params.append(bigquery.ScalarQueryParameter("start_date", "STRING", start_date))

        if end_date:
            where_clauses.append("created_at <= TIMESTAMP(@end_date)")
            query_params.append(bigquery.ScalarQueryParameter("end_date", "STRING", end_date))

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Query total count for pagination metadata
        count_sql = f"SELECT COUNT(*) AS total FROM {target_table} {where_sql}"
        
        # Main issue selection
        data_sql = f"""
            SELECT *
            FROM {target_table}
            {where_sql}
            ORDER BY created_at DESC
            LIMIT @limit OFFSET @offset
        """

        query_params_with_paging = query_params + [
            bigquery.ScalarQueryParameter("limit", "INT64", limit),
            bigquery.ScalarQueryParameter("offset", "INT64", offset),
        ]

        try:
            # Execute count
            count_job_config = bigquery.QueryJobConfig(query_parameters=query_params)
            count_job = self.client.query(count_sql, job_config=count_job_config)
            count_rows = list(count_job.result())
            total_count = count_rows[0]["total"] if count_rows else 0

            # Execute data query
            data_job_config = bigquery.QueryJobConfig(query_parameters=query_params_with_paging)
            data_job = self.client.query(data_sql, job_config=data_job_config)
            rows = [serialize_row(row) for row in data_job.result()]

            return {
                "total_issues": total_count,
                "returned_issues": len(rows),
                "limit": limit,
                "offset": offset,
                "issues": rows,
            }
        except NotFound:
            return {"error": f"Table {target_table} does not exist in project '{self.client.project}'."}
        except GoogleCloudError as gce:
            logger.exception("BigQuery query error: %s", gce)
            return {"error": f"BigQuery error: {gce.message}"}
        except Exception as e:
            logger.exception("Unexpected error querying BigQuery: %s", e)
            return {"error": str(e)}

    def get_issue_details(
        self,
        issue_id: str,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch detailed information for a specific Code Mender issue by finding/issue ID."""
        ds = dataset or self.dataset
        tb = table or self.table
        target_table = f"`{self.client.project}.{ds}.{tb}`"

        # Look up by finding_id or issue_id or id
        sql = f"""
            SELECT *
            FROM {target_table}
            WHERE CAST(finding_id AS STRING) = @issue_id
               OR CAST(issue_id AS STRING) = @issue_id
               OR CAST(id AS STRING) = @issue_id
            LIMIT 1
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("issue_id", "STRING", issue_id)]
        )

        try:
            job = self.client.query(sql, job_config=job_config)
            results = list(job.result())
            if not results:
                return {"error": f"Issue with ID '{issue_id}' not found in {target_table}."}
            return serialize_row(results[0])
        except NotFound:
            return {"error": f"Table {target_table} does not exist."}
        except Exception as e:
            logger.exception("Error getting issue details: %s", e)
            return {"error": str(e)}

    def get_issues_summary(
        self,
        repository: Optional[str] = None,
        days: int = 30,
        dataset: Optional[str] = None,
        table: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate aggregated summary statistics on Code Mender findings."""
        ds = dataset or self.dataset
        tb = table or self.table
        target_table = f"`{self.client.project}.{ds}.{tb}`"

        where_clauses = ["created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @days DAY)"]
        params = [bigquery.ScalarQueryParameter("days", "INT64", max(1, days))]

        if repository:
            where_clauses.append("LOWER(CAST(repository AS STRING)) LIKE LOWER(@repo)")
            params.append(bigquery.ScalarQueryParameter("repo", "STRING", f"%{repository}%"))

        where_sql = f"WHERE {' AND '.join(where_clauses)}"

        sql = f"""
            WITH base AS (
                SELECT * FROM {target_table} {where_sql}
            )
            SELECT
                (SELECT COUNT(*) FROM base) AS total_issues,
                (SELECT COUNTIF(UPPER(CAST(severity AS STRING)) = 'CRITICAL') FROM base) AS critical_count,
                (SELECT COUNTIF(UPPER(CAST(severity AS STRING)) = 'HIGH') FROM base) AS high_count,
                (SELECT COUNTIF(UPPER(CAST(severity AS STRING)) = 'MEDIUM') FROM base) AS medium_count,
                (SELECT COUNTIF(UPPER(CAST(severity AS STRING)) = 'LOW') FROM base) AS low_count,
                (SELECT COUNTIF(UPPER(CAST(status AS STRING)) IN ('FIXED', 'VERIFIED', 'APPLIED')) FROM base) AS resolved_count,
                (SELECT COUNTIF(UPPER(CAST(status AS STRING)) NOT IN ('FIXED', 'VERIFIED', 'APPLIED', 'FALSE_POSITIVE')) FROM base) AS open_count
        """

        top_vulns_sql = f"""
            SELECT
                COALESCE(CAST(vulnerability_type AS STRING), CAST(cwe_id AS STRING), 'Unknown') AS vuln_type,
                COUNT(*) AS count
            FROM {target_table}
            {where_sql}
            GROUP BY 1
            ORDER BY count DESC
            LIMIT 5
        """

        try:
            job_config = bigquery.QueryJobConfig(query_parameters=params)
            summary_res_list = list(self.client.query(sql, job_config=job_config).result())
            if not summary_res_list:
                return {"error": "No data returned for summary."}
            summary_res = summary_res_list[0]
            top_vulns_res = list(self.client.query(top_vulns_sql, job_config=job_config).result())

            return {
                "period_days": days,
                "repository_filter": repository,
                "total_issues": summary_res["total_issues"],
                "open_issues": summary_res["open_count"],
                "resolved_issues": summary_res["resolved_count"],
                "severity_breakdown": {
                    "CRITICAL": summary_res["critical_count"],
                    "HIGH": summary_res["high_count"],
                    "MEDIUM": summary_res["medium_count"],
                    "LOW": summary_res["low_count"],
                },
                "top_vulnerabilities": [
                    {"type": row["vuln_type"], "count": row["count"]} for row in top_vulns_res
                ],
            }
        except Exception as e:
            logger.exception("Error generating summary: %s", e)
            return {"error": str(e)}

    def execute_read_query(self, query: str, limit: int = 50) -> Dict[str, Any]:
        """Execute a safe, custom read-only SQL query against BigQuery.
        
        Enforces read-only safety by validating statements and restricting row output.
        """
        limit = min(max(1, limit), settings.max_query_limit)
        cleaned = query.strip()

        # Security check: must start with SELECT or WITH
        if not re.match(r"^(SELECT|WITH)\b", cleaned, re.IGNORECASE):
            return {
                "error": "Only read-only SELECT or WITH statements are permitted."
            }

        # Check for disallowed DML/DDL keywords
        disallowed_keywords = [
            r"\bDELETE\b", r"\bUPDATE\b", r"\bINSERT\b", r"\bDROP\b",
            r"\bALTER\b", r"\bCREATE\b", r"\bTRUNCATE\b", r"\bMERGE\b", r"\bGRANT\b"
        ]
        for pattern in disallowed_keywords:
            if re.search(pattern, cleaned, re.IGNORECASE):
                return {"error": f"Query contains disallowed keyword matching {pattern}."}

        # Enforce limit if not already present
        if not re.search(r"\bLIMIT\s+\d+", cleaned, re.IGNORECASE):
            cleaned += f" LIMIT {limit}"

        try:
            job = self.client.query(cleaned)
            rows = [serialize_row(row) for row in job.result()]
            return {
                "row_count": len(rows),
                "data": rows,
                "total_bytes_processed": job.total_bytes_processed,
            }
        except Exception as e:
            logger.exception("Failed custom query: %s", e)
            return {"error": str(e)}
