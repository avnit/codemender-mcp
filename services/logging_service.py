import datetime
import logging
from typing import Any, Dict, List, Optional

from google.cloud import logging_v2
from google.cloud.exceptions import GoogleCloudError

from config import settings

logger = logging.getLogger(__name__)


def format_log_entry(entry: logging_v2.LogEntry) -> Dict[str, Any]:
    """Format a Cloud Logging LogEntry into a clean, JSON-serializable dictionary."""
    payload = entry.payload
    # Handle structured payload or string payload
    if isinstance(payload, dict):
        payload_data = payload
    else:
        payload_data = str(payload)

    return {
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "severity": entry.severity,
        "log_name": entry.log_name.split("/")[-1] if entry.log_name else None,
        "full_log_name": entry.log_name,
        "resource": {
            "type": entry.resource.type if entry.resource else None,
            "labels": dict(entry.resource.labels) if entry.resource and entry.resource.labels else {},
        },
        "payload": payload_data,
        "labels": dict(entry.labels) if entry.labels else {},
        "trace": entry.trace,
        "span_id": entry.span_id,
        "insert_id": entry.insert_id,
    }


class LoggingService:
    """Service for searching and correlating Cloud Logging data for Code Mender runs."""

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or settings.gcp_project_id
        self._client: Optional[logging_v2.Client] = None

    @property
    def client(self) -> logging_v2.Client:
        """Lazy initialization of Cloud Logging client using Application Default Credentials."""
        if self._client is None:
            logger.info("Initializing Cloud Logging client for project: %s", self.project_id)
            self._client = logging_v2.Client(project=self.project_id)
        return self._client

    def get_issue_logs(
        self,
        issue_id: Optional[str] = None,
        session_id: Optional[str] = None,
        min_severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Fetch Cloud Logging entries correlated with an issue ID or Code Mender session ID.

        Args:
            issue_id: Finding or issue ID to correlate.
            session_id: Code Mender scan/patch session ID to correlate.
            min_severity: Minimum severity level (e.g. INFO, WARNING, ERROR).
            start_time: Earliest timestamp in ISO format.
            end_time: Latest timestamp in ISO format.
            limit: Maximum log entries to retrieve (capped at 200).
        """
        if not issue_id and not session_id:
            return {"error": "At least one of 'issue_id' or 'session_id' must be provided."}

        limit = min(max(1, limit), 200)
        filter_parts: List[str] = []

        # Identifier matching
        id_filters = []
        if issue_id:
            id_filters.extend([
                f'jsonPayload.finding_id="{issue_id}"',
                f'jsonPayload.issue_id="{issue_id}"',
                f'labels.finding_id="{issue_id}"',
                f'labels.issue_id="{issue_id}"',
                f'"{issue_id}"',
            ])
        if session_id:
            id_filters.extend([
                f'jsonPayload.session_id="{session_id}"',
                f'labels.session_id="{session_id}"',
                f'"{session_id}"',
            ])

        if id_filters:
            filter_parts.append(f"({' OR '.join(id_filters)})")

        # Severity filter
        if min_severity:
            filter_parts.append(f"severity >= {min_severity.upper()}")

        # Time bounds
        if start_time:
            filter_parts.append(f'timestamp >= "{start_time}"')
        if end_time:
            filter_parts.append(f'timestamp <= "{end_time}"')

        log_filter = " AND ".join(filter_parts)
        logger.info("Executing Cloud Logging query with filter: %s", log_filter)

        try:
            entries = self.client.list_entries(
                filter_=log_filter,
                order_by=logging_v2.DESCENDING,
                max_results=limit,
            )
            formatted = [format_log_entry(entry) for entry in entries]
            return {
                "filter_used": log_filter,
                "entry_count": len(formatted),
                "entries": formatted,
            }
        except GoogleCloudError as gce:
            logger.exception("Cloud Logging error: %s", gce)
            return {"error": f"Cloud Logging API error: {gce.message}"}
        except Exception as e:
            logger.exception("Unexpected error querying Cloud Logging: %s", e)
            return {"error": str(e)}

    def search_logs(
        self,
        query: Optional[str] = None,
        min_severity: Optional[str] = None,
        hours_ago: int = 24,
        resource_type: Optional[str] = None,
        log_name: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Search Cloud Logging for Code Mender executions, errors, or sandbox events.

        Args:
            query: Free text or field search query string.
            min_severity: Minimum log severity (DEFAULT, INFO, WARNING, ERROR, CRITICAL).
            hours_ago: Search within the last N hours (default 24).
            resource_type: Cloud resource type (e.g. 'cloud_run_job', 'cloud_run_revision').
            log_name: Specific log name or suffix to filter on.
            limit: Maximum entries to return.
        """
        limit = min(max(1, limit), 200)
        filter_parts: List[str] = []

        # Time window
        now = datetime.datetime.now(datetime.timezone.utc)
        since = now - datetime.timedelta(hours=max(1, hours_ago))
        filter_parts.append(f'timestamp >= "{since.isoformat()}"')

        if query:
            filter_parts.append(f'"{query}"')

        if min_severity:
            filter_parts.append(f"severity >= {min_severity.upper()}")

        if resource_type:
            filter_parts.append(f'resource.type="{resource_type}"')

        if log_name:
            filter_parts.append(f'logName=~"{log_name}"')
        elif settings.log_name_filter:
            filter_parts.append(f'logName=~"{settings.log_name_filter}"')

        log_filter = " AND ".join(filter_parts)
        logger.info("Executing Cloud Logging search: %s", log_filter)

        try:
            entries = self.client.list_entries(
                filter_=log_filter,
                order_by=logging_v2.DESCENDING,
                max_results=limit,
            )
            formatted = [format_log_entry(entry) for entry in entries]
            return {
                "filter_used": log_filter,
                "time_window_hours": hours_ago,
                "entry_count": len(formatted),
                "entries": formatted,
            }
        except Exception as e:
            logger.exception("Unexpected error in search_logs: %s", e)
            return {"error": str(e)}
