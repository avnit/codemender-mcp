import datetime
import decimal
import unittest
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from services.bigquery_service import BigQueryService, serialize_bq_val
from services.logging_service import LoggingService, format_log_entry
from server import app


class TestSerialization(unittest.TestCase):
    def test_serialize_datetime(self):
        dt = datetime.datetime(2026, 9, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(serialize_bq_val(dt), "2026-09-10T12:00:00+00:00")

    def test_serialize_decimal(self):
        dec = decimal.Decimal("123.45")
        self.assertEqual(serialize_bq_val(dec), 123.45)

    def test_serialize_nested_dict(self):
        data = {
            "time": datetime.date(2026, 9, 10),
            "amount": decimal.Decimal("99.9"),
            "bytes_val": b"hello",
            "list_val": [decimal.Decimal("1.2")],
        }
        serialized = serialize_bq_val(data)
        self.assertEqual(serialized["time"], "2026-09-10")
        self.assertEqual(serialized["amount"], 99.9)
        self.assertEqual(serialized["bytes_val"], "hello")
        self.assertEqual(serialized["list_val"], [1.2])


class TestBigQueryService(unittest.TestCase):
    @patch("services.bigquery_service.bigquery.Client")
    def test_list_issues_filter_construction(self, mock_bq_client):
        mock_instance = MagicMock()
        mock_bq_client.return_value = mock_instance
        mock_instance.project = "test-project"

        # Mock count and data results
        mock_count_job = MagicMock()
        mock_count_job.result.return_value = [{"total": 1}]
        
        mock_data_job = MagicMock()
        mock_data_job.result.return_value = [
            {"finding_id": "FINDING-123", "severity": "HIGH", "status": "OPEN"}
        ]
        mock_instance.query.side_effect = [mock_count_job, mock_data_job]

        service = BigQueryService(project_id="test-project", dataset="test_ds", table="test_tb")
        res = service.list_issues(
            severity="HIGH",
            status="OPEN",
            repository="org/repo",
            vulnerability_type="CWE-89",
            limit=10,
        )

        self.assertIn("issues", res)
        self.assertEqual(res["total_issues"], 1)
        self.assertEqual(len(res["issues"]), 1)
        self.assertEqual(res["issues"][0]["finding_id"], "FINDING-123")

    def test_execute_read_query_safety(self):
        service = BigQueryService(project_id="test-project")
        
        # Disallowed statements
        res_delete = service.execute_read_query("DELETE FROM `test.table` WHERE 1=1")
        self.assertIn("error", res_delete)
        self.assertIn("SELECT or WITH", res_delete["error"])

        res_drop = service.execute_read_query("SELECT 1; DROP TABLE `test.table`")
        self.assertIn("error", res_drop)
        self.assertIn("disallowed", res_drop["error"])

        res_update = service.execute_read_query("UPDATE `test.table` SET status='CLOSED'")
        self.assertIn("error", res_update)


class TestLoggingService(unittest.TestCase):
    @patch("services.logging_service.logging_v2.Client")
    def test_get_issue_logs_filter(self, mock_logging_client):
        mock_instance = MagicMock()
        mock_logging_client.return_value = mock_instance
        mock_instance.list_entries.return_value = []

        service = LoggingService(project_id="test-project")
        res = service.get_issue_logs(issue_id="ISSUE-456", min_severity="WARNING")

        self.assertIn("filter_used", res)
        self.assertIn('jsonPayload.finding_id="ISSUE-456"', res["filter_used"])
        self.assertIn("severity >= WARNING", res["filter_used"])

    def test_format_log_entry(self):
        mock_entry = MagicMock()
        mock_entry.timestamp = datetime.datetime(2026, 9, 10, 10, 0, 0, tzinfo=datetime.timezone.utc)
        mock_entry.severity = "ERROR"
        mock_entry.log_name = "projects/test-project/logs/codemender"
        mock_entry.resource.type = "cloud_run_job"
        mock_entry.resource.labels = {"job_name": "codemender-worker"}
        mock_entry.payload = {"message": "Failed to verify patch", "exit_code": 1}
        mock_entry.labels = {"session_id": "sess-123"}
        mock_entry.trace = "projects/test/traces/abc"
        mock_entry.span_id = "span-1"
        mock_entry.insert_id = "ins-1"

        formatted = format_log_entry(mock_entry)
        self.assertEqual(formatted["severity"], "ERROR")
        self.assertEqual(formatted["log_name"], "codemender")
        self.assertEqual(formatted["payload"]["message"], "Failed to verify patch")
        self.assertEqual(formatted["labels"]["session_id"], "sess-123")


class TestHttpEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "codemender-mcp-server")

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["service"], "Code Mender MCP Server")
        self.assertIn("/sse", data["mcp_sse_endpoint"])


if __name__ == "__main__":
    unittest.main()
