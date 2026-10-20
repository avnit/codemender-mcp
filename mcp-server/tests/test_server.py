try:  # install stubs for missing Google Cloud libraries before other imports
    import _stubs  # noqa: F401
except ImportError:  # pragma: no cover - when imported as a package (pytest)
    from tests import _stubs  # noqa: F401

import datetime
import decimal
import unittest
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from services.bigquery_service import BigQueryService, serialize_bq_val
from services.logging_service import LoggingService, format_log_entry
from services.wiz_service import WizService
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

        # Allowed statements with keywords inside string literals (false positive prevention)
        mock_client = MagicMock()
        mock_job = MagicMock()
        mock_job.result.return_value = []
        mock_client.query.return_value = mock_job
        service._client = mock_client
        
        res_safe_str = service.execute_read_query("SELECT * FROM `test.table` WHERE title = 'This is an UPDATE vulnerability'")
        self.assertNotIn("error", res_safe_str)
        
        res_safe_comment = service.execute_read_query("SELECT * FROM `test.table` -- checking drops")
        self.assertNotIn("error", res_safe_comment)
        
        res_semicolon = service.execute_read_query("SELECT * FROM `test.table`;")
        self.assertNotIn("error", res_semicolon)


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


def _mock_response(status_code=200, json_body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.raise_for_status.return_value = None
    return resp


class TestWizService(unittest.TestCase):
    def _service(self, http):
        return WizService(
            client_id="cid",
            client_secret="secret",
            api_endpoint="https://api.test.app.wiz.io/graphql",
            http_client=http,
        )

    def test_not_configured(self):
        service = WizService(http_client=MagicMock())
        service.client_id = service.client_secret = service.api_endpoint = None
        res = service.list_issues()
        self.assertIn("error", res)
        self.assertIn("not configured", res["error"])

    def test_build_issue_filters(self):
        filters = WizService.build_issue_filters(
            severity="critical, high",
            status="OPEN",
            issue_type="TOXIC_COMBINATION",
            project_id="proj-1",
            search_query="s3",
            start_date="2026-09-01T00:00:00Z",
            entity_id="ent-1",
        )
        self.assertEqual(filters["severity"], ["CRITICAL", "HIGH"])
        self.assertEqual(filters["status"], ["OPEN"])
        self.assertEqual(filters["type"], ["TOXIC_COMBINATION"])
        self.assertEqual(filters["project"], ["proj-1"])
        self.assertEqual(filters["search"], "s3")
        self.assertEqual(filters["createdAt"], {"after": "2026-09-01T00:00:00Z"})
        self.assertEqual(filters["relatedEntity"], {"id": "ent-1"})

    def test_invalid_severity_rejected(self):
        res = self._service(MagicMock()).list_issues(severity="SUPER_BAD")
        self.assertIn("Invalid severity", res["error"])

    def test_list_issues_auth_and_query(self):
        http = MagicMock()
        http.post.side_effect = [
            _mock_response(json_body={"access_token": "tok", "expires_in": 3600}),
            _mock_response(json_body={"data": {"issuesV2": {
                "totalCount": 1,
                "pageInfo": {"hasNextPage": False, "endCursor": "c1"},
                "nodes": [{"id": "wiz-1", "severity": "CRITICAL", "status": "OPEN"}],
            }}}),
        ]
        res = self._service(http).list_issues(severity="CRITICAL", limit=5)

        self.assertEqual(res["total_issues"], 1)
        self.assertEqual(res["issues"][0]["id"], "wiz-1")
        self.assertEqual(res["next_cursor"], "c1")

        auth_call, gql_call = http.post.call_args_list
        self.assertEqual(auth_call.kwargs["data"]["grant_type"], "client_credentials")
        self.assertEqual(auth_call.kwargs["data"]["audience"], "wiz-api")
        self.assertEqual(gql_call.kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(gql_call.kwargs["json"]["variables"]["first"], 5)
        self.assertEqual(gql_call.kwargs["json"]["variables"]["filterBy"]["severity"], ["CRITICAL"])

    def test_token_is_cached(self):
        http = MagicMock()
        gql = {"data": {"issuesV2": {"nodes": [], "pageInfo": {}}}}
        http.post.side_effect = [
            _mock_response(json_body={"access_token": "tok", "expires_in": 3600}),
            _mock_response(json_body=gql),
            _mock_response(json_body=gql),
        ]
        service = self._service(http)
        service.list_issues()
        service.list_issues()
        self.assertEqual(http.post.call_count, 3)

    def test_graphql_errors_returned(self):
        http = MagicMock()
        http.post.side_effect = [
            _mock_response(json_body={"access_token": "tok", "expires_in": 3600}),
            _mock_response(json_body={"errors": [{"message": "bad field"}]}),
        ]
        res = self._service(http).get_issue_details("wiz-1")
        self.assertIn("bad field", res["error"])

    def test_issue_not_found(self):
        http = MagicMock()
        http.post.side_effect = [
            _mock_response(json_body={"access_token": "tok", "expires_in": 3600}),
            _mock_response(json_body={"data": {"issuesV2": {"nodes": []}}}),
        ]
        res = self._service(http).get_issue_details("missing")
        self.assertIn("not found", res["error"])

    def test_summary(self):
        http = MagicMock()
        http.post.side_effect = [
            _mock_response(json_body={"access_token": "tok", "expires_in": 3600}),
            _mock_response(json_body={"data": {
                "total": {"totalCount": 10}, "critical": {"totalCount": 2},
                "high": {"totalCount": 3}, "medium": {"totalCount": 4},
                "low": {"totalCount": 1}, "informational": {"totalCount": 0},
            }}),
        ]
        res = self._service(http).get_issues_summary()
        self.assertEqual(res["total_issues"], 10)
        self.assertEqual(res["severity_breakdown"]["CRITICAL"], 2)
        self.assertEqual(res["filters_applied"]["status"], ["OPEN", "IN_PROGRESS"])

    def test_read_query_rejects_mutations(self):
        http = MagicMock()
        service = self._service(http)
        res = service.execute_read_query("mutation { updateIssue(input: {}) { issue { id } } }")
        self.assertIn("error", res)
        http.post.assert_not_called()

        # The word 'mutation' inside a string literal is allowed
        http.post.side_effect = [
            _mock_response(json_body={"access_token": "tok", "expires_in": 3600}),
            _mock_response(json_body={"data": {"issuesV2": {"nodes": []}}}),
        ]
        res_ok = service.execute_read_query(
            'query { issuesV2(filterBy: {search: "mutation"}) { nodes { id } } }'
        )
        self.assertNotIn("error", res_ok)


class TestHttpEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

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
        self.assertIn("/mcp", data["mcp_streamable_endpoint"])

    def test_mcp_streamable_http(self):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "gemini-enterprise", "version": "1.0"},
            },
        }
        # Test /mcp (endpoint used by Gemini Enterprise)
        res_mcp = self.client.post("/mcp", json=payload)
        self.assertEqual(res_mcp.status_code, 200)
        self.assertIn("protocolVersion", res_mcp.text)

        # Test POST / (root)
        res_root = self.client.post("/", json=payload)
        self.assertEqual(res_root.status_code, 200)

        # Test POST /sse (fallback)
        res_sse = self.client.post("/sse", json=payload)
        self.assertEqual(res_sse.status_code, 200)

    def test_http_methods_compatibility_no_405(self):
        """Verify Gemini Enterprise preflight and lifecycle requests (OPTIONS, DELETE, HEAD) do not 405."""
        for path in ["/mcp", "/"]:
            # Preflight OPTIONS
            res_options = self.client.options(path)
            self.assertEqual(res_options.status_code, 204)
            self.assertEqual(res_options.headers.get("access-control-allow-origin"), "*")

            # Session termination DELETE
            res_delete = self.client.delete(path)
            self.assertEqual(res_delete.status_code, 200)
            self.assertEqual(res_delete.json(), {"status": "session terminated"})

            # Liveness / probe HEAD
            res_head = self.client.head(path)
            self.assertEqual(res_head.status_code, 200)

    def test_mcp_tools_list(self):
        """Verify tools/list works over /mcp with standard JSON Accept header."""
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        res = self.client.post(
            "/mcp",
            json=payload,
            headers={"Accept": "application/json"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("list_codemender_issues", res.text)
        self.assertIn("list_wiz_issues", res.text)
        self.assertIn("get_wiz_issue_details", res.text)


if __name__ == "__main__":
    unittest.main()
