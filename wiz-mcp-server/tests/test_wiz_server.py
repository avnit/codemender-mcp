import asyncio
import json
import unittest
from unittest.mock import MagicMock, patch

import httpx
from starlette.testclient import TestClient

import server
from services.wiz_service import (
    CODE_TO_CLOUD_QUERY,
    EXCESSIVE_IDENTITIES_QUERY,
    ISSUE_ENTITY_QUERY,
    TOP_VULNS_QUERY,
    WizService,
)


def _resp(status_code=200, json_body=None, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_body if json_body is not None else {}
    r.text = text or json.dumps(json_body or {})
    r.content = r.text.encode()
    if status_code >= 400:
        req = httpx.Request("POST", "https://example.test")
        r.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=req, response=httpx.Response(status_code, text=r.text, request=req)
        )
    else:
        r.raise_for_status.return_value = None
    return r


AUTH = _resp(json_body={"access_token": "tok", "expires_in": 3600})


def _wiz(http):
    return WizService(
        client_id="cid",
        client_secret="secret",
        api_endpoint="https://api.test.app.wiz.io/graphql",
        http_client=http,
    )


def _unconfigured_wiz():
    w = WizService(http_client=MagicMock())
    w.client_id = w.client_secret = w.api_endpoint = None
    return w


def _gql_payloads(http):
    """GraphQL request payloads sent through http.post (skipping the auth call)."""
    return [c.kwargs["json"] for c in http.post.call_args_list if "json" in c.kwargs]


class TestWizService(unittest.TestCase):
    def test_not_configured(self):
        res = _unconfigured_wiz().list_issues()
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
        res = _wiz(MagicMock()).list_issues(severity="SUPER_BAD")
        self.assertIn("Invalid severity", res["error"])

    def test_list_issues_auth_and_query(self):
        http = MagicMock()
        http.post.side_effect = [
            _resp(json_body={"access_token": "tok", "expires_in": 3600}),
            _resp(
                json_body={
                    "data": {
                        "issuesV2": {
                            "totalCount": 1,
                            "pageInfo": {"hasNextPage": False, "endCursor": "c1"},
                            "nodes": [{"id": "wiz-1", "severity": "CRITICAL", "status": "OPEN"}],
                        }
                    }
                }
            ),
        ]
        res = _wiz(http).list_issues(severity="CRITICAL", limit=5)

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
            _resp(json_body={"access_token": "tok", "expires_in": 3600}),
            _resp(json_body=gql),
            _resp(json_body=gql),
        ]
        service = _wiz(http)
        service.list_issues()
        service.list_issues()
        self.assertEqual(http.post.call_count, 3)

    def test_graphql_errors_returned(self):
        http = MagicMock()
        http.post.side_effect = [
            _resp(json_body={"access_token": "tok", "expires_in": 3600}),
            _resp(json_body={"errors": [{"message": "bad field"}]}),
        ]
        res = _wiz(http).get_issue_details("wiz-1")
        self.assertIn("bad field", res["error"])

    def test_issue_not_found(self):
        http = MagicMock()
        http.post.side_effect = [
            _resp(json_body={"access_token": "tok", "expires_in": 3600}),
            _resp(json_body={"data": {"issuesV2": {"nodes": []}}}),
        ]
        res = _wiz(http).get_issue_details("missing")
        self.assertIn("not found", res["error"])

    def test_summary(self):
        http = MagicMock()
        http.post.side_effect = [
            _resp(json_body={"access_token": "tok", "expires_in": 3600}),
            _resp(
                json_body={
                    "data": {
                        "total": {"totalCount": 10},
                        "critical": {"totalCount": 2},
                        "high": {"totalCount": 3},
                        "medium": {"totalCount": 4},
                        "low": {"totalCount": 1},
                        "informational": {"totalCount": 0},
                    }
                }
            ),
        ]
        res = _wiz(http).get_issues_summary()
        self.assertEqual(res["total_issues"], 10)
        self.assertEqual(res["severity_breakdown"]["CRITICAL"], 2)
        self.assertEqual(res["filters_applied"]["status"], ["OPEN", "IN_PROGRESS"])

    def test_read_query_rejects_mutations(self):
        http = MagicMock()
        service = _wiz(http)
        res = service.execute_read_query("mutation { updateIssue(input: {}) { issue { id } } }")
        self.assertIn("error", res)
        http.post.assert_not_called()

        http.post.side_effect = [
            _resp(json_body={"access_token": "tok", "expires_in": 3600}),
            _resp(json_body={"data": {"issuesV2": {"nodes": []}}}),
        ]
        res_ok = service.execute_read_query(
            'query { issuesV2(filterBy: {search: "mutation"}) { nodes { id } } }'
        )
        self.assertNotIn("error", res_ok)


class TestWizTopVulnerabilities(unittest.TestCase):
    def test_variables_construction(self):
        v = WizService.build_vulnerability_variables("production", "proj-123", "critical,high", 5)
        fb = v["filterBy"]
        self.assertEqual(fb["vendorSeverity"], ["CRITICAL", "HIGH"])
        self.assertEqual(fb["status"], ["OPEN"])
        self.assertTrue(fb["hasWideInternetExposure"])
        self.assertEqual(fb["environment"], ["PRODUCTION"])
        self.assertEqual(fb["projectId"], ["proj-123"])
        self.assertEqual(v["first"], 20)
        self.assertEqual(v["_limit"], 5)

    def test_no_environment_or_project(self):
        v = WizService.build_vulnerability_variables("", None, None, 5)
        self.assertNotIn("environment", v["filterBy"])
        self.assertNotIn("projectId", v["filterBy"])
        self.assertEqual(v["filterBy"]["vendorSeverity"], ["CRITICAL"])

    def test_limit_clamped(self):
        self.assertEqual(WizService.build_vulnerability_variables(limit=0)["_limit"], 1)
        big = WizService.build_vulnerability_variables(limit=999)
        self.assertEqual(big["_limit"], 50)
        self.assertEqual(big["first"], 100)

    def test_invalid_inputs(self):
        w = _wiz(MagicMock())
        self.assertIn("Invalid severity", w.top_internet_facing_vulnerabilities(severity="SUPER")["error"])
        self.assertIn("Invalid environment", w.top_internet_facing_vulnerabilities(environment="prod!")["error"])
        self.assertIn("Invalid project", w.top_internet_facing_vulnerabilities(project="a b")["error"])

    def test_not_configured(self):
        res = _unconfigured_wiz().top_internet_facing_vulnerabilities()
        self.assertIn("not configured", res["error"])

    def test_query_ranking_and_exposure_filter(self):
        nodes = [
            {
                "id": "v1",
                "name": "CVE-1",
                "vendorSeverity": "CRITICAL",
                "score": 9.0,
                "hasExploit": False,
                "vulnerableAsset": {"id": "a1", "hasWideInternetExposure": True},
            },
            {
                "id": "v2",
                "name": "CVE-2",
                "vendorSeverity": "CRITICAL",
                "score": 9.8,
                "hasExploit": True,
                "vulnerableAsset": {"id": "a2", "hasWideInternetExposure": True},
            },
            {
                "id": "v3",
                "name": "CVE-3",
                "vendorSeverity": "CRITICAL",
                "score": 10.0,
                "hasExploit": True,
                "vulnerableAsset": {"id": "a3", "hasWideInternetExposure": False, "hasLimitedInternetExposure": False},
            },
        ]
        http = MagicMock()
        http.post.side_effect = [
            AUTH,
            _resp(json_body={"data": {"vulnerabilityFindings": {"totalCount": 3, "nodes": nodes}}}),
        ]
        res = _wiz(http).top_internet_facing_vulnerabilities(limit=2)
        self.assertEqual(res["source"], "wiz")
        self.assertEqual([v["cve"] for v in res["vulnerabilities"]], ["CVE-2", "CVE-1"])
        self.assertEqual(res["vulnerabilities"][0]["asset"]["internet_exposure"], "wide")
        payload = _gql_payloads(http)[0]
        self.assertEqual(payload["query"], TOP_VULNS_QUERY)
        self.assertEqual(payload["variables"]["first"], 8)
        self.assertNotIn("_limit", payload["variables"])

    def test_graphql_error_returns_error_dict(self):
        http = MagicMock()
        http.post.side_effect = [AUTH, _resp(json_body={"errors": [{"message": "Cannot query field"}]})]
        res = _wiz(http).top_internet_facing_vulnerabilities()
        self.assertIn("Cannot query field", res["error"])


class TestWizExcessiveIdentities(unittest.TestCase):
    def test_variables_construction(self):
        v = WizService.build_identity_variables(service="payment-service", project=None, limit=10)
        self.assertEqual(v["projectId"], "*")
        self.assertEqual(v["first"], 10)
        self.assertEqual(v["adminQuery"]["where"]["hasAdminPrivileges"], {"EQUALS": [True]})
        self.assertEqual(v["highQuery"]["where"]["hasHighPrivileges"], {"EQUALS": [True]})
        self.assertEqual(v["adminQuery"]["where"]["name"], {"CONTAINS": ["payment-service"]})
        self.assertIn("SERVICE_ACCOUNT", v["adminQuery"]["type"])

    def test_project_and_limit(self):
        v = WizService.build_identity_variables(project="proj-1", limit=5000)
        self.assertEqual(v["projectId"], "proj-1")
        self.assertEqual(v["first"], 100)
        self.assertNotIn("name", v["adminQuery"]["where"])

    def test_invalid_inputs(self):
        w = _wiz(MagicMock())
        self.assertIn("Invalid service", w.excessive_permission_identities(service="x' OR 1=1")["error"])
        self.assertIn("Invalid project", w.excessive_permission_identities(project="bad project")["error"])

    def test_not_configured(self):
        self.assertIn("not configured", _unconfigured_wiz().excessive_permission_identities()["error"])

    def test_merge_and_dedupe(self):
        body = {
            "data": {
                "admin": {
                    "nodes": [
                        {
                            "entities": [
                                {
                                    "id": "sa1",
                                    "name": "payment-service-sa",
                                    "type": "SERVICE_ACCOUNT",
                                    "properties": json.dumps({"hasAdminPrivileges": True, "cloudPlatform": "GCP"}),
                                }
                            ]
                        }
                    ]
                },
                "high": {
                    "nodes": [
                        {
                            "entities": [
                                {"id": "sa1", "name": "payment-service-sa", "type": "SERVICE_ACCOUNT", "properties": {}},
                                {
                                    "id": "sa2",
                                    "name": "other-sa",
                                    "type": "SERVICE_ACCOUNT",
                                    "properties": {"hasHighPrivileges": True},
                                },
                            ]
                        }
                    ]
                },
            }
        }
        http = MagicMock()
        http.post.side_effect = [AUTH, _resp(json_body=body)]
        res = _wiz(http).excessive_permission_identities(service="sa")
        self.assertEqual(res["returned"], 2)
        first = res["identities"][0]
        self.assertEqual(first["id"], "sa1")
        self.assertTrue(first["has_admin_privileges"])
        self.assertTrue(first["has_high_privileges"])
        self.assertEqual(first["cloud_platform"], "GCP")
        payload = _gql_payloads(http)[0]
        self.assertEqual(payload["query"], EXCESSIVE_IDENTITIES_QUERY)
        self.assertEqual(payload["variables"]["projectId"], "*")


class TestWizCodeToCloud(unittest.TestCase):
    def test_filter_choice(self):
        self.assertEqual(WizService.build_code_to_cloud_filter("abc-123"), {"id": ["abc-123"]})
        rid = "//run.googleapis.com/projects/p/locations/us-central1/services/payment-service"
        self.assertEqual(WizService.build_code_to_cloud_filter(rid), {"providerUniqueId": [rid]})

    def test_extract_code_origin_from_oci_label(self):
        origin = WizService.extract_code_origin(
            {
                "imageDigest": "sha256:abc",
                "imageLabels": [
                    {
                        "key": "org.opencontainers.image.source",
                        "value": "https://github.com/your-github-org/payment-service",
                    }
                ],
            }
        )
        self.assertEqual(origin["image_digest"], "sha256:abc")
        self.assertEqual(origin["repository"], "https://github.com/your-github-org/payment-service")

    def test_extract_code_origin_label_strings(self):
        origin = WizService.extract_code_origin({"labels": ["org.opencontainers.image.source=https://x/y"]})
        self.assertEqual(origin["repository"], "https://x/y")

    def test_trace_by_issue(self):
        issue_body = {
            "data": {
                "issuesV2": {
                    "nodes": [
                        {
                            "id": "wiz-issue-0001",
                            "entitySnapshot": {
                                "id": "e1",
                                "providerId": "//run.googleapis.com/projects/p/locations/r/services/payment-service",
                            },
                        }
                    ]
                }
            }
        }
        res_body = {
            "data": {
                "cloudResources": {
                    "nodes": [
                        {
                            "id": "r1",
                            "name": "payment-service",
                            "graphEntity": {
                                "properties": json.dumps(
                                    {
                                        "imageDigest": "sha256:1",
                                        "imageLabels": {
                                            "org.opencontainers.image.source": "https://github.com/your-github-org/payment-service"
                                        },
                                    }
                                )
                            },
                        }
                    ]
                }
            }
        }
        http = MagicMock()
        http.post.side_effect = [AUTH, _resp(json_body=issue_body), _resp(json_body=res_body)]
        res = _wiz(http).trace_code_to_cloud(issue_id="wiz-issue-0001")
        self.assertTrue(res["found"])
        self.assertEqual(res["image_digest"], "sha256:1")
        payloads = _gql_payloads(http)
        self.assertEqual(payloads[0]["query"], ISSUE_ENTITY_QUERY)
        self.assertEqual(payloads[0]["variables"], {"filterBy": {"id": ["wiz-issue-0001"]}})
        self.assertEqual(payloads[1]["query"], CODE_TO_CLOUD_QUERY)
        self.assertIn("providerUniqueId", payloads[1]["variables"]["filterBy"])

    def test_trace_issue_not_found(self):
        http = MagicMock()
        http.post.side_effect = [AUTH, _resp(json_body={"data": {"issuesV2": {"nodes": []}}})]
        res = _wiz(http).trace_code_to_cloud(issue_id="wiz-issue-9999")
        self.assertFalse(res["found"])

    def test_trace_validation_and_not_configured(self):
        w = _wiz(MagicMock())
        self.assertIn("Provide", w.trace_code_to_cloud()["error"])
        self.assertIn("Invalid issue_id", w.trace_code_to_cloud(issue_id="bad id!")["error"])
        self.assertIn("not configured", _unconfigured_wiz().trace_code_to_cloud(resource_id="r1")["error"])


class TestWizServerToolsAndHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(server.app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_tools_and_prompts_registered(self):
        names = {t.name for t in asyncio.run(server.mcp.list_tools())}
        self.assertEqual(
            names,
            {
                "list_wiz_issues",
                "get_wiz_issue_details",
                "get_wiz_issues_summary",
                "query_wiz_graphql",
                "wiz_top_internet_facing_vulnerabilities",
                "wiz_excessive_permission_identities",
                "wiz_trace_code_to_cloud",
            },
        )
        prompts = {p.name for p in asyncio.run(server.mcp.list_prompts())}
        self.assertEqual(prompts, {"triage_wiz_issue", "remediate_wiz_issue"})
        text = server.remediate_wiz_issue("wiz-issue-0001")
        self.assertIn("wiz_trace_code_to_cloud(issue_id='wiz-issue-0001')", text)
        self.assertIn("confirmed=True", text)

    def test_pass_through_tools(self):
        with patch.object(server.wiz_service, "top_internet_facing_vulnerabilities", return_value={"ok": 1}) as m:
            server.wiz_top_internet_facing_vulnerabilities(project="p1")
            m.assert_called_once_with(environment="production", project="p1", severity="CRITICAL", limit=5)
        with patch.object(server.wiz_service, "excessive_permission_identities", return_value={}) as m:
            server.wiz_excessive_permission_identities(service="payment-service")
            m.assert_called_once_with(service="payment-service", project=None, limit=25)
        with patch.object(server.wiz_service, "trace_code_to_cloud", return_value={"found": True}) as m:
            res = server.wiz_trace_code_to_cloud(issue_id="wiz-issue-0001")
            self.assertEqual(res, {"found": True})
            m.assert_called_once_with(issue_id="wiz-issue-0001", resource_id=None)

    def test_health_check_and_security_headers(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "wiz-mcp-server")
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(response.headers.get("x-frame-options"), "DENY")

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["service"], "Wiz Security MCP Server")
        self.assertIn("/mcp", data["mcp_streamable_endpoint"])
        self.assertIn("wiz_trace_code_to_cloud", data["tools"])

    def test_mcp_streamable_http_and_tools_list(self):
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "adk-agent", "version": "1.0"},
            },
        }
        for path in ("/mcp", "/", "/sse"):
            res = self.client.post(path, json=init_payload)
            self.assertEqual(res.status_code, 200)

        list_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        res_tools = self.client.post("/mcp", json=list_payload, headers={"Accept": "application/json"})
        self.assertEqual(res_tools.status_code, 200)
        self.assertIn("list_wiz_issues", res_tools.text)
        self.assertIn("wiz_trace_code_to_cloud", res_tools.text)
        self.assertNotIn("list_codemender_issues", res_tools.text)

    def test_http_methods_compatibility_no_405(self):
        for path in ("/mcp", "/"):
            self.assertEqual(self.client.options(path).status_code, 204)
            self.assertEqual(self.client.delete(path).status_code, 200)
            self.assertEqual(self.client.head(path).status_code, 200)


if __name__ == "__main__":
    unittest.main()
