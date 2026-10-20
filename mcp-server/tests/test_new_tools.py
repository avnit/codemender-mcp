try:  # install stubs for missing Google Cloud libraries before other imports
    import _stubs  # noqa: F401
except ImportError:  # pragma: no cover - when imported as a package (pytest)
    from tests import _stubs  # noqa: F401

import asyncio
import json
import unittest
from unittest.mock import MagicMock, patch

import httpx

import server
from config import settings
from services.sandbox_service import SandboxService
from services.security_data_service import SecurityDataService
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
    return WizService(client_id="cid", client_secret="secret",
                      api_endpoint="https://api.test.app.wiz.io/graphql", http_client=http)


def _unconfigured_wiz():
    w = WizService(http_client=MagicMock())
    w.client_id = w.client_secret = w.api_endpoint = None
    return w


def _gql_payloads(http):
    """GraphQL request payloads sent through http.post (skipping the auth call)."""
    return [c.kwargs["json"] for c in http.post.call_args_list if "json" in c.kwargs]


# ----------------------------------------------------------------------
# Wiz: internet-facing vulnerabilities
# ----------------------------------------------------------------------

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
            {"id": "v1", "name": "CVE-1", "vendorSeverity": "CRITICAL", "score": 9.0, "hasExploit": False,
             "vulnerableAsset": {"id": "a1", "hasWideInternetExposure": True}},
            {"id": "v2", "name": "CVE-2", "vendorSeverity": "CRITICAL", "score": 9.8, "hasExploit": True,
             "vulnerableAsset": {"id": "a2", "hasWideInternetExposure": True}},
            {"id": "v3", "name": "CVE-3", "vendorSeverity": "CRITICAL", "score": 10.0, "hasExploit": True,
             "vulnerableAsset": {"id": "a3", "hasWideInternetExposure": False, "hasLimitedInternetExposure": False}},
        ]
        http = MagicMock()
        http.post.side_effect = [AUTH, _resp(json_body={"data": {"vulnerabilityFindings": {"totalCount": 3, "nodes": nodes}}})]
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


# ----------------------------------------------------------------------
# Wiz: identities with excessive permissions
# ----------------------------------------------------------------------

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
        body = {"data": {
            "admin": {"nodes": [{"entities": [
                {"id": "sa1", "name": "payment-service-sa", "type": "SERVICE_ACCOUNT",
                 "properties": json.dumps({"hasAdminPrivileges": True, "cloudPlatform": "GCP"})}]}]},
            "high": {"nodes": [{"entities": [
                {"id": "sa1", "name": "payment-service-sa", "type": "SERVICE_ACCOUNT", "properties": {}},
                {"id": "sa2", "name": "other-sa", "type": "SERVICE_ACCOUNT",
                 "properties": {"hasHighPrivileges": True}}]}]},
        }}
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


# ----------------------------------------------------------------------
# Wiz: code-to-cloud
# ----------------------------------------------------------------------

class TestWizCodeToCloud(unittest.TestCase):

    def test_filter_choice(self):
        self.assertEqual(WizService.build_code_to_cloud_filter("abc-123"), {"id": ["abc-123"]})
        rid = "//run.googleapis.com/projects/p/locations/us-central1/services/payment-service"
        self.assertEqual(WizService.build_code_to_cloud_filter(rid), {"providerUniqueId": [rid]})

    def test_extract_code_origin_from_oci_label(self):
        origin = WizService.extract_code_origin({
            "imageDigest": "sha256:abc",
            "imageLabels": [{"key": "org.opencontainers.image.source",
                             "value": "https://github.com/your-github-org/payment-service"}],
        })
        self.assertEqual(origin["image_digest"], "sha256:abc")
        self.assertEqual(origin["repository"], "https://github.com/your-github-org/payment-service")

    def test_extract_code_origin_label_strings(self):
        origin = WizService.extract_code_origin({"labels": ["org.opencontainers.image.source=https://x/y"]})
        self.assertEqual(origin["repository"], "https://x/y")

    def test_trace_by_issue(self):
        issue_body = {"data": {"issuesV2": {"nodes": [{"id": "wiz-issue-0001", "entitySnapshot": {
            "id": "e1", "providerId": "//run.googleapis.com/projects/p/locations/r/services/payment-service"}}]}}}
        res_body = {"data": {"cloudResources": {"nodes": [{"id": "r1", "name": "payment-service",
            "graphEntity": {"properties": json.dumps({"imageDigest": "sha256:1", "imageLabels": {
                "org.opencontainers.image.source": "https://github.com/your-github-org/payment-service"}})}}]}}}
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


# ----------------------------------------------------------------------
# BigQuery security data
# ----------------------------------------------------------------------

class TestSecurityDataService(unittest.TestCase):

    def setUp(self):
        self.svc = SecurityDataService(project_id="test-project")
        self.client = MagicMock()
        self.client.project = "test-project"
        self.client.query.return_value.result.return_value = [{"a": 1}]
        self.svc._client = self.client

    def _call(self):
        args, kwargs = self.client.query.call_args
        sql = args[0]
        params = {p.name: p.value for p in kwargs["job_config"].query_parameters}
        return sql, params

    def test_scc_parameters(self):
        res = self.svc.query_scc_findings(severity="high", category="OPEN_FIREWALL", project="my-proj", days=3, limit=10)
        self.assertEqual(res["row_count"], 1)
        sql, params = self._call()
        self.assertEqual(params, {"days": 3, "limit": 10, "severity": "HIGH", "state": "ACTIVE",
                                  "category": "OPEN_FIREWALL", "project": "my-proj"})
        for token in ("@severity", "@state", "@category", "@project", "@days", "@limit"):
            self.assertIn(token, sql)
        self.assertNotIn("OPEN_FIREWALL", sql)
        self.assertNotIn("my-proj", sql)
        self.assertIn("`test-project.scc_export.findings`", sql)

    def test_scc_validation(self):
        self.assertIn("Invalid severity", self.svc.query_scc_findings(severity="URGENT")["error"])
        self.assertIn("Invalid state", self.svc.query_scc_findings(state="OPENISH")["error"])
        self.assertIn("Invalid category", self.svc.query_scc_findings(category="x'; DROP TABLE t;--")["error"])
        self.client.query.assert_not_called()

    def test_limits_and_days_clamped(self):
        self.svc.query_security_events(days=10000, limit=10000)
        _, params = self._call()
        self.assertEqual(params["days"], settings.max_lookback_days)
        self.assertEqual(params["limit"], settings.max_query_limit)
        self.svc.query_security_events(days=0, limit=0)
        _, params = self._call()
        self.assertEqual(params["days"], 1)
        self.assertEqual(params["limit"], 1)

    def test_model_armor(self):
        self.svc.query_model_armor_logs(match_state="match_found", filter_type="PI_AND_JAILBREAK")
        sql, params = self._call()
        self.assertEqual(params["match_state"], "MATCH_FOUND")
        self.assertEqual(params["filter_type"], "pi_and_jailbreak")
        self.assertIn("@filter_type", sql)
        self.assertIn("modelarmor_googleapis_com_sanitize_operations", sql)
        self.assertIn("Invalid match_state", self.svc.query_model_armor_logs(match_state="YES")["error"])
        self.assertIn("Invalid filter_type", self.svc.query_model_armor_logs(filter_type="pii")["error"])

    def test_vpcsc(self):
        self.svc.query_vpcsc_violations(perimeter="lab_perimeter", principal="Alice@Example.com",
                                        service="storage.googleapis.com")
        sql, params = self._call()
        self.assertEqual(params["perimeter"], "%lab_perimeter%")
        self.assertEqual(params["principal"], "Alice@Example.com")
        self.assertEqual(params["service"], "storage.googleapis.com")
        self.assertNotIn("Alice@Example.com", sql)
        self.assertIn("violationReason", sql)
        self.assertIn("Invalid principal", self.svc.query_vpcsc_violations(principal="a' OR '1'='1")["error"])
        self.assertIn("Invalid service", self.svc.query_vpcsc_violations(service="Storage Service")["error"])
        self.assertIn("Invalid perimeter", self.svc.query_vpcsc_violations(perimeter="p;drop")["error"])

    def test_security_events(self):
        self.svc.query_security_events(event_type="sandbox_result", severity="error", issue_id="CM-0001")
        sql, params = self._call()
        self.assertEqual(params["event_type"], "SANDBOX_RESULT")
        self.assertEqual(params["severity"], "ERROR")
        self.assertEqual(params["issue_id"], "CM-0001")
        self.assertNotIn("CM-0001", sql)
        self.assertIn("`test-project.security_lab.security_events`", sql)
        self.assertIn("Invalid event_type", self.svc.query_security_events(event_type="HACK")["error"])
        self.assertIn("Invalid severity", self.svc.query_security_events(severity="LOUD")["error"])
        self.assertIn("Invalid issue_id", self.svc.query_security_events(issue_id="CM 1; --")["error"])

    def test_code_to_cloud_and_finding_lookup(self):
        self.assertIn("Provide", self.svc.get_code_to_cloud()["error"])
        self.svc.get_code_to_cloud(repository="your-github-org/payment-service")
        sql, params = self._call()
        self.assertEqual(params["repository"], "%your-github-org/payment-service")
        self.assertIn("code_to_cloud_map", sql)
        self.svc.get_finding_repository("CM-0003")
        sql, params = self._call()
        self.assertEqual(params["issue_id"], "CM-0003")
        self.assertIn("wiz_issue_id = @issue_id", sql)
        self.assertIn("Invalid repository", self.svc.get_code_to_cloud(repository="not a repo")["error"])

    def test_sandbox_run_lookup(self):
        self.assertIn("Provide", self.svc.get_sandbox_run()["error"])
        self.svc.get_sandbox_run(execution_name="projects/p/locations/r/jobs/j/executions/codemender-sandbox-abc")
        sql, params = self._call()
        self.assertEqual(params["execution_name"], "codemender-sandbox-abc")
        self.assertIn("sandbox_runs", sql)

    def test_query_errors_become_error_dicts(self):
        from google.cloud.exceptions import NotFound
        self.client.query.side_effect = NotFound("missing")
        self.assertIn("not found", self.svc.query_security_events()["error"])
        self.client.query.side_effect = RuntimeError("boom")
        self.assertEqual(self.svc.query_security_events()["error"], "boom")


# ----------------------------------------------------------------------
# Sandbox Cloud Run Job
# ----------------------------------------------------------------------

class _Creds:
    valid = True
    token = "gcp-token"


VALID = dict(repository="your-github-org/payment-service", commit_sha="abc1234",
             patch_uri="gs://lab-bucket/patches/CM-0001/run-1.diff", issue_id="CM-0001")


class TestSandboxService(unittest.TestCase):

    def _svc(self, http=None):
        return SandboxService(project_id="test-project", region="us-central1", job_name="codemender-sandbox",
                              bucket="lab-bucket", http_client=http or MagicMock(), credentials=_Creds())

    def test_confirmation_required(self):
        http = MagicMock()
        res = self._svc(http).start_validation(**VALID, confirmed=False)
        self.assertEqual(res["error"], "confirmation_required")
        self.assertEqual(res["planned_run"]["source_uri"],
                         "gs://lab-bucket/sources/your-github-org__payment-service/abc1234.tar.gz")
        http.request.assert_not_called()

    def test_validation(self):
        svc = self._svc()
        cases = [
            (dict(VALID, repository="payment-service"), "Invalid repository"),
            (dict(VALID, repository="org/../etc"), "Invalid repository"),
            (dict(VALID, commit_sha="abc12"), "Invalid commit_sha"),
            (dict(VALID, commit_sha="g" * 40), "Invalid commit_sha"),
            (dict(VALID, commit_sha="a" * 41), "Invalid commit_sha"),
            (dict(VALID, patch_uri="https://evil.example/p.diff"), "Invalid patch_uri"),
            (dict(VALID, patch_uri="gs://other-bucket/p.diff"), "sandbox inputs bucket"),
            (dict(VALID, patch_uri=""), "patch_uri is required"),
            (dict(VALID, issue_id="CM 0001"), "Invalid issue_id"),
        ]
        for kwargs, msg in cases:
            res = svc.start_validation(**kwargs, confirmed=True)
            self.assertIn(msg, res["error"], kwargs)
        res = svc.start_validation(**VALID, poc_test="../secrets", confirmed=True)
        self.assertIn("Invalid poc_test", res["error"])

    def test_patch_none_allowed(self):
        res = self._svc().start_validation(**dict(VALID, patch_uri="none"))
        self.assertEqual(res["error"], "confirmation_required")

    def test_run_job_with_overrides(self):
        http = MagicMock()
        http.request.return_value = _resp(json_body={
            "name": "projects/test-project/locations/us-central1/operations/op-1",
            "metadata": {"name": "projects/test-project/locations/us-central1/jobs/codemender-sandbox/executions/codemender-sandbox-x7k2p"},
        })
        res = self._svc(http).start_validation(**dict(VALID, commit_sha="ABC1234"), poc_test="tests/poc", confirmed=True)
        self.assertEqual(res["status"], "STARTED")
        self.assertEqual(res["execution_name"], "codemender-sandbox-x7k2p")
        self.assertTrue(res["run_id"].startswith("run-"))
        args, kwargs = http.request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "https://run.googleapis.com/v2/projects/test-project/locations/us-central1/jobs/codemender-sandbox:run")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer gcp-token")
        env = {e["name"]: e["value"] for e in kwargs["json"]["overrides"]["containerOverrides"][0]["env"]}
        self.assertEqual(set(env), {"RUN_ID", "REPOSITORY", "COMMIT_SHA", "SOURCE_URI", "PATCH_URI", "ISSUE_ID", "POC_TEST"})
        self.assertEqual(env["RUN_ID"], res["run_id"])
        self.assertEqual(env["COMMIT_SHA"], "abc1234")
        self.assertEqual(env["SOURCE_URI"], "gs://lab-bucket/sources/your-github-org__payment-service/abc1234.tar.gz")
        self.assertEqual(env["PATCH_URI"], VALID["patch_uri"])

    def test_run_job_http_error(self):
        http = MagicMock()
        http.request.return_value = _resp(status_code=403, json_body={"error": "denied"})
        res = self._svc(http).start_validation(**VALID, confirmed=True)
        self.assertIn("Cloud Run API HTTP 403", res["error"])

    def test_not_configured(self):
        svc = SandboxService(project_id=None, bucket=None, http_client=MagicMock(), credentials=_Creds())
        svc.project_id = None
        svc.bucket = None
        self.assertIn("not configured", svc.start_validation(**VALID, confirmed=True)["error"])
        self.assertIn("not configured", svc.get_execution("codemender-sandbox-abc")["error"])

    def test_get_execution(self):
        http = MagicMock()
        http.request.return_value = _resp(json_body={
            "name": "projects/test-project/locations/us-central1/jobs/codemender-sandbox/executions/codemender-sandbox-abc",
            "completionTime": "2026-10-20T10:00:00Z", "succeededCount": 1, "logUri": "https://console/logs",
            "conditions": [{"type": "Completed", "state": "CONDITION_SUCCEEDED"}],
        })
        res = self._svc(http).get_execution("codemender-sandbox-abc")
        self.assertEqual(res["state"], "SUCCEEDED")
        self.assertEqual(res["execution_name"], "codemender-sandbox-abc")
        args, _ = http.request.call_args
        self.assertEqual(args, ("GET", "https://run.googleapis.com/v2/projects/test-project/locations/us-central1/jobs/codemender-sandbox/executions/codemender-sandbox-abc"))

    def test_get_execution_invalid_name(self):
        http = MagicMock()
        self.assertIn("Invalid execution_name", self._svc(http).get_execution("../../etc")["error"])
        self.assertIn("Invalid execution_name", self._svc(http).get_execution("projects/p/x")["error"])
        http.request.assert_not_called()

    def test_summarize_states(self):
        self.assertEqual(SandboxService.summarize_execution({"runningCount": 1})["state"], "RUNNING")
        self.assertEqual(SandboxService.summarize_execution({})["state"], "PENDING")
        self.assertEqual(SandboxService.summarize_execution({"completionTime": "t", "failedCount": 1})["state"], "FAILED")

    def test_find_execution_by_run_id(self):
        http = MagicMock()
        http.request.return_value = _resp(json_body={"executions": [
            {"name": "projects/p/locations/r/jobs/j/executions/e1",
             "template": {"containers": [{"env": [{"name": "RUN_ID", "value": "run-other"}]}]}},
            {"name": "projects/p/locations/r/jobs/j/executions/e2", "runningCount": 1,
             "template": {"containers": [{"env": [{"name": "RUN_ID", "value": "run-1"}]}]}},
        ]})
        res = self._svc(http).find_execution_by_run_id("run-1")
        self.assertEqual(res["execution_name"], "e2")
        self.assertEqual(res["state"], "RUNNING")
        self.assertIn("Invalid run_id", self._svc(http).find_execution_by_run_id("run 1;")["error"])


# ----------------------------------------------------------------------
# Server tools (orchestration)
# ----------------------------------------------------------------------

class TestServerTools(unittest.TestCase):

    def test_trace_code_to_cloud_uses_wiz_when_found(self):
        wiz_res = {"found": True, "source": "wiz", "repository": "https://github.com/o/r"}
        with patch.object(server.wiz_service, "trace_code_to_cloud", return_value=wiz_res), \
                patch.object(server.security_data_service, "get_code_to_cloud") as bq:
            self.assertEqual(server.trace_code_to_cloud(issue_id="wiz-issue-0001"), wiz_res)
            bq.assert_not_called()

    def test_trace_code_to_cloud_falls_back_to_bigquery(self):
        rows = [{"resource_id": "//run.googleapis.com/x", "repository": "your-github-org/payment-service"}]
        with patch.object(server.wiz_service, "trace_code_to_cloud",
                          return_value={"found": False, "source": "wiz", "reason": "Wiz issue 'CM-0003' not found."}), \
                patch.object(server.security_data_service, "get_finding_repository",
                             return_value={"data": [{"finding_id": "CM-0003", "repository": "your-github-org/payment-service"}]}) as fr, \
                patch.object(server.security_data_service, "get_code_to_cloud",
                             return_value={"data": rows, "filters_applied": {}}) as bq:
            res = server.trace_code_to_cloud(issue_id="CM-0003")
        fr.assert_called_once_with("CM-0003")
        bq.assert_called_once_with(resource_id=None, repository="your-github-org/payment-service")
        self.assertEqual(res["source"], "bigquery")
        self.assertTrue(res["found"])
        self.assertEqual(res["mappings"], rows)
        self.assertIn("not found", res["wiz_status"])

    def test_trace_code_to_cloud_fallback_when_wiz_not_configured(self):
        with patch.object(server.wiz_service, "trace_code_to_cloud", return_value={"error": "Wiz integration is not configured."}), \
                patch.object(server.security_data_service, "get_code_to_cloud", return_value={"data": []}) as bq:
            res = server.trace_code_to_cloud(resource_id="//run.googleapis.com/projects/p/locations/r/services/s")
        bq.assert_called_once_with(resource_id="//run.googleapis.com/projects/p/locations/r/services/s", repository=None)
        self.assertFalse(res["found"])
        self.assertIn("not configured", res["wiz_status"])

    def test_trace_code_to_cloud_requires_input(self):
        self.assertIn("Provide", server.trace_code_to_cloud()["error"])

    def test_start_sandbox_validation_requires_confirmation(self):
        svc = SandboxService(project_id="p", region="us-central1", job_name="codemender-sandbox",
                             bucket="lab-bucket", http_client=MagicMock(), credentials=_Creds())
        with patch.object(server, "sandbox_service", svc):
            res = server.start_sandbox_validation(**VALID)
        self.assertEqual(res["error"], "confirmation_required")
        svc.http.request.assert_not_called()

    def test_start_sandbox_validation_docstring(self):
        doc = server.start_sandbox_validation.__doc__
        self.assertIn("ACTION TOOL", doc)
        self.assertIn("explicit user confirmation", doc)

    def test_get_sandbox_result(self):
        row = {"run_id": "run-1", "execution_name": "codemender-sandbox-abc", "verdict": "PATCH_VERIFIED"}
        with patch.object(server.security_data_service, "get_sandbox_run", return_value={"data": [row]}), \
                patch.object(server.sandbox_service, "get_execution", return_value={"state": "SUCCEEDED"}) as ge:
            res = server.get_sandbox_result(run_id="run-1")
        ge.assert_called_once_with("codemender-sandbox-abc")
        self.assertEqual(res["verdict"], "PATCH_VERIFIED")
        self.assertEqual(res["execution"]["state"], "SUCCEEDED")

    def test_get_sandbox_result_before_ingestion(self):
        with patch.object(server.security_data_service, "get_sandbox_run", return_value={"data": []}), \
                patch.object(server.sandbox_service, "find_execution_by_run_id",
                             return_value={"state": "RUNNING", "execution_name": "codemender-sandbox-abc"}):
            res = server.get_sandbox_result(run_id="run-1")
        self.assertIsNone(res["verdict"])
        self.assertEqual(res["execution_name"], "codemender-sandbox-abc")
        self.assertTrue(res["notes"])
        self.assertIn("Provide", server.get_sandbox_result()["error"])

    def test_pass_through_tools(self):
        with patch.object(server.wiz_service, "top_internet_facing_vulnerabilities", return_value={"ok": 1}) as m:
            server.wiz_top_internet_facing_vulnerabilities(project="p1")
            m.assert_called_once_with(environment="production", project="p1", severity="CRITICAL", limit=5)
        with patch.object(server.wiz_service, "excessive_permission_identities", return_value={}) as m:
            server.wiz_excessive_permission_identities(service="payment-service")
            m.assert_called_once_with(service="payment-service", project=None, limit=25)
        for tool, method in [
            (server.query_scc_findings, "query_scc_findings"),
            (server.query_model_armor_logs, "query_model_armor_logs"),
            (server.query_vpcsc_violations, "query_vpcsc_violations"),
            (server.query_security_events, "query_security_events"),
        ]:
            with patch.object(server.security_data_service, method, return_value={"row_count": 0}) as m:
                self.assertEqual(tool(), {"row_count": 0})
                m.assert_called_once()

    def test_tools_and_prompt_registered(self):
        names = {t.name for t in asyncio.run(server.mcp.list_tools())}
        for name in ["wiz_top_internet_facing_vulnerabilities", "wiz_excessive_permission_identities",
                     "trace_code_to_cloud", "query_scc_findings", "query_model_armor_logs",
                     "query_vpcsc_violations", "query_security_events", "start_sandbox_validation",
                     "get_sandbox_result", "list_codemender_issues", "query_wiz_graphql"]:
            self.assertIn(name, names)
        prompts = {p.name for p in asyncio.run(server.mcp.list_prompts())}
        self.assertIn("remediate_wiz_issue", prompts)
        text = server.remediate_wiz_issue("wiz-issue-0001")
        self.assertIn("trace_code_to_cloud(issue_id='wiz-issue-0001')", text)
        self.assertIn("confirmed=True", text)


if __name__ == "__main__":
    unittest.main()
