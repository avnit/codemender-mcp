"""Start and inspect sandbox validation runs on the `codemender-sandbox` Cloud Run Job.

Uses the Cloud Run Admin API v2 over REST (httpx) with Application Default
Credentials from google.auth, so the google-cloud-run package is not needed.

The job runs on the Cloud Run second-generation execution environment with an
egress-denied VPC and a service account that can only read the sandbox inputs
bucket. It cannot reach GitHub; source and patch are read from GCS.
"""

import datetime
import logging
import re
import threading
import uuid
from typing import Any, Dict, List, Optional

import httpx

from config import settings

logger = logging.getLogger(__name__)

RUN_API = "https://run.googleapis.com/v2"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
PATCH_URI_RE = re.compile(r"^gs://([a-z0-9][a-z0-9._\-]{1,220}[a-z0-9])/([A-Za-z0-9_.\-/]{1,1024})$")
ISSUE_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
POC_TEST_RE = re.compile(r"^[A-Za-z0-9_.\-/]{1,256}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
EXECUTION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,127}$")


class SandboxService:
    """Thin client for running and polling the sandbox Cloud Run Job."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        region: Optional[str] = None,
        job_name: Optional[str] = None,
        bucket: Optional[str] = None,
        http_client: Optional[httpx.Client] = None,
        credentials: Any = None,
        timeout: float = 30.0,
    ):
        self.project_id = project_id or settings.gcp_project_id
        self.region = region or settings.effective_sandbox_region
        self.job_name = job_name or settings.sandbox_job_name
        self.bucket = bucket or settings.effective_sandbox_bucket
        self._http = http_client
        self._timeout = timeout
        self._credentials = credentials
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Auth & transport
    # ------------------------------------------------------------------

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=self._timeout)
        return self._http

    @property
    def is_configured(self) -> bool:
        return bool(self.project_id and self.region and self.job_name and self.bucket)

    def _not_configured_error(self) -> Dict[str, Any]:
        return {"error": "Sandbox is not configured. Set GCP_PROJECT_ID (and optionally SANDBOX_REGION, "
                         "SANDBOX_JOB_NAME, SANDBOX_BUCKET)."}

    def _get_credentials_object(self) -> Any:
        with self._lock:
            if self._credentials is None:
                import google.auth

                creds, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
                self._credentials = creds
            return self._credentials

    def _token(self) -> str:
        creds = self._get_credentials_object()
        with self._lock:
            if not getattr(creds, "valid", False) or not getattr(creds, "token", None):
                import google.auth.transport.requests

                creds.refresh(google.auth.transport.requests.Request())
            return creds.token

    def _request(self, method: str, url: str, json_body: Optional[Dict[str, Any]] = None,
                 params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}
        resp = self.http.request(method, url, headers=headers, json=json_body, params=params)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def _run(self, fn, *args, **kwargs) -> Dict[str, Any]:
        """Uniform error handling, same shape as the Wiz service."""
        try:
            return fn(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            logger.exception("Cloud Run API HTTP error: %s", e)
            return {"error": f"Cloud Run API HTTP {e.response.status_code}: {e.response.text[:500]}"}
        except httpx.HTTPError as e:
            logger.exception("Cloud Run API transport error: %s", e)
            return {"error": f"Cloud Run API request failed: {e}"}
        except Exception as e:
            logger.exception("Sandbox service error: %s", e)
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Validation and request construction
    # ------------------------------------------------------------------

    def job_path(self) -> str:
        return f"projects/{self.project_id}/locations/{self.region}/jobs/{self.job_name}"

    def source_uri(self, repository: str, commit_sha: str) -> str:
        owner, name = repository.split("/", 1)
        return f"gs://{self.bucket}/sources/{owner}__{name}/{commit_sha}.tar.gz"

    def validate_inputs(
        self,
        repository: str,
        commit_sha: str,
        patch_uri: str,
        issue_id: str,
        poc_test: str = "tests/poc",
    ) -> Optional[str]:
        """Return an error message, or None when all inputs are valid."""
        if not repository or not REPOSITORY_RE.match(repository) or ".." in repository:
            return "Invalid repository. Use owner/name (e.g. your-github-org/payment-service)."
        if not commit_sha or not COMMIT_SHA_RE.match(commit_sha):
            return "Invalid commit_sha. Use a 7-40 character hex git commit SHA."
        if not patch_uri:
            return "patch_uri is required. Use gs://<sandbox-bucket>/patches/<issue_id>/<run_id>.diff or 'none'."
        if patch_uri != "none":
            m = PATCH_URI_RE.match(patch_uri)
            if not m or ".." in patch_uri:
                return "Invalid patch_uri. Use gs://<bucket>/<path> or 'none'."
            if self.bucket and m.group(1) != self.bucket:
                return (f"patch_uri must be in the sandbox inputs bucket gs://{self.bucket}/. "
                        "The sandbox service account can read only that bucket.")
        if not issue_id or not ISSUE_ID_RE.match(issue_id):
            return "Invalid issue_id. Use letters, digits, '.', '_', ':', '-' (max 128 chars)."
        if not poc_test or not POC_TEST_RE.match(poc_test) or ".." in poc_test or poc_test.startswith("/"):
            return "Invalid poc_test. Use a relative path inside the repository, e.g. tests/poc."
        return None

    @staticmethod
    def new_run_id() -> str:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"run-{ts}-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def build_run_body(env: Dict[str, str]) -> Dict[str, Any]:
        return {
            "overrides": {
                "containerOverrides": [
                    {"env": [{"name": k, "value": v} for k, v in env.items()]}
                ]
            }
        }

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def start_validation(
        self,
        repository: str,
        commit_sha: str,
        patch_uri: str,
        issue_id: str,
        poc_test: str = "tests/poc",
        confirmed: bool = False,
    ) -> Dict[str, Any]:
        """Validate inputs, require confirmation, then run the sandbox job with env overrides."""
        repository = (repository or "").strip()
        commit_sha = (commit_sha or "").strip().lower()
        patch_uri = (patch_uri or "").strip()
        issue_id = (issue_id or "").strip()
        poc_test = (poc_test or "tests/poc").strip()

        if not self.is_configured:
            return self._not_configured_error()
        error = self.validate_inputs(repository, commit_sha, patch_uri, issue_id, poc_test)
        if error:
            return {"error": error}

        planned = {
            "job": self.job_path(),
            "repository": repository,
            "commit_sha": commit_sha,
            "source_uri": self.source_uri(repository, commit_sha),
            "patch_uri": patch_uri,
            "issue_id": issue_id,
            "poc_test": poc_test,
        }
        if confirmed is not True:
            return {
                "error": "confirmation_required",
                "message": ("start_sandbox_validation runs a Cloud Run Job. Show the planned run to the "
                            "user, get explicit approval, then call again with confirmed=True."),
                "planned_run": planned,
            }

        def _do() -> Dict[str, Any]:
            run_id = self.new_run_id()
            env = {
                "RUN_ID": run_id,
                "REPOSITORY": repository,
                "COMMIT_SHA": commit_sha,
                "SOURCE_URI": planned["source_uri"],
                "PATCH_URI": patch_uri,
                "ISSUE_ID": issue_id,
                "POC_TEST": poc_test,
            }
            url = f"{RUN_API}/{self.job_path()}:run"
            op = self._request("POST", url, json_body=self.build_run_body(env))
            metadata = op.get("metadata") or {}
            execution_resource = metadata.get("name")
            execution_name = execution_resource.rsplit("/", 1)[-1] if execution_resource else None
            return {
                "status": "STARTED",
                "run_id": run_id,
                "execution_name": execution_name,
                "execution_resource": execution_resource,
                "operation": op.get("name"),
                "source_uri": planned["source_uri"],
                "patch_uri": patch_uri,
                "issue_id": issue_id,
                "next_step": f"Call get_sandbox_result(run_id='{run_id}') to check progress and the verdict.",
            }

        return self._run(_do)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def _execution_resource(self, execution_name: str) -> Optional[str]:
        name = execution_name.strip()
        if name.startswith("projects/"):
            parts = name.split("/")
            if (len(parts) == 8 and parts[2] == "locations" and parts[4] == "jobs"
                    and parts[6] == "executions" and EXECUTION_ID_RE.match(parts[7])):
                return name
            return None
        if EXECUTION_ID_RE.match(name):
            return f"{self.job_path()}/executions/{name}"
        return None

    @staticmethod
    def summarize_execution(ex: Dict[str, Any]) -> Dict[str, Any]:
        succeeded = int(ex.get("succeededCount") or 0)
        failed = int(ex.get("failedCount") or 0)
        cancelled = int(ex.get("cancelledCount") or 0)
        running = int(ex.get("runningCount") or 0)
        if ex.get("completionTime"):
            if cancelled:
                state = "CANCELLED"
            elif failed:
                state = "FAILED"
            else:
                state = "SUCCEEDED" if succeeded else "FAILED"
        elif running:
            state = "RUNNING"
        else:
            state = "PENDING"
        name = ex.get("name") or ""
        return {
            "state": state,
            "execution_name": name.rsplit("/", 1)[-1] if name else None,
            "execution_resource": name or None,
            "create_time": ex.get("createTime"),
            "start_time": ex.get("startTime"),
            "completion_time": ex.get("completionTime"),
            "running_count": running,
            "succeeded_count": succeeded,
            "failed_count": failed,
            "cancelled_count": cancelled,
            "log_uri": ex.get("logUri"),
            "conditions": [
                {"type": c.get("type"), "state": c.get("state"), "message": c.get("message")}
                for c in (ex.get("conditions") or [])
            ],
        }

    def get_execution(self, execution_name: str) -> Dict[str, Any]:
        """Status of one execution (short name or full resource name)."""
        if not execution_name:
            return {"error": "execution_name is required."}
        if not self.is_configured:
            return self._not_configured_error()
        resource = self._execution_resource(execution_name)
        if not resource:
            return {"error": "Invalid execution_name."}

        def _do() -> Dict[str, Any]:
            ex = self._request("GET", f"{RUN_API}/{resource}")
            return self.summarize_execution(ex)

        return self._run(_do)

    @staticmethod
    def _execution_env(ex: Dict[str, Any]) -> Dict[str, str]:
        env: Dict[str, str] = {}
        containers: List[Dict[str, Any]] = ((ex.get("template") or {}).get("containers")) or []
        for c in containers:
            for e in c.get("env") or []:
                if "name" in e and "value" in e:
                    env[e["name"]] = e["value"]
        return env

    def find_execution_by_run_id(self, run_id: str, page_size: int = 50) -> Dict[str, Any]:
        """Find a recent execution whose RUN_ID override matches (best effort).

        Relies on Execution.template carrying the env overrides; confirm in your environment.
        """
        if not run_id or not RUN_ID_RE.match(run_id):
            return {"error": "Invalid run_id."}
        if not self.is_configured:
            return self._not_configured_error()

        def _do() -> Dict[str, Any]:
            body = self._request("GET", f"{RUN_API}/{self.job_path()}/executions",
                                 params={"pageSize": max(1, min(page_size, 100))})
            for ex in body.get("executions") or []:
                if self._execution_env(ex).get("RUN_ID") == run_id:
                    return self.summarize_execution(ex)
            return {"error": f"No recent execution found for run_id '{run_id}'."}

        return self._run(_do)
