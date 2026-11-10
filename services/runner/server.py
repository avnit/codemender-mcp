"""CodeMender MCP server (streamable HTTP), designed to run on Cloud Run.

Tools:
  cm_find           Scan a whole repository; findings go to BigQuery.
  cm_validate       Run `cm verify` (exploitability check) on one finding.
  cm_fix            Run `cm fix` on one finding; store the patch in BigQuery
                    and push it to the repo as a branch / pull request.
  cm_apply_patch    Re-push a stored patch (e.g. after a push failure).
  cm_job_status     Poll a job (optionally wait for it).
  cm_list_findings  List findings for a repository / scan / status.
  cm_get_finding    Full details of one finding (patch, verdict, SARIF).

find/validate/fix return immediately with a `job_id`; each one runs in a new,
isolated Cloud Run Job execution. Pass `wait_seconds` to block for a result.
"""

from __future__ import annotations

import hmac
import logging
import sys
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from services.runner.service import CodeMenderService, ServiceError
from services.runner.settings import Settings

logger = logging.getLogger("cm_mcp")

INSTRUCTIONS = """\
CodeMender security scanning, verification and auto-fix for git repositories.
Typical flow:
  1. cm_find(repo="owner/repo") -> job_id. Poll cm_job_status(job_id, wait_seconds=600).
     A full scan can take a long time; findings are stored in BigQuery.
  2. cm_list_findings(repo="owner/repo") to see finding_ids.
  3. cm_validate(finding_id) to check exploitability (VERIFIED / FALSE_POSITIVE).
  4. cm_fix(finding_id) to generate a patch; it is saved in BigQuery and, by
     default, pushed as branch codemender/fix-<id> with a pull request.
"""


def build_mcp(service: CodeMenderService, settings: Settings) -> FastMCP:
  """Creates the FastMCP app with all CodeMender tools bound to `service`."""
  mcp = FastMCP(
      "codemender",
      instructions=INSTRUCTIONS,
      stateless_http=True,
      json_response=True,
      host="0.0.0.0",
      port=settings.port,
  )

  def _wait(view: dict[str, Any], wait_seconds: int) -> dict[str, Any]:
    if wait_seconds and view.get("job_id"):
      return service.job_status(view["job_id"], wait_seconds)
    return view

  def _guard(fn, *args, **kwargs) -> dict[str, Any]:
    try:
      return fn(*args, **kwargs)
    except ServiceError as exc:
      return {"error": str(exc)}
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.exception("Tool call failed")
      return {"error": f"{type(exc).__name__}: {exc}"}

  @mcp.tool()
  def cm_find(repo: str, ref: str = "", wait_seconds: int = 0) -> dict[str, Any]:
    """Scan an entire repository with CodeMender and store findings in BigQuery.

    Args:
      repo: "owner/repo" (GitHub) or an HTTPS git URL.
      ref: Branch, tag or commit SHA to scan. Defaults to the default branch.
      wait_seconds: Optionally wait up to this many seconds for completion.
    """
    return _guard(lambda: _wait(service.start_find(repo, ref), wait_seconds))

  @mcp.tool()
  def cm_validate(finding_id: str, wait_seconds: int = 0) -> dict[str, Any]:
    """Validate (cm verify) one finding's exploitability; updates BigQuery.

    The verdict is VERIFIED (exploitable), FALSE_POSITIVE (refuted) or
    INCONCLUSIVE, written to the finding's `status` / `verify_status`.
    """
    return _guard(lambda: _wait(service.start_validate(finding_id), wait_seconds))

  @mcp.tool()
  def cm_fix(finding_id: str, patch_mode: str = "", wait_seconds: int = 0) -> dict[str, Any]:
    """Generate a fix (cm fix) for one finding, store it in BigQuery and patch the repo.

    Args:
      finding_id: ID from cm_list_findings.
      patch_mode: "pr" (push branch codemender/fix-<id> and open a pull request),
        "branch" (push the branch only) or "none" (only store the patch in
        BigQuery). Defaults to the server's CM_MCP_DEFAULT_PATCH_MODE ("pr").
      wait_seconds: Optionally wait up to this many seconds for completion.
    """
    return _guard(lambda: _wait(service.start_fix(finding_id, patch_mode), wait_seconds))

  @mcp.tool()
  def cm_apply_patch(finding_id: str, patch_mode: str = "pr") -> dict[str, Any]:
    """Push a patch already stored for a finding ("pr" or "branch")."""
    return _guard(service.apply_patch, finding_id, patch_mode)

  @mcp.tool()
  def cm_job_status(job_id: str, wait_seconds: int = 0) -> dict[str, Any]:
    """Get a job's status (STAGING, RUNNING, SUCCEEDED, FAILED) and result."""
    return _guard(service.job_status, job_id, wait_seconds)

  @mcp.tool()
  def cm_list_findings(
      repo: str = "", status: str = "", scan_job_id: str = "", limit: int = 100
  ) -> dict[str, Any]:
    """List stored findings, filtered by repo, status and/or scan job.

    status: OPEN, VERIFIED, FALSE_POSITIVE, INCONCLUSIVE, FIXED or PATCHED.
    """
    return _guard(lambda: {"findings": service.list_findings(repo, status, scan_job_id, limit)})

  @mcp.tool()
  def cm_get_finding(finding_id: str, include_sarif: bool = False) -> dict[str, Any]:
    """Get one finding including its patch, verification verdict and PR link."""
    return _guard(service.get_finding, finding_id, include_sarif)

  @mcp.custom_route("/healthz", methods=["GET"])
  async def healthz(_: Request) -> JSONResponse:
    return JSONResponse({"ok": True})

  return mcp


class BearerAuthMiddleware:
  """Rejects HTTP requests without `Authorization: Bearer <token>`.

  `/healthz` is exempt so Cloud Run health checks keep working.
  """

  def __init__(self, app, token: str) -> None:
    self.app = app
    self._expected = f"Bearer {token}".encode()

  async def __call__(self, scope, receive, send) -> None:
    if scope["type"] == "http" and scope.get("path") != "/healthz":
      headers = dict(scope.get("headers") or [])
      if not hmac.compare_digest(headers.get(b"authorization", b""), self._expected):
        resp = JSONResponse({"error": "unauthorized"}, status_code=401)
        await resp(scope, receive, send)
        return
    await self.app(scope, receive, send)


def build_service(settings: Settings) -> CodeMenderService:
  """Wires the production GCP adapters."""
  # pylint: disable=import-outside-toplevel
  from services.runner.cloud import CloudRunJobDispatcher, GcsTransit
  from services.runner.store import BigQueryStore

  store = BigQueryStore(settings.project, settings.bq_dataset, settings.bq_location)
  store.ensure_schema()
  return CodeMenderService(
      settings,
      store,
      GcsTransit(settings.project),
      CloudRunJobDispatcher(settings.project, settings.region, settings.job_name),
  )


def build_app(settings: Optional[Settings] = None, service: Optional[CodeMenderService] = None):
  """Returns the ASGI app (MCP endpoint at `/mcp`)."""
  settings = settings or Settings.from_env()
  service = service or build_service(settings)
  app = build_mcp(service, settings).streamable_http_app()
  if settings.auth_token:
    app = BearerAuthMiddleware(app, settings.auth_token)
  return app, service


def main() -> int:
  logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                      format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
  import uvicorn  # pylint: disable=import-outside-toplevel

  settings = Settings.from_env()
  app, service = build_app(settings)
  service.resume()
  logger.info("CodeMender MCP server listening on :%d/mcp (job=%s, dataset=%s)",
              settings.port, settings.job_name, settings.bq_dataset)
  uvicorn.run(app, host="0.0.0.0", port=settings.port, log_level="info")
  return 0


if __name__ == "__main__":
  sys.exit(main())
