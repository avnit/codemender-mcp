"""Tests for the MCP tool surface and HTTP auth."""

from __future__ import annotations

import asyncio
import unittest

from starlette.testclient import TestClient

from services.runner import server
from services.runner.service import ServiceError
from services.runner.settings import Settings


class _StubService:
  def __init__(self) -> None:
    self.calls: list[tuple] = []

  def start_find(self, repo, ref=""):
    self.calls.append(("find", repo, ref))
    return {"job_id": "find-1", "status": "STAGING"}

  def start_validate(self, finding_id):
    raise ServiceError(f"Unknown finding_id {finding_id!r}.")

  def job_status(self, job_id, wait_seconds=0):
    self.calls.append(("status", job_id, wait_seconds))
    return {"job_id": job_id, "status": "SUCCEEDED"}


class TestTools(unittest.TestCase):

  def setUp(self) -> None:
    self.service = _StubService()
    self.mcp = server.build_mcp(self.service, Settings(project="p"))

  def _call(self, name, args):
    result = asyncio.run(self.mcp.call_tool(name, args))
    # FastMCP returns (content, structured) in recent versions.
    if isinstance(result, tuple):
      return result[1].get("result", result[1])
    import json  # pylint: disable=import-outside-toplevel
    return json.loads(result[0].text)

  def test_tools_registered(self):
    names = {t.name for t in asyncio.run(self.mcp.list_tools())}
    self.assertEqual(names, {"cm_find", "cm_validate", "cm_fix", "cm_apply_patch",
                             "cm_job_status", "cm_list_findings", "cm_get_finding"})

  def test_find_with_wait_polls_status(self):
    out = self._call("cm_find", {"repo": "acme/widgets", "wait_seconds": 30})
    self.assertEqual(out["status"], "SUCCEEDED")
    self.assertEqual(self.service.calls, [("find", "acme/widgets", ""),
                                          ("status", "find-1", 30)])

  def test_service_errors_are_returned_not_raised(self):
    out = self._call("cm_validate", {"finding_id": "nope"})
    self.assertIn("Unknown finding_id", out["error"])


class TestAuth(unittest.TestCase):

  def test_bearer_token_required(self):
    settings = Settings(project="p", auth_token="tok")
    app, _ = server.build_app(settings, service=_StubService())
    with TestClient(app) as client:
      self.assertEqual(client.get("/healthz").status_code, 200)
      self.assertEqual(client.post("/mcp", json={}).status_code, 401)
      resp = client.post(
          "/mcp",
          headers={"Authorization": "Bearer tok",
                   "Accept": "application/json, text/event-stream"},
          json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
      )
      self.assertNotEqual(resp.status_code, 401)


if __name__ == "__main__":
  unittest.main()
