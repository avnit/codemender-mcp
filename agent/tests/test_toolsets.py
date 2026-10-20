import unittest
from unittest import mock

import tests  # noqa: F401
from google.adk.tools.mcp_tool import McpToolset
from security_agent import guardrails
from security_agent import toolsets as ts
from security_agent.config import load_config

FULL_ENV = {
    "GOOGLE_CLOUD_PROJECT": "lab-project-123",
    "WIZ_MCP_URL": "https://mcp.app.wiz.io",
    "WIZ_CLIENT_ID": "wiz-id",
    "WIZ_CLIENT_SECRET": "wiz-secret",
    "CLOUD_LOGGING_MCP_URL": "https://logging.googleapis.com/mcp",
    "GITHUB_MCP_URL": "https://api.githubcopilot.com/mcp/",
    "GITHUB_PAT": "test-pat",
    "CODEMENDER_MCP_URL": "https://codemender-mcp-server-abc123.us-central1.run.app/mcp",
}


def cfg(**overrides):
  env = dict(FULL_ENV)
  env.update(overrides)
  return load_config({k: v for k, v in env.items() if v is not None})


class FakeCreds:
  def __init__(self):
    self.valid = False
    self.token = None
    self.refreshes = 0

  def refresh(self, request):
    self.refreshes += 1
    self.valid = True
    self.token = f"access-{self.refreshes}"


class SkipTest(unittest.TestCase):

  def test_toggles_disable_each_toolset(self):
    c = cfg(ENABLE_WIZ="false", ENABLE_LOGGING="false",
            ENABLE_GITHUB="false", ENABLE_CODEMENDER="false")
    with self.assertLogs(ts.logger, level="WARNING") as logs:
      self.assertEqual(ts.build_toolsets(c), [])
    self.assertEqual(len(logs.records), 4)

  def test_missing_config_skips_cleanly(self):
    c = load_config({})  # defaults: URLs present, no credentials
    with self.assertLogs(ts.logger, level="WARNING") as logs:
      self.assertIsNone(ts.wiz_toolset(c))
      self.assertIsNone(ts.github_toolset(c))
      self.assertIsNone(ts.codemender_toolset(c))
    joined = " ".join(r.getMessage() for r in logs.records)
    self.assertIn("WIZ_MCP_TOKEN", joined)
    self.assertIn("GITHUB_PAT", joined)
    self.assertIn("CODEMENDER_MCP_URL", joined)

  def test_placeholders_count_as_missing(self):
    c = cfg(GITHUB_PAT="ghp_REPLACE_ME",
            CODEMENDER_MCP_URL="https://codemender-mcp-server-XXXX.us-central1.run.app/mcp",
            WIZ_CLIENT_SECRET="REPLACE_ME")
    with self.assertLogs(ts.logger, level="WARNING"):
      self.assertIsNone(ts.github_toolset(c))
      self.assertIsNone(ts.codemender_toolset(c))
      self.assertIsNone(ts.wiz_toolset(c))

  def test_factory_exception_does_not_crash(self):
    def boom(_cfg):
      raise RuntimeError("bad")
    with mock.patch.dict(ts.FACTORIES, {"wiz": boom}, clear=False):
      with self.assertLogs(ts.logger, level="WARNING"):
        out = ts.build_toolsets(cfg(ENABLE_LOGGING="false", ENABLE_GITHUB="false",
                                    ENABLE_CODEMENDER="false"))
    self.assertEqual(out, [])

  def test_all_configured_builds_four_toolsets_without_network(self):
    out = ts.build_toolsets(cfg())
    self.assertEqual(len(out), 4)
    self.assertTrue(all(isinstance(t, McpToolset) for t in out))


class HeaderTest(unittest.TestCase):

  def test_wiz_static_token(self):
    toolset = ts.wiz_toolset(cfg(WIZ_MCP_TOKEN="static-wiz"))
    self.assertEqual(toolset.header_provider(None), {"Authorization": "Bearer static-wiz"})

  def test_wiz_client_credentials_exchange_and_cache(self):
    calls = []

    def fake_post(url, data):
      calls.append((url, data))
      return {"access_token": f"wiz-{len(calls)}", "expires_in": 3600}

    now = [1000.0]
    src = ts.WizTokenSource(client_id="id", client_secret="secret",
                            auth_url="https://auth.app.wiz.io/oauth/token",
                            audience="wiz-api", http_post=fake_post,
                            clock=lambda: now[0])
    provider = ts.bearer_header_provider(src)
    self.assertEqual(provider(None), {"Authorization": "Bearer wiz-1"})
    self.assertEqual(provider(None), {"Authorization": "Bearer wiz-1"})  # cached
    url, data = calls[0]
    self.assertEqual(url, "https://auth.app.wiz.io/oauth/token")
    self.assertEqual(data, {"grant_type": "client_credentials", "client_id": "id",
                            "client_secret": "secret", "audience": "wiz-api"})
    now[0] += 3500  # inside the refresh skew window
    self.assertEqual(provider(None), {"Authorization": "Bearer wiz-2"})

  def test_logging_access_token_and_quota_header(self):
    creds = FakeCreds()
    src = ts.GoogleAccessTokenSource(credentials=creds, request_factory=object)
    toolset = ts.logging_toolset(cfg(), token_source=src)
    self.assertEqual(toolset.header_provider(None),
                     {"Authorization": "Bearer access-1",
                      "x-goog-user-project": "lab-project-123"})
    self.assertEqual(creds.refreshes, 1)
    toolset.header_provider(None)
    self.assertEqual(creds.refreshes, 1)  # still valid
    creds.valid = False  # expired
    self.assertEqual(toolset.header_provider(None)["Authorization"], "Bearer access-2")

  def test_logging_uses_google_auth_default_with_cloud_platform_scope(self):
    creds = FakeCreds()
    with mock.patch("google.auth.default", return_value=(creds, "p")) as default:
      src = ts.GoogleAccessTokenSource(request_factory=object)
      self.assertEqual(src.token(), "access-1")
    default.assert_called_once_with(scopes=[ts.CLOUD_PLATFORM_SCOPE])

  def test_github_static_bearer_and_filter(self):
    toolset = ts.github_toolset(cfg())
    params = toolset._connection_params  # pylint: disable=protected-access
    self.assertEqual(params.headers, {"Authorization": "Bearer test-pat"})
    self.assertEqual(params.url, "https://api.githubcopilot.com/mcp/")
    self.assertIs(toolset.tool_filter, guardrails.github_tool_filter)

  def test_codemender_id_token_audience_is_base_url(self):
    seen = []

    def fetcher(request, audience):
      seen.append(audience)
      return "id-token"

    c = cfg()
    src = ts.GoogleIdTokenSource(audience=ts.cloud_run_audience(c.codemender_mcp_url),
                                 fetcher=fetcher, request_factory=object)
    toolset = ts.codemender_toolset(c, token_source=src)
    self.assertEqual(toolset.header_provider(None), {"Authorization": "Bearer id-token"})
    toolset.header_provider(None)
    self.assertEqual(seen, ["https://codemender-mcp-server-abc123.us-central1.run.app"])

  def test_codemender_default_source_uses_fetch_id_token(self):
    with mock.patch("google.oauth2.id_token.fetch_id_token", return_value="tok") as f:
      toolset = ts.codemender_toolset(cfg())
      with mock.patch("google.auth.transport.requests.Request", return_value="req"):
        self.assertEqual(toolset.header_provider(None), {"Authorization": "Bearer tok"})
    f.assert_called_once_with("req", "https://codemender-mcp-server-abc123.us-central1.run.app")


if __name__ == "__main__":
  unittest.main()
