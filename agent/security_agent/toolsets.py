"""MCP toolset factories, one per server.

Each factory returns an `McpToolset` or `None`. It returns `None` (and logs a
warning) when the server is disabled with its ENABLE_* toggle or when its
configuration is missing. Nothing here opens a network connection at import
or build time: tokens are fetched lazily inside header providers, which ADK
calls when it opens an MCP session.

ADK APIs used (google-adk 2.10):
  McpToolset(connection_params=..., tool_filter=..., header_provider=...)
  StreamableHTTPConnectionParams(url=..., headers=..., timeout=...)
  header_provider: Callable[[ReadonlyContext], dict[str, str]]
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool import StreamableHTTPConnectionParams

from . import guardrails
from .config import AgentConfig

logger = logging.getLogger(__name__)

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
# Refresh tokens this many seconds before they expire.
_EXPIRY_SKEW_SECONDS = 300


# ---------------------------------------------------------------------------
# Token sources. Each one caches its token until shortly before expiry so the
# headers stay stable (ADK pools MCP sessions by header identity).
# ---------------------------------------------------------------------------


class WizTokenSource:
  """Wiz bearer token: static WIZ_MCP_TOKEN or client-credentials exchange.

  The exchange posts grant_type=client_credentials, client_id, client_secret
  and audience=wiz-api to https://auth.app.wiz.io/oauth/token. The Wiz remote
  MCP server accepting this token is "confirm in your environment"; some
  tenants use OAuth with user consent instead.
  """

  def __init__(
      self,
      *,
      static_token: str | None = None,
      client_id: str | None = None,
      client_secret: str | None = None,
      auth_url: str,
      audience: str,
      http_post: Callable[..., Any] | None = None,
      clock: Callable[[], float] = time.time,
  ):
    self._static_token = static_token
    self._client_id = client_id
    self._client_secret = client_secret
    self._auth_url = auth_url
    self._audience = audience
    self._http_post = http_post
    self._clock = clock
    self._token: str | None = None
    self._expires_at = 0.0
    self._lock = threading.Lock()

  def _post(self, url: str, data: dict[str, str]) -> dict[str, Any]:
    if self._http_post is not None:
      return self._http_post(url, data)
    import httpx  # imported lazily; installed with the agent

    resp = httpx.post(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15.0,
    )
    resp.raise_for_status()
    return resp.json()

  def token(self) -> str:
    if self._static_token:
      return self._static_token
    with self._lock:
      now = self._clock()
      if self._token and now < self._expires_at - _EXPIRY_SKEW_SECONDS:
        return self._token
      body = self._post(
          self._auth_url,
          {
              "grant_type": "client_credentials",
              "client_id": self._client_id or "",
              "client_secret": self._client_secret or "",
              "audience": self._audience,
          },
      )
      self._token = body["access_token"]
      self._expires_at = now + float(body.get("expires_in", 3600))
      return self._token


class GoogleAccessTokenSource:
  """OAuth access token from Application Default Credentials."""

  def __init__(
      self,
      scopes: tuple[str, ...] = (CLOUD_PLATFORM_SCOPE,),
      credentials: Any = None,
      request_factory: Callable[[], Any] | None = None,
  ):
    self._scopes = list(scopes)
    self._credentials = credentials
    self._request_factory = request_factory
    self._lock = threading.Lock()

  def _request(self):
    if self._request_factory is not None:
      return self._request_factory()
    from google.auth.transport.requests import Request

    return Request()

  def token(self) -> str:
    with self._lock:
      if self._credentials is None:
        import google.auth

        self._credentials, _ = google.auth.default(scopes=self._scopes)
      # `valid` is False when the token is missing or expired.
      if not getattr(self._credentials, "valid", False):
        self._credentials.refresh(self._request())
      return self._credentials.token


class GoogleIdTokenSource:
  """Google ID token for a Cloud Run audience (the service base URL)."""

  def __init__(
      self,
      audience: str,
      fetcher: Callable[[Any, str], str] | None = None,
      request_factory: Callable[[], Any] | None = None,
      clock: Callable[[], float] = time.time,
      lifetime_seconds: float = 3600,
  ):
    self._audience = audience
    self._fetcher = fetcher
    self._request_factory = request_factory
    self._clock = clock
    self._lifetime = lifetime_seconds
    self._token: str | None = None
    self._fetched_at = 0.0
    self._lock = threading.Lock()

  def token(self) -> str:
    with self._lock:
      now = self._clock()
      if self._token and now < self._fetched_at + self._lifetime - _EXPIRY_SKEW_SECONDS:
        return self._token
      if self._request_factory is not None:
        request = self._request_factory()
      else:
        from google.auth.transport.requests import Request

        request = Request()
      fetcher = self._fetcher
      if fetcher is None:
        from google.oauth2 import id_token

        fetcher = id_token.fetch_id_token
      self._token = fetcher(request, self._audience)
      self._fetched_at = now
      return self._token


def cloud_run_audience(mcp_url: str) -> str:
  """https://svc-xyz.a.run.app/mcp -> https://svc-xyz.a.run.app"""
  from urllib.parse import urlsplit

  parts = urlsplit(mcp_url)
  return f"{parts.scheme}://{parts.netloc}"


def bearer_header_provider(source) -> Callable[[Any], dict[str, str]]:
  """Builds an ADK header_provider that returns a fresh bearer header."""

  def provider(_readonly_context: Any = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {source.token()}"}

  return provider


def _connection(url: str, cfg: AgentConfig, headers: dict[str, str] | None = None):
  return StreamableHTTPConnectionParams(
      url=url, headers=headers, timeout=cfg.mcp_timeout_seconds
  )


def _skip(server: str, reason: str) -> None:
  logger.warning("Skipping %s MCP toolset: %s", server, reason)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def wiz_toolset(cfg: AgentConfig, token_source: WizTokenSource | None = None):
  if not cfg.enable_wiz:
    _skip("Wiz", "ENABLE_WIZ is false")
    return None
  if not cfg.wiz_mcp_url:
    _skip("Wiz", "WIZ_MCP_URL is not set")
    return None
  if token_source is None:
    if cfg.wiz_mcp_token:
      token_source = WizTokenSource(
          static_token=cfg.wiz_mcp_token,
          auth_url=cfg.wiz_auth_url,
          audience=cfg.wiz_audience,
      )
    elif cfg.wiz_client_id and cfg.wiz_client_secret:
      token_source = WizTokenSource(
          client_id=cfg.wiz_client_id,
          client_secret=cfg.wiz_client_secret,
          auth_url=cfg.wiz_auth_url,
          audience=cfg.wiz_audience,
      )
    else:
      _skip("Wiz", "set WIZ_MCP_TOKEN or WIZ_CLIENT_ID and WIZ_CLIENT_SECRET")
      return None
  return McpToolset(
      connection_params=_connection(cfg.wiz_mcp_url, cfg),
      header_provider=bearer_header_provider(token_source),
  )


def logging_toolset(
    cfg: AgentConfig, token_source: GoogleAccessTokenSource | None = None
):
  if not cfg.enable_logging:
    _skip("Cloud Logging", "ENABLE_LOGGING is false")
    return None
  if not cfg.cloud_logging_mcp_url:
    _skip("Cloud Logging", "CLOUD_LOGGING_MCP_URL is not set")
    return None
  token_source = token_source or GoogleAccessTokenSource()

  def provider(_readonly_context: Any = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token_source.token()}"}
    # Quota/billing project for user credentials. Confirm in your environment.
    if cfg.google_cloud_project:
      headers["x-goog-user-project"] = cfg.google_cloud_project
    return headers

  return McpToolset(
      connection_params=_connection(cfg.cloud_logging_mcp_url, cfg),
      header_provider=provider,
  )


def github_toolset(cfg: AgentConfig):
  if not cfg.enable_github:
    _skip("GitHub", "ENABLE_GITHUB is false")
    return None
  if not cfg.github_mcp_url:
    _skip("GitHub", "GITHUB_MCP_URL is not set")
    return None
  if not cfg.github_pat:
    _skip("GitHub", "GITHUB_PAT is not set")
    return None
  return McpToolset(
      connection_params=_connection(
          cfg.github_mcp_url,
          cfg,
          headers={"Authorization": f"Bearer {cfg.github_pat}"},
      ),
      # Merge/delete/admin tools are never exposed to the model. The
      # before_tool_callback in guardrails.py blocks them again by name.
      tool_filter=guardrails.github_tool_filter,
  )


def codemender_toolset(
    cfg: AgentConfig, token_source: GoogleIdTokenSource | None = None
):
  if not cfg.enable_codemender:
    _skip("CodeMender", "ENABLE_CODEMENDER is false")
    return None
  if not cfg.codemender_mcp_url:
    _skip("CodeMender", "CODEMENDER_MCP_URL is not set")
    return None
  token_source = token_source or GoogleIdTokenSource(
      audience=cloud_run_audience(cfg.codemender_mcp_url)
  )
  return McpToolset(
      connection_params=_connection(cfg.codemender_mcp_url, cfg),
      header_provider=bearer_header_provider(token_source),
  )


FACTORIES = {
    "wiz": wiz_toolset,
    "logging": logging_toolset,
    "github": github_toolset,
    "codemender": codemender_toolset,
}


def build_toolsets(cfg: AgentConfig) -> list:
  toolsets = []
  for name, factory in FACTORIES.items():
    try:
      ts = factory(cfg)
    except Exception as exc:  # never crash agent construction
      _skip(name, f"factory failed: {exc}")
      ts = None
    if ts is not None:
      toolsets.append(ts)
  return toolsets
