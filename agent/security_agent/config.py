"""Environment loading for the AI security agent.

All settings come from environment variables (see agent/.env.example).
`load_config()` never raises for missing values: toolset factories decide
whether they have enough configuration and skip themselves if not.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Mapping

AGENT_NAME = "ai_security_agent"

DEFAULT_MODEL = "gemini-2.5-flash"
DEFAULT_WIZ_MCP_URL = "https://mcp.app.wiz.io"
DEFAULT_WIZ_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_WIZ_AUDIENCE = "wiz-api"
DEFAULT_CLOUD_LOGGING_MCP_URL = "https://logging.googleapis.com/mcp"
DEFAULT_GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"

# Values that ship in .env.example. Treated as "not configured".
PLACEHOLDER_MARKERS = ("REPLACE_ME", "your-", "XXXX")

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f"}


def parse_bool(value: str | None, default: bool) -> bool:
  if value is None or value.strip() == "":
    return default
  v = value.strip().lower()
  if v in _TRUE:
    return True
  if v in _FALSE:
    return False
  return default


def is_placeholder(value: str | None) -> bool:
  """True when the value is empty or still a placeholder from .env.example."""
  if not value or not value.strip():
    return True
  return any(marker in value for marker in PLACEHOLDER_MARKERS)


def _clean(value: str | None) -> str | None:
  return None if is_placeholder(value) else value.strip()


@dataclasses.dataclass(frozen=True)
class AgentConfig:
  google_cloud_project: str | None
  google_cloud_location: str
  model: str

  enable_wiz: bool
  enable_logging: bool
  enable_github: bool
  enable_codemender: bool

  wiz_mcp_url: str | None
  wiz_mcp_token: str | None
  wiz_client_id: str | None
  wiz_client_secret: str | None
  wiz_auth_url: str
  wiz_audience: str

  cloud_logging_mcp_url: str | None

  github_mcp_url: str | None
  github_pat: str | None
  github_org: str | None
  github_default_branches: tuple[str, ...]

  codemender_mcp_url: str | None

  staging_bucket: str | None

  # "native": ADK ToolConfirmation (tool_context.request_confirmation).
  # "chat": the user's latest message must start with "confirm".
  hitl_mode: str
  # Also register skills through ADK's experimental SkillToolset.
  use_adk_skill_toolset: bool
  skills_dir: Path
  mcp_timeout_seconds: float


def default_skills_dir() -> Path:
  # agent/security_agent/config.py -> agent/skills
  return Path(__file__).resolve().parent.parent / "skills"


def load_config(env: Mapping[str, str] | None = None) -> AgentConfig:
  e = os.environ if env is None else env
  branches = e.get("GITHUB_DEFAULT_BRANCHES", "main,master")
  hitl_mode = (e.get("HITL_MODE") or "native").strip().lower()
  if hitl_mode not in ("native", "chat"):
    hitl_mode = "native"
  return AgentConfig(
      google_cloud_project=_clean(e.get("GOOGLE_CLOUD_PROJECT")),
      google_cloud_location=e.get("GOOGLE_CLOUD_LOCATION") or "us-central1",
      model=e.get("AGENT_MODEL") or DEFAULT_MODEL,
      enable_wiz=parse_bool(e.get("ENABLE_WIZ"), True),
      enable_logging=parse_bool(e.get("ENABLE_LOGGING"), True),
      enable_github=parse_bool(e.get("ENABLE_GITHUB"), True),
      enable_codemender=parse_bool(e.get("ENABLE_CODEMENDER"), True),
      wiz_mcp_url=_clean(e.get("WIZ_MCP_URL", DEFAULT_WIZ_MCP_URL)),
      wiz_mcp_token=_clean(e.get("WIZ_MCP_TOKEN")),
      wiz_client_id=_clean(e.get("WIZ_CLIENT_ID")),
      wiz_client_secret=_clean(e.get("WIZ_CLIENT_SECRET")),
      wiz_auth_url=e.get("WIZ_AUTH_URL") or DEFAULT_WIZ_AUTH_URL,
      wiz_audience=e.get("WIZ_AUDIENCE") or DEFAULT_WIZ_AUDIENCE,
      cloud_logging_mcp_url=_clean(
          e.get("CLOUD_LOGGING_MCP_URL", DEFAULT_CLOUD_LOGGING_MCP_URL)
      ),
      github_mcp_url=_clean(e.get("GITHUB_MCP_URL", DEFAULT_GITHUB_MCP_URL)),
      github_pat=_clean(e.get("GITHUB_PAT")),
      github_org=_clean(e.get("GITHUB_ORG")),
      github_default_branches=tuple(
          b.strip() for b in branches.split(",") if b.strip()
      ),
      codemender_mcp_url=_clean(e.get("CODEMENDER_MCP_URL")),
      staging_bucket=_clean(e.get("STAGING_BUCKET")),
      hitl_mode=hitl_mode,
      use_adk_skill_toolset=parse_bool(e.get("USE_ADK_SKILL_TOOLSET"), False),
      skills_dir=Path(e.get("SKILLS_DIR") or default_skills_dir()),
      mcp_timeout_seconds=float(e.get("MCP_TIMEOUT_SECONDS") or 30),
  )
