"""Deploy ai_security_agent to Vertex AI Agent Engine.

Usage (from agent/):
  python3 deploy.py --dry-run          # print the deployment config, no API calls
  python3 deploy.py                    # create a new Agent Engine resource
  python3 deploy.py --update RESOURCE  # update an existing reasoning engine

Requires google-cloud-aiplatform[agent_engines,adk] (see requirements.txt).
The vertexai import happens inside main() so this module imports without it.

API used (vertexai SDK, confirm against your installed version):
  vertexai.init(project=..., location=..., staging_bucket=...)
  app = vertexai.agent_engines.AdkApp(agent=root_agent, enable_tracing=True)
  vertexai.agent_engines.create(agent_engine=app, requirements=[...],
                                extra_packages=[...], env_vars={...},
                                display_name=...)
  vertexai.agent_engines.update(resource_name=..., ...same kwargs...)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

DISPLAY_NAME = "ai_security_agent"

REQUIREMENTS = [
    "google-adk>=2.10",
    "google-cloud-aiplatform[agent_engines,adk]",
    "google-auth",
    "httpx",
    "pyyaml",
]

# Packaged next to the agent so skills are available at runtime.
EXTRA_PACKAGES = ["security_agent", "skills"]

# Variables forwarded to the deployed agent. GOOGLE_CLOUD_PROJECT and
# GOOGLE_CLOUD_LOCATION are set by Agent Engine itself (confirm in your
# environment) and are reserved, so they are not forwarded.
FORWARDED_ENV = [
    "GOOGLE_GENAI_USE_VERTEXAI",
    "AGENT_MODEL",
    "ENABLE_WIZ",
    "ENABLE_LOGGING",
    "ENABLE_GITHUB",
    "ENABLE_CODEMENDER",
    "WIZ_MCP_URL",
    "WIZ_CLIENT_ID",
    "CLOUD_LOGGING_MCP_URL",
    "GITHUB_MCP_URL",
    "GITHUB_ORG",
    "GITHUB_DEFAULT_BRANCHES",
    "CODEMENDER_MCP_URL",
    "HITL_MODE",
    "USE_ADK_SKILL_TOOLSET",
]

# Secrets: pass as Secret Manager references, never as plain env values.
# Agent Engine supports {"secret": "<name>", "version": "latest"} env values
# (confirm in your environment).
SECRET_ENV = {
    "WIZ_CLIENT_SECRET": "wiz-client-secret",
    "GITHUB_PAT": "github-mcp-pat",
}


def load_dotenv(path: Path) -> None:
  """Minimal .env reader (KEY=VALUE lines); existing env vars win."""
  if not path.is_file():
    return
  for line in path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
      continue
    key, value = line.split("=", 1)
    os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def build_config(env=None) -> dict:
  e = os.environ if env is None else env
  env_vars = {k: e[k] for k in FORWARDED_ENV if e.get(k)}
  for key, secret in SECRET_ENV.items():
    env_vars[key] = {"secret": secret, "version": "latest"}
  return {
      "project": e.get("GOOGLE_CLOUD_PROJECT", "your-gcp-project-id"),
      "location": e.get("GOOGLE_CLOUD_LOCATION", "us-central1"),
      "staging_bucket": e.get("STAGING_BUCKET", "gs://your-gcp-project-id-agent-staging"),
      "display_name": DISPLAY_NAME,
      "requirements": REQUIREMENTS,
      "extra_packages": EXTRA_PACKAGES,
      "env_vars": env_vars,
  }


def main(argv=None) -> int:
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument("--dry-run", action="store_true", help="print config and exit")
  parser.add_argument("--update", metavar="RESOURCE_NAME",
                      help="projects/.../locations/.../reasoningEngines/ID to update")
  parser.add_argument("--env-file", default=str(HERE / ".env"))
  args = parser.parse_args(argv)

  load_dotenv(Path(args.env_file))
  cfg = build_config()

  if args.dry_run:
    print(json.dumps(cfg, indent=2))
    return 0

  if "your-gcp-project-id" in cfg["project"] or "your-gcp-project-id" in cfg["staging_bucket"]:
    print("Set GOOGLE_CLOUD_PROJECT and STAGING_BUCKET first (see .env.example).", file=sys.stderr)
    return 2

  os.chdir(HERE)  # extra_packages are relative to agent/
  sys.path.insert(0, str(HERE))

  import vertexai  # pylint: disable=import-outside-toplevel
  from vertexai import agent_engines  # pylint: disable=import-outside-toplevel

  from security_agent.agent import root_agent  # pylint: disable=import-outside-toplevel

  vertexai.init(project=cfg["project"], location=cfg["location"],
                staging_bucket=cfg["staging_bucket"])
  app = agent_engines.AdkApp(agent=root_agent, enable_tracing=True)
  kwargs = dict(
      agent_engine=app,
      requirements=cfg["requirements"],
      extra_packages=cfg["extra_packages"],
      env_vars=cfg["env_vars"],
      display_name=cfg["display_name"],
  )
  if args.update:
    remote = agent_engines.update(resource_name=args.update, **kwargs)
  else:
    remote = agent_engines.create(**kwargs)
  print(f"Deployed: {remote.resource_name}")
  print("Next: register it in Gemini Enterprise (register_gemini_enterprise.md).")
  return 0


if __name__ == "__main__":
  sys.exit(main())
