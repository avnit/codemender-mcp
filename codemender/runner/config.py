# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Configuration injection and environment security module for CodeMender Agent."""

import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional

import yaml

logger = logging.getLogger("codemender-orchestrator")

# cm sandbox network profiles (`sandbox.network.profile` in cm's config.yaml).
#   permissive-closed: cm's own default. The sandbox gets its own network
#                      namespace, so the agent's commands have no network.
#   permissive-open:   cm skips the network namespace, so the agent's commands
#                      have full network access. Explicit opt-in only.
# cm treats every value other than `permissive-open` as closed.
SANDBOX_NETWORK_CLOSED = "permissive-closed"
SANDBOX_NETWORK_OPEN = "permissive-open"


@dataclass(frozen=True)
class OrchestratorConfig:
  """Centralized immutable configuration for the CodeMender Orchestrator."""

  model: Optional[str] = None
  build_command: Optional[str] = None
  sandbox_enabled: bool = True
  sandbox_network_profile: str = SANDBOX_NETWORK_CLOSED

  @classmethod
  def from_env(cls) -> "OrchestratorConfig":
    """Loads configuration from environment variables safely in one place."""
    model = os.environ.get("CODEMENDER_MODEL")
    build_command = os.environ.get("CODEMENDER_BUILD_COMMAND")

    sandbox_env = os.environ.get("CODEMENDER_SANDBOX_ENABLED")
    if sandbox_env is not None and sandbox_env.strip():
      sandbox_enabled = sandbox_env.strip().lower() not in (
          "false",
          "0",
          "no",
          "off",
      )
    else:
      sandbox_enabled = True

    # Closed by default: `permissive-open` gives the agent's commands full
    # network access, so it must be requested explicitly.
    sandbox_network_profile = os.environ.get(
        "CODEMENDER_SANDBOX_NETWORK_PROFILE", SANDBOX_NETWORK_CLOSED
    )

    return cls(
        model=model,
        build_command=build_command,
        sandbox_enabled=sandbox_enabled,
        sandbox_network_profile=sandbox_network_profile,
    )


def inject_codemender_config(
    repo_dir: str,
    config: Optional[OrchestratorConfig] = None,
) -> None:
  """Reads project-level and environment configs and merges them into ~/.codemender/config.yaml."""
  cfg = config or OrchestratorConfig.from_env()
  home_dir = os.path.expanduser("~")
  global_config_path = os.path.join(home_dir, ".codemender", "config.yaml")

  # 1. Load global default config created by 'cm init'
  if os.path.exists(global_config_path):
    try:
      with open(global_config_path, "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f) or {}
    except Exception as e:
      logger.warning("Could not read global config.yaml: %s. Re-creating.", e)
      config_data = {}
  else:
    config_data = {}

  # Initialize top-level sections if missing to prevent KeyError during deep merge
  if "build" not in config_data or config_data["build"] is None:
    config_data["build"] = {}
  if "vcs" not in config_data or config_data["vcs"] is None:
    config_data["vcs"] = {}
  if (
      "commands" not in config_data["vcs"]
      or config_data["vcs"]["commands"] is None
  ):
    config_data["vcs"]["commands"] = {}

  # 2. Defaults (VCS is always git inside the orchestrator clone)
  config_data["vcs"]["type"] = "git"
  if "commands" not in config_data["vcs"] or config_data["vcs"]["commands"] is None:
    config_data["vcs"]["commands"] = {}
  if "reset" not in config_data["vcs"]["commands"]:
    config_data["vcs"]["commands"]["reset"] = "git checkout HEAD -- . && git clean -fd"

  # Set default project path to the repository directory to restrict agent scope
  if not config_data.get("project_paths"):
    config_data["project_paths"] = [os.path.abspath(repo_dir)]
  else:
    config_data["project_paths"] = [
        p if os.path.isabs(p) else os.path.abspath(os.path.join(repo_dir, p))
        for p in config_data["project_paths"]
    ]

  # 3. Read Repository-Level config (Config-as-Code - takes precedence over defaults)
  project_config = None
  for filename in [
      ".codemender.yaml",
      "codemender.yaml",
      ".codemender.yml",
      "codemender.yml",
  ]:
    local_path = os.path.join(repo_dir, filename)
    if os.path.exists(local_path):
      try:
        with open(local_path, "r", encoding="utf-8") as f:
          project_config = yaml.safe_load(f)
        logger.info("Found repository-level configuration: %s", filename)
        break
      except Exception as e:
        logger.warning("Failed to parse local config file %s: %s", filename, e)

  # Merge repository-level dictionary sections into global configuration
  if project_config and isinstance(project_config, dict):
    # Deep merge the 'build' section
    if "build" in project_config and isinstance(project_config["build"], dict):
      config_data["build"].update(project_config["build"])

    # Deep merge the 'vcs' section preserving specific commands
    if "vcs" in project_config and isinstance(project_config["vcs"], dict):
      if "commands" in project_config["vcs"] and isinstance(
          project_config["vcs"]["commands"], dict
      ):
        config_data["vcs"]["commands"].update(project_config["vcs"]["commands"])
      for k, v in project_config["vcs"].items():
        if k != "commands":
          config_data["vcs"][k] = v

    # Copy standard configured sections directly
    for key in ["scan", "project_paths", "output", "tools", "sandbox", "security"]:
      if key in project_config:
        config_data[key] = project_config[key]

    # Re-normalize project_paths if overwritten by project_config to ensure absolute paths
    if "project_paths" in project_config and isinstance(project_config["project_paths"], list):
      config_data["project_paths"] = [
          p if os.path.isabs(p) else os.path.abspath(os.path.join(repo_dir, p))
          for p in project_config["project_paths"]
      ]

  # 4. Read Environment Variable configurations (Env Overrides take top precedence)
  if cfg.build_command and cfg.build_command.strip().strip("'\""):
    effective_build_cmd = cfg.build_command.strip().strip("'\"")
    logger.info(
        "Applying env override CODEMENDER_BUILD_COMMAND: %s", effective_build_cmd
    )
    config_data["build"]["command"] = effective_build_cmd

  if cfg.model:
    config_data["model"] = cfg.model.strip()

  # 5. Sandbox Configuration (Enabled by default with absolute target mounts)
  if "sandbox" not in config_data or config_data["sandbox"] is None:
    config_data["sandbox"] = {}
  if "mounts" not in config_data["sandbox"] or config_data["sandbox"]["mounts"] is None:
    config_data["sandbox"]["mounts"] = {}
  if "network" not in config_data["sandbox"] or config_data["sandbox"]["network"] is None:
    config_data["sandbox"]["network"] = {}

  # Set sandbox enablement and network profile from central OrchestratorConfig
  config_data["sandbox"]["enabled"] = cfg.sandbox_enabled
  config_data["sandbox"]["mounts"]["target_dir"] = os.path.abspath(repo_dir)
  config_data["sandbox"]["network"]["profile"] = cfg.sandbox_network_profile

  # 6. Interactive Terminal Prompt Fallback (if no build command configured)
  if not config_data["build"].get("command"):
    if sys.stdin.isatty():
      try:
        prompt_cmd = input(
            "\n⚠️  No build command configured for this project.\nPlease enter"
            " the build/test command (e.g., 'npm test') or press Enter to"
            " skip: "
        ).strip()
        if prompt_cmd:
          config_data["build"]["command"] = prompt_cmd
      except (KeyboardInterrupt, EOFError):
        logger.warning("\nPrompt interrupted. Skipping build command.")
    else:
      logger.warning(
          "No build command configured (running in headless environment)."
          " Post-fix verification will be skipped."
      )

  # 7. Force disable confirmations for headless execution safety (AFTER repository config merge)
  if "tools" not in config_data or config_data["tools"] is None:
    config_data["tools"] = {}
  config_data["tools"]["confirm_commands"] = False
  config_data["tools"]["confirm_writes"] = False

  # 8. Save the merged configuration back to ~/.codemender/config.yaml using atomic rename
  try:
    os.makedirs(os.path.dirname(global_config_path), exist_ok=True)
    tmp_config_path = global_config_path + ".tmp"
    with open(tmp_config_path, "w", encoding="utf-8") as f:
      yaml.safe_dump(config_data, f, default_flow_style=False)
    os.replace(tmp_config_path, global_config_path)
    logger.info(
        "Successfully injected configurations into %s", global_config_path
    )
  except Exception as e:
    logger.error("Failed to write global config.yaml: %s", e)


