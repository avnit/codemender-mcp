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

"""Unit tests for codemender.runner.config module."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock

_PKG_DIR = Path(__file__).resolve().parents[2]
if str(_PKG_DIR) not in sys.path:
  sys.path.insert(0, str(_PKG_DIR))

from codemender.runner.config import inject_codemender_config
from codemender.runner.config import OrchestratorConfig
import yaml


class TestConfig(unittest.TestCase):

  def test_inject_codemender_config_repo_level(self):
    """Verify repository-level .codemender.yaml overrides build command."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        local_config = {
            "build": {"command": "npm run test:security"},
            "scan": {"paths": ["src/"]},
        }
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(local_config, f)

        with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
          inject_codemender_config(repo_dir)

          out_config = os.path.join(temp_home, ".codemender", "config.yaml")
          self.assertTrue(os.path.exists(out_config))

          with open(out_config, "r") as f:
            data = yaml.safe_load(f)

          self.assertEqual(data["build"]["command"], "npm run test:security")
          self.assertFalse(data["tools"]["confirm_commands"])

  def test_sandbox_network_profile_defaults_to_closed(self):
    """With no override, cm's sandbox gets no network (`permissive-closed`)."""
    with unittest.mock.patch.dict(os.environ, {}, clear=True):
      self.assertEqual(
          OrchestratorConfig.from_env().sandbox_network_profile,
          "permissive-closed",
      )
    self.assertEqual(
        OrchestratorConfig().sandbox_network_profile, "permissive-closed"
    )

  def test_sandbox_network_profile_open_is_explicit_opt_in(self):
    """`permissive-open` is still honored when asked for explicitly."""
    env = {"CODEMENDER_SANDBOX_NETWORK_PROFILE": "permissive-open"}
    with unittest.mock.patch.dict(os.environ, env, clear=True):
      self.assertEqual(
          OrchestratorConfig.from_env().sandbox_network_profile,
          "permissive-open",
      )

  def test_sandbox_stays_enabled_in_github_actions(self):
    """GitHub Actions mode keeps cm's sandbox on unless explicitly disabled."""
    env = {"GITHUB_ACTIONS": "true"}
    with unittest.mock.patch.dict(os.environ, env, clear=True):
      cfg = OrchestratorConfig.from_env()
    self.assertTrue(cfg.sandbox_enabled)

  def test_inject_codemender_config_sandbox(self):
    """Verify sandbox settings and project_paths normalization in config.yaml."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        local_config = {
            "build": {"command": "npm test"},
            "project_paths": ["src", "routes", os.path.abspath("/custom/abs/path")],
        }
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(local_config, f)

        with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
          inject_codemender_config(repo_dir, config=OrchestratorConfig())

          out_config = os.path.join(temp_home, ".codemender", "config.yaml")
          self.assertTrue(os.path.exists(out_config))

          with open(out_config, "r") as f:
            data = yaml.safe_load(f)

          # Verify sandbox defaults
          self.assertIn("sandbox", data)
          self.assertTrue(data["sandbox"]["enabled"])
          self.assertEqual(data["sandbox"]["mounts"]["target_dir"], os.path.abspath(repo_dir))
          self.assertEqual(data["sandbox"]["network"]["profile"], "permissive-closed")

          # Verify project_paths are all absolute
          self.assertIn("project_paths", data)
          for p in data["project_paths"]:
            self.assertTrue(os.path.isabs(p), f"Path {p} is not absolute")
          self.assertIn(os.path.abspath(os.path.join(repo_dir, "src")), data["project_paths"])
          self.assertIn(os.path.abspath(os.path.join(repo_dir, "routes")), data["project_paths"])
          self.assertIn(os.path.abspath("/custom/abs/path"), data["project_paths"])

  def test_inject_codemender_config_does_not_guess_build_command(self):
    """Verify inject_codemender_config leaves build.command unset when not explicitly configured."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        with open(os.path.join(repo_dir, "package.json"), "w") as f:
          f.write('{"scripts": {"test": "jest"}}')
        with open(os.path.join(repo_dir, "pyproject.toml"), "w") as f:
          f.write("[tool.pytest]")
        with open(os.path.join(repo_dir, "go.mod"), "w") as f:
          f.write("module example.com/test")
        with (
            unittest.mock.patch("os.path.expanduser", return_value=temp_home),
            unittest.mock.patch("sys.stdin.isatty", return_value=False),
            unittest.mock.patch.dict(os.environ, {}, clear=True),
        ):
          inject_codemender_config(repo_dir)
          out_config = os.path.join(temp_home, ".codemender", "config.yaml")
          with open(out_config, "r") as f:
            data = yaml.safe_load(f)
          self.assertNotIn("command", data["build"])

  def test_inject_codemender_config_env_override_takes_precedence(self):
    """Verify env override CODEMENDER_BUILD_COMMAND takes precedence over repo config."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        local_config = {"build": {"command": "npm test"}}
        with open(os.path.join(repo_dir, ".codemender.yaml"), "w") as f:
          yaml.dump(local_config, f)
        test_env = {"CODEMENDER_BUILD_COMMAND": "npm run custom:test"}
        with unittest.mock.patch.dict(os.environ, test_env, clear=True):
          cfg = OrchestratorConfig.from_env()
          with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
            inject_codemender_config(repo_dir, config=cfg)
            out_config = os.path.join(temp_home, ".codemender", "config.yaml")
            with open(out_config, "r") as f:
              data = yaml.safe_load(f)
            self.assertEqual(data["build"]["command"], "npm run custom:test")

  def test_inject_codemender_config_composite_build_command(self):
    """Verify composite build commands with ampersands are safely preserved."""
    with tempfile.TemporaryDirectory() as temp_home:
      with tempfile.TemporaryDirectory() as repo_dir:
        test_env = {"CODEMENDER_BUILD_COMMAND": "npm install && npm test"}
        with unittest.mock.patch.dict(os.environ, test_env, clear=True):
          cfg = OrchestratorConfig.from_env()
          with unittest.mock.patch("os.path.expanduser", return_value=temp_home):
            inject_codemender_config(repo_dir, config=cfg)
            out_config = os.path.join(temp_home, ".codemender", "config.yaml")
            with open(out_config, "r") as f:
              data = yaml.safe_load(f)
            self.assertEqual(data["build"]["command"], "npm install && npm test")


if __name__ == "__main__":
  unittest.main()
