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

"""Unit tests for `codemender.runner.__main__`."""

from __future__ import annotations

import io
from pathlib import Path
import unittest
from unittest import mock

from codemender.cm import CmAdapter
from codemender.runner import __main__ as cli_main
from codemender.runner import exit_codes
from codemender.runner.commands import find_diff
from codemender.runner.commands import fix
from codemender.runner.commands import init
from codemender.runner.commands import verify
from codemender.runner.events import EventEmitter


class TestDispatch(unittest.TestCase):
  """Unit tests for `codemender.runner.__main__.dispatch`."""

  def setUp(self) -> None:
    super().setUp()
    self.adapter = CmAdapter("/fake/bin/cm")
    self.repo_dir = Path("/tmp/fake-repo")
    self.out_dir = Path("/tmp/fake-out")
    self.finding_path = Path("/tmp/finding-001.sarif")

  def test_init_skips_auto_init_and_forwards_emitter(self) -> None:
    emitter = EventEmitter(stream=io.StringIO())
    with mock.patch.object(
        init, "run", return_value=exit_codes.OK
    ) as mock_init:
      self.assertEqual(
          cli_main.dispatch(
              "init", self.adapter, repo=self.repo_dir, emitter=emitter
          ),
          exit_codes.OK,
      )
      mock_init.assert_called_once_with(
          init.InitConfig(repo=self.repo_dir.resolve()),
          self.adapter,
          emitter,
      )

  def test_find_diff_runs_auto_init_and_defaults_diff_workers(self) -> None:
    with (
        mock.patch.object(init, "run", return_value=exit_codes.OK) as mock_init,
        mock.patch.object(
            find_diff, "run", return_value=exit_codes.OK
        ) as mock_find_diff,
    ):
      rc = cli_main.dispatch(
          "find-diff",
          self.adapter,
          repo=self.repo_dir,
          base="origin/main",
          out=self.out_dir,
          diff_workers=None,
      )
      self.assertEqual(rc, exit_codes.OK)
      mock_init.assert_called_once()
      self.assertIsNone(mock_init.call_args.kwargs.get("emitter"))
      mock_find_diff.assert_called_once()
      find_cfg = mock_find_diff.call_args.args[0]
      self.assertEqual(find_cfg.repo, self.repo_dir.resolve())
      self.assertEqual(find_cfg.base, "origin/main")
      self.assertEqual(find_cfg.out, self.out_dir.resolve())
      self.assertEqual(find_cfg.diff_workers, find_diff.DEFAULT_DIFF_WORKERS)

  def test_fix_and_verify_respect_auto_init_flag(self) -> None:
    with (
        mock.patch.object(init, "run", return_value=exit_codes.OK) as mock_init,
        mock.patch.object(fix, "run", return_value=exit_codes.OK) as mock_fix,
        mock.patch.object(
            verify, "run", return_value=exit_codes.OK
        ) as mock_verify,
    ):
      rc_no_init = cli_main.dispatch(
          "fix",
          self.adapter,
          repo=self.repo_dir,
          out=self.out_dir,
          finding=self.finding_path,
          auto_init=False,
      )
      self.assertEqual(rc_no_init, exit_codes.OK)
      mock_init.assert_not_called()
      mock_fix.assert_called_once()

      rc_verify = cli_main.dispatch(
          "verify",
          self.adapter,
          repo=self.repo_dir,
          out=self.out_dir,
          finding=self.finding_path,
      )
      self.assertEqual(rc_verify, exit_codes.OK)
      mock_init.assert_called_once()
      mock_verify.assert_called_once()

  def test_auto_init_failure_and_unknown_command_skip_command_execution(
      self,
  ) -> None:
    with (
        mock.patch.object(
            init, "run", return_value=exit_codes.FAILED
        ) as mock_init,
        mock.patch.object(
            find_diff, "run", return_value=exit_codes.OK
        ) as mock_find_diff,
    ):
      rc = cli_main.dispatch("find-diff", self.adapter, repo=self.repo_dir)
      self.assertEqual(rc, exit_codes.FAILED)
      mock_init.assert_called_once()
      mock_find_diff.assert_not_called()

      mock_init.reset_mock()
      self.assertEqual(
          cli_main.dispatch("unknown-cmd", self.adapter),
          exit_codes.USAGE,
      )
      mock_init.assert_not_called()


if __name__ == "__main__":
  unittest.main()
