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

"""`cm-runner find-diff` -- impact-aware differential vulnerability scan.

Runs CodeMender's differential scanner (`cm find <repo> -y --bypass-warning
--diff=<base> --diff-workers=<N> --fail-on NONE`) followed by report extraction (`cm report
--format sarif`, and `cm report --format md` when `--out` is given) through
`CmAdapter`.

On success, writes a single compact (1-line) OASIS SARIF v2.1.0 JSON document to
stdout and logs human-readable progress and summaries to stderr. On any usage
(exit 2) or execution (exit 3) failure, writes zero bytes to stdout.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
from pathlib import Path

from codemender import sarif
from codemender.cm import CmAdapter
from codemender.runner import exit_codes
from codemender.runner.events import EventEmitter
from codemender.vcs import git

logger = logging.getLogger(__name__)

# Outer timeout circuit breakers:
# `cm find --diff` enforces a per-file session timeout (`--diff-job-timeout`,
# default 10m, scaling up to 20m for files >32 KB); 1800s (30m) matches
# `_FIX_TIMEOUT_SEC` and `_VERIFY_TIMEOUT_SEC` while giving `cm` headroom to
# cancel remote LROs cleanly before terminating the child.
_FIND_DIFF_TIMEOUT_SEC = 1800.0
_CM_REPORT_TIMEOUT_SEC = 60.0
# A full-repository scan covers every file rather than a PR diff, so it gets a
# longer circuit breaker (3h). The Cloud Run Job timeout must be at least this.
_FIND_FULL_TIMEOUT_SEC = 10800.0

# Concurrent `cm find --diff` worker bounds and default (1..16 supported by cm;
# cm's own built-in default is 4).
MIN_DIFF_WORKERS = 1
MAX_DIFF_WORKERS = 16
DEFAULT_DIFF_WORKERS = 8


@dataclasses.dataclass
class FindDiffConfig:
  """Command-line configuration for `cm-runner find-diff`.

  Attributes:
    repo: Target Git repository path, resolved to an absolute path.
    base: Target Git reference to diff against (default: "HEAD").
    out: Optional directory path where `report.sarif` and `report.md` are
      written.
    diff_workers: Number of concurrent `cm find --diff` workers (default: 8,
      valid range: 1..16).
    full_scan: When True, scan the whole repository (`cm find <repo>` without
      `--diff`) instead of only the changes against `base`. Used by
      `cm-runner find-full` and the MCP server's `cm_find` tool.
  """

  repo: Path
  base: str = "HEAD"
  out: Path | None = None
  diff_workers: int | None = DEFAULT_DIFF_WORKERS
  full_scan: bool = False

  def __post_init__(self) -> None:
    if isinstance(self.base, str):
      self.base = self.base.strip()
    if self.diff_workers is None:
      self.diff_workers = DEFAULT_DIFF_WORKERS

  def validate(self) -> int:
    """Validates command-line options and Git pre-flight checks before running `cm`.

    Returns:
      `exit_codes.OK` when all options and Git pre-flight checks pass,
      `exit_codes.USAGE` when CLI options are invalid, or `exit_codes.FAILED`
      when `--repo` is not a Git working tree or `--base` does not resolve to
      a valid commit.
    """
    if not self.repo.is_dir():
      logger.error("--repo %s is not a directory.", self.repo)
      return exit_codes.USAGE
    if not isinstance(self.base, str) or not self.base:
      logger.error("--base must be a non-empty Git reference.")
      return exit_codes.USAGE
    if self.out is not None and self.out.exists() and not self.out.is_dir():
      logger.error("--out %s exists and is not a directory.", self.out)
      return exit_codes.USAGE
    if (
        isinstance(self.diff_workers, bool)
        or not isinstance(self.diff_workers, int)
        or not (MIN_DIFF_WORKERS <= self.diff_workers <= MAX_DIFF_WORKERS)
    ):
      logger.error(
          "--diff-workers must be an integer between %d and %d (got %r).",
          MIN_DIFF_WORKERS,
          MAX_DIFF_WORKERS,
          self.diff_workers,
      )
      return exit_codes.USAGE

    # Pre-flight checks: verify target directory is a Git working tree and base
    # reference resolves to an existing commit before spawning `cm`.
    if not git.is_git_repository(self.repo.as_posix()):
      logger.error("--repo %s is not inside a Git working tree.", self.repo)
      return exit_codes.FAILED

    if not self.full_scan and not git.ref_exists(
        self.repo.as_posix(), self.base
    ):
      logger.error(
          "--base reference %r does not exist or is invalid in %s.",
          self.base,
          self.repo,
      )
      return exit_codes.FAILED

    return exit_codes.OK


def config_from_args(args: argparse.Namespace) -> FindDiffConfig:
  """Builds a normalized `FindDiffConfig` from parsed CLI arguments."""
  repo_arg = getattr(args, "repo", ".")
  base_arg = getattr(args, "base", "HEAD")
  out_arg = getattr(args, "out", None)
  diff_workers_arg = getattr(args, "diff_workers", None)
  return FindDiffConfig(
      repo=Path(repo_arg).expanduser().resolve(),
      base=base_arg,
      out=(
          Path(out_arg).expanduser().resolve()
          if out_arg is not None
          else None
      ),
      diff_workers=diff_workers_arg,
  )


def run(
    cfg: FindDiffConfig,
    adapter: CmAdapter,
    emitter: EventEmitter,
) -> int:
  """Executes the differential scan and emits compact SARIF 2.1.0 on stdout.

  Args:
    cfg: Validated or unvalidated `FindDiffConfig`.
    adapter: Verified `CmAdapter` instance.
    emitter: Destination stream wrapper for stdout output.

  Returns:
    `exit_codes.OK` (0) on success, `exit_codes.USAGE` (2) on invalid CLI
    arguments, or `exit_codes.FAILED` (3) on pre-flight, execution, parse, or
    artifact write failure.
  """
  err = cfg.validate()
  if err != exit_codes.OK:
    return err

  # Step 1: Differential scan via `cm find --diff`.
  # `--bypass-warning` accepts `cm`'s responsibility warning on the caller's
  # behalf, matching fix.py and verify.py; there is no terminal to ask in CI.
  find_args = ["find", cfg.repo.as_posix(), "-y", "--bypass-warning"]
  if not cfg.full_scan:
    find_args += [f"--diff={cfg.base}", f"--diff-workers={cfg.diff_workers}"]
  find_args += ["--fail-on", "NONE"]
  find_result = adapter.run(
      find_args,
      cwd=cfg.repo.as_posix(),
      timeout_sec=(
          _FIND_FULL_TIMEOUT_SEC if cfg.full_scan else _FIND_DIFF_TIMEOUT_SEC
      ),
  )
  logger.info("cm find --diff stdout:\n%s", find_result.stdout.rstrip())
  logger.info("cm find --diff stderr:\n%s", find_result.stderr.rstrip())

  if not find_result.ok:
    logger.error(
        "'cm find --diff=%s' failed (exit %s, error %s). stderr:\n%s",
        cfg.base,
        find_result.exit_code,
        find_result.error,
        find_result.stderr,
    )
    return exit_codes.FAILED

  # Step 2: Extract SARIF 2.1.0 report via `cm report --format sarif`.
  sarif_result = adapter.run(
      ["report", "--format", "sarif"],
      cwd=cfg.repo.as_posix(),
      timeout_sec=_CM_REPORT_TIMEOUT_SEC,
  )
  if sarif_result.stderr.strip():
    logger.debug(
        "cm report --format sarif stderr:\n%s", sarif_result.stderr.rstrip()
    )

  if not sarif_result.ok:
    logger.error(
        "'cm report --format sarif' failed (exit %s, error %s). stderr:\n%s",
        sarif_result.exit_code,
        sarif_result.error,
        sarif_result.stderr,
    )
    return exit_codes.FAILED

  try:
    sarif_doc = sarif.SarifDocument.from_json(sarif_result.stdout)
  except sarif.SarifJsonError as exc:
    logger.error(
        "Could not parse SARIF JSON from 'cm report --format sarif': %s", exc
    )
    return exit_codes.FAILED
  except sarif.SarifSchemaError as exc:
    logger.error(
        "Invalid SARIF 2.1.0 structure from 'cm report --format sarif': %s",
        exc,
    )
    return exit_codes.FAILED

  # Step 3: Optional `--out` artifact generation (`report.sarif` & `report.md`)
  # performed prior to stdout emission to preserve failure atomicity.
  if cfg.out is not None:
    md_result = adapter.run(
        ["report", "--format", "md"],
        cwd=cfg.repo.as_posix(),
        timeout_sec=_CM_REPORT_TIMEOUT_SEC,
    )
    if md_result.stderr.strip():
      logger.debug(
          "cm report --format md stderr:\n%s", md_result.stderr.rstrip()
      )
    if not md_result.ok:
      logger.error(
          "'cm report --format md' failed (exit %s, error %s). stderr:\n%s",
          md_result.exit_code,
          md_result.error,
          md_result.stderr,
      )
      return exit_codes.FAILED

    try:
      cfg.out.mkdir(parents=True, exist_ok=True)
      (cfg.out / "report.sarif").write_text(
          sarif_result.stdout, encoding="utf-8"
      )
      (cfg.out / "report.md").write_text(md_result.stdout, encoding="utf-8")
    except OSError as exc:
      logger.error(
          "Could not write report artifacts to --out %s: %s", cfg.out, exc
      )
      return exit_codes.FAILED

  finding_count = sarif_doc.result_count
  if finding_count == 0:
    logger.info(
        "cm-runner find-diff completed cleanly against %s: 0 findings.",
        cfg.base,
    )
  else:
    logger.info(
        "cm-runner find-diff completed against %s: %d finding(s).",
        cfg.base,
        finding_count,
    )

  emitter.stream.write(sarif_doc.to_json() + "\n")
  emitter.stream.flush()
  return exit_codes.OK
