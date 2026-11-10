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

"""Entrypoint for the cm-runner command-line interface.

Run as:  python -m codemender.runner <command> [flags]
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import contextlib
import io
import logging
from pathlib import Path
import sys

from codemender.cm import CmAdapter
from codemender.runner import exit_codes
from codemender.runner.commands import find_diff
from codemender.runner.commands import fix
from codemender.runner.commands import version
from codemender.runner.events import EventEmitter

logger = logging.getLogger(__name__)

_LOG_LEVELS = ("debug", "info", "warning", "error")
_REPO_COMMANDS = ("init", "find-diff", "find-full", "fix", "verify")


def configure_logging(level: str) -> None:
  """Routes all logging to stderr.

  `force=True` tears down any handler a transitively imported module may have
  installed. This is deliberate belt-and-braces: the repo's `main.py` attaches
  a stdout handler at import time, and if it ever reaches us indirectly, a
  single stray log line would corrupt the event stream.

  Args:
    level: One of _LOG_LEVELS, case-insensitive.
  """
  logging.basicConfig(
      level=getattr(logging, level.upper(), logging.INFO),
      format="%(asctime)s [%(levelname)s] %(message)s",
      handlers=[logging.StreamHandler(sys.stderr)],
      force=True,
  )


def _global_flags() -> argparse.ArgumentParser:
  """Builds the flags shared by the root parser and every subcommand.

  Attaching these to both means `cm-runner --log-level debug version` and
  `cm-runner version --log-level debug` both work. argparse would otherwise
  only accept the first form, and the second is what people actually type.

  Every flag uses `default=argparse.SUPPRESS`. Without it, the subparser's
  defaults silently overwrite whatever the root parser already parsed, so
  `--log-level debug version` would quietly log at info -- the flag accepted
  and ignored, which is worse than rejecting it. SUPPRESS means the attribute is
  only set when the user actually passes the flag; `_apply_defaults` fills in
  the rest afterwards.
  """
  common = argparse.ArgumentParser(add_help=False)
  common.add_argument(
      "--cm-binary",
      default=argparse.SUPPRESS,
      metavar="PATH",
      help="path to the cm executable (default: first 'cm' on PATH)",
  )
  common.add_argument(
      "--log-level",
      choices=_LOG_LEVELS,
      default=argparse.SUPPRESS,
      help="stderr log verbosity (default: info)",
  )
  common.add_argument(
      "--no-init",
      dest="auto_init",
      action="store_false",
      default=argparse.SUPPRESS,
      help="skip automatic 'init' before running a repository command",
  )
  return common


# Applied after parsing, because the flags above use SUPPRESS.
_DEFAULTS = {
    "cm_binary": None,
    "log_level": "info",
    "auto_init": True,
}


def _apply_defaults(args: argparse.Namespace) -> argparse.Namespace:
  """Fills in any global flag the user did not supply."""
  for name, value in _DEFAULTS.items():
    if not hasattr(args, name):
      setattr(args, name, value)
  return args


def build_parser() -> argparse.ArgumentParser:
  """Constructs the argument parser for cm-runner."""
  common = _global_flags()

  parser = argparse.ArgumentParser(
      prog="cm-runner",
      parents=[common],
      description=(
          "Command-line interface to the CodeMender orchestrator. "
          "Emits NDJSON on stdout; all logging goes to stderr."
      ),
  )

  subparsers = parser.add_subparsers(dest="command", metavar="<command>")
  subparsers.add_parser(
      "version",
      parents=[common],
      help="report orchestrator, cm, and contract versions",
      description="Report orchestrator, cm, and contract versions.",
  )
  init_parser = subparsers.add_parser(
      "init",
      parents=[common],
      help="set up cm for a repository and check the result",
      description=(
          "Set up cm for a repository and check the result. Emits one "
          "'check' event per step; exits 3 if any check fails."
      ),
  )
  init_parser.add_argument(
      "--repo",
      default=".",
      metavar="PATH",
      help="the repository to set up (default: the current directory)",
  )
  find_diff_parser = subparsers.add_parser(
      "find-diff",
      parents=[common],
      help="scan git diff against a base reference and emit SARIF 2.1.0",
      description=(
          "Scan git diff against a base reference and emit compact SARIF 2.1.0"
          " JSON on stdout."
      ),
  )
  find_diff_parser.add_argument(
      "--repo",
      default=".",
      metavar="PATH",
      help="the repository to scan (default: the current directory)",
  )
  find_diff_parser.add_argument(
      "--base",
      default="HEAD",
      metavar="REF",
      help="the git reference to diff against (default: HEAD)",
  )
  find_diff_parser.add_argument(
      "--out",
      default=None,
      metavar="DIR",
      help="directory to write report.sarif and report.md artifacts",
  )
  find_diff_parser.add_argument(
      "--diff-workers",
      type=int,
      default=find_diff.DEFAULT_DIFF_WORKERS,
      metavar="N",
      help=(
          "number of concurrent cm diff workers, "
          f"{find_diff.MIN_DIFF_WORKERS}..{find_diff.MAX_DIFF_WORKERS} "
          f"(default: {find_diff.DEFAULT_DIFF_WORKERS})"
      ),
  )
  find_full_parser = subparsers.add_parser(
      "find-full",
      parents=[common],
      help="scan the whole repository and emit SARIF 2.1.0",
      description=(
          "Scan every file in the repository (no diff base) and emit compact"
          " SARIF 2.1.0 JSON on stdout."
      ),
  )
  find_full_parser.add_argument(
      "--repo",
      default=".",
      metavar="PATH",
      help="the repository to scan (default: the current directory)",
  )
  find_full_parser.add_argument(
      "--out",
      default=None,
      metavar="DIR",
      help="directory to write report.sarif and report.md artifacts",
  )
  fix_parser = subparsers.add_parser(
      "fix",
      parents=[common],
      help="patch one finding and print the patch as a unified diff",
      description=(
          "Run 'cm fix' on one finding and print the resulting patch on"
          " stdout as a unified diff, ready for 'git apply'. Refuses to run"
          " on a repository with uncommitted work, which 'cm fix' would"
          " discard."
      ),
  )
  fix_parser.add_argument(
      "--finding",
      required=True,
      metavar="FILE",
      help=(
          "SARIF file holding exactly one finding, or '-' to read it from stdin"
      ),
  )
  fix_parser.add_argument(
      "--repo",
      default=".",
      metavar="PATH",
      help="the repository to fix (default: the current directory)",
  )
  fix_parser.add_argument(
      "--out",
      default=None,
      metavar="DIR",
      help="directory to also write the patch to, as <finding name>.diff",
  )
  verify_parser = subparsers.add_parser(
      "verify",
      parents=[common],
      help="verify one finding and emit updated SARIF 2.1.0",
      description=(
          "Run 'cm verify' on one finding and emit the resulting SARIF 2.1.0"
          " document on stdout. Refuses to run on a repository with"
          " uncommitted work, which 'cm verify' would discard."
      ),
  )
  verify_parser.add_argument(
      "--finding",
      required=True,
      metavar="FILE",
      help=(
          "SARIF file holding exactly one finding, or '-' to read it from stdin"
      ),
  )
  verify_parser.add_argument(
      "--repo",
      default=".",
      metavar="PATH",
      help="the repository to verify against (default: the current directory)",
  )
  verify_parser.add_argument(
      "--out",
      default=None,
      metavar="DIR",
      help=(
          "directory to also write the resulting SARIF document to, as"
          " <finding name>.sarif"
      ),
  )
  return parser


def dispatch(
    command: str,
    adapter: CmAdapter,
    *,
    repo: Path | str = ".",
    base: str = "HEAD",
    out: Path | str | None = None,
    finding: Path | str | None = None,
    diff_workers: int | None = None,
    auto_init: bool = True,
    emitter: EventEmitter | None = None,
) -> int:
  """Executes a `cm-runner` repository subcommand with stdout isolation.

  Args:
    command: Repository subcommand name (`"init"`, `"find-diff"`,
      `"find-full"`, `"fix"`, or `"verify"`).
    adapter: Verified `CmAdapter` instance.
    repo: Target Git repository directory path.
    base: Base Git reference for `find-diff` (default: `"HEAD"`).
    out: Optional directory path for output artifacts.
    finding: Optional single-finding SARIF path (or `"-"`) for `fix`/`verify`.
    diff_workers: Optional concurrent `cm find --diff` worker count (`None`
      uses `FindDiffConfig`'s default).
    auto_init: Whether to run `init` automatically before repository commands.
    emitter: Optional `EventEmitter` for stdout payloads; defaults to a discard
      in-memory stream for `find-diff`, `fix`, and `verify` (`None` for `init`).

  Returns:
    A process exit code from `codemender.runner.exit_codes`.
  """
  if command not in _REPO_COMMANDS:
    return exit_codes.USAGE

  repo_path = Path(repo).expanduser().resolve()
  out_path = Path(out).expanduser().resolve() if out is not None else None
  cmd_emitter = (
      emitter if emitter is not None else EventEmitter(stream=io.StringIO())
  )
  with contextlib.redirect_stdout(sys.stderr):
    if command != "init" and auto_init:
      # Imported lazily so `cm-runner version` does not pull in `yaml`.
      # pylint: disable-next=import-outside-toplevel
      from codemender.runner.commands import init

      init_rc = init.run(init.InitConfig(repo=repo_path), adapter, emitter=None)
      if init_rc != exit_codes.OK:
        return init_rc

    if command == "init":
      # Imported lazily so `cm-runner version` does not pull in `yaml`.
      # pylint: disable-next=import-outside-toplevel
      from codemender.runner.commands import init

      return init.run(init.InitConfig(repo=repo_path), adapter, emitter)
    if command == "find-diff":
      return find_diff.run(
          find_diff.FindDiffConfig(
              repo=repo_path,
              base=base,
              out=out_path,
              diff_workers=diff_workers,
          ),
          adapter,
          cmd_emitter,
      )
    if command == "find-full":
      return find_diff.run(
          find_diff.FindDiffConfig(repo=repo_path, out=out_path, full_scan=True),
          adapter,
          cmd_emitter,
      )
    if command == "fix":
      return fix.run(
          fix.FixConfig(finding=finding, repo=repo_path, out=out_path),
          adapter,
          cmd_emitter,
      )
    # pylint: disable-next=import-outside-toplevel
    from codemender.runner.commands import verify

    return verify.run(
        verify.VerifyConfig(finding=finding, repo=repo_path, out=out_path),
        adapter,
        cmd_emitter,
    )


def main(argv: Sequence[str] | None = None) -> int:
  """Parses arguments and dispatches to a subcommand.

  Args:
    argv: Argument vector excluding the program name. Defaults to
      `sys.argv[1:]`.

  Returns:
    A process exit code from `codemender.runner.exit_codes`.
  """
  parser = build_parser()
  args = _apply_defaults(parser.parse_args(argv))

  configure_logging(args.log_level)

  if not args.command:
    # No subcommand: usage goes to stderr so stdout stays clean even here.
    parser.print_help(sys.stderr)
    return exit_codes.USAGE

  # Events go to the real stdout. While the command runs, anything else
  # written through `sys.stdout` lands on stderr instead. That covers helpers
  # a command may call that print to stdout, such as the legacy
  # `utils.run_command` reached through `vcs/git.py`, so they cannot corrupt
  # the event stream. `cm` itself runs through `codemender.cm.CmAdapter`,
  # which captures its output.
  emitter = EventEmitter(stream=sys.stdout)

  # Every command needs `cm`, so it is checked once, here, before any command
  # starts. A command is only ever given an adapter that works.
  adapter = _find_cm(args.cm_binary)
  if adapter is None:
    return exit_codes.FAILED

  if args.command == "version":
    with contextlib.redirect_stdout(sys.stderr):
      return version.run(adapter, emitter)

  return dispatch(
      args.command,
      adapter,
      repo=getattr(args, "repo", "."),
      base=getattr(args, "base", "HEAD"),
      out=getattr(args, "out", None),
      finding=getattr(args, "finding", None),
      diff_workers=getattr(args, "diff_workers", None),
      auto_init=args.auto_init,
      emitter=emitter,
  )


def _find_cm(binary: str | None) -> CmAdapter | None:
  """Finds `cm` and checks that it runs.

  `CmAdapter.locate` only finds a path: an explicit `--cm-binary` is not
  checked at all, and a PATH lookup only confirms there is an executable file
  named `cm`. Running `cm --version` is what catches a wrong path, a binary
  built for another CPU, or a broken download.

  On failure the reason goes to stderr and nothing is written to stdout, so a
  failed run never leaves a line that looks like a result (ADR-0001).

  Args:
    binary: The `--cm-binary` flag, or None to look `cm` up on PATH.

  Returns:
    An adapter whose `cm --version` worked, or None if `cm` is missing or
    will not run.
  """
  adapter = CmAdapter.locate(binary)
  if adapter is None:
    logger.error("cm not found on PATH. Install it, or pass --cm-binary.")
    return None
  if adapter.version() is None:
    # `version()` has already logged why.
    logger.error("%s did not run 'cm --version'.", adapter.binary)
    return None
  return adapter


if __name__ == "__main__":
  sys.exit(main())
