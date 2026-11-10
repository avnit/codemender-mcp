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

"""`cm-runner verify` -- verify one finding and emit updated SARIF 2.1.0.

`main` has already checked that `cm` runs. `verify` then runs these steps in
order and stops at the first failure:

  1. Check the command line, then read the finding: a file, or stdin with
     `--finding -`. It must be a SARIF document holding exactly one result.
  2. Check the repository. It must be a Git working tree with no uncommitted
     work other than the files `cm` itself writes. `cm verify` starts with
     `git checkout HEAD -- . && git clean -fd`, which would otherwise throw
     that work away without warning.
  3. Import the finding into `cm`'s database and find the new ID `cm` gave it
     (any `finding_id` embedded in the input SARIF is ignored because
     `cm report import` assigns a fresh ID).
  4. Run `cm verify` on that ID, and reset the working tree afterwards
     (preserving `.cm_project` and `.exploit/`).
  5. Inspect the finding's status in `cm`'s database and update a copy of the
     SARIF document's metadata (`properties.status`, `properties.updated_at`,
     and `properties.dismiss_reason` / `suppressions` when `DISMISSED`). The
     input `--finding` file is never overwritten in place.
  6. Write the new SARIF file to `--out` if given (`<finding name>.sarif`), then
     write a single compact SARIF 2.1.0 JSON line to stdout.

On exit 2 or 3 nothing is written to stdout.

`cm` runs through `CmAdapter` with the runner's own environment (ADR-0003).
Git runs through `codemender.vcs.git`.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import logging
from pathlib import Path
from typing import Optional

from codemender import sarif
from codemender.cm import CmAdapter
from codemender.cm import Finding
from codemender.runner import exit_codes
from codemender.runner.commands import fix
from codemender.runner.events import EventEmitter
from codemender.vcs import git

logger = logging.getLogger(__name__)

# `cm verify` runs dynamic/agentic verification and needs the same ceiling as
# `cm fix`.
_VERIFY_TIMEOUT_SEC = 3000.0

# Lifecycle statuses written to the SARIF result properties.
_VERIFIED = "VERIFIED"
_DISMISSED = "DISMISSED"
_OPEN = "OPEN"

# Default fallback reason when `cm` marks a finding dismissed without a message.
_DEFAULT_DISMISS_REASON = (
    "Finding was demonstrated not exploitable by cm verify"
)

# Name of the `--out` SARIF file when the finding came from stdin.
_STDIN_SARIF_NAME = "finding"


@dataclasses.dataclass(frozen=True)
class VerifyConfig(fix.FixConfig):
  """Everything `verify` takes from the command line.

  Inherits `finding`, `repo`, `out`, path normalisation, and `validate()` from
  `fix.FixConfig`.
  """

  @property
  def sarif_file_name(self) -> str:
    """Name of the `--out` SARIF file: the finding file's name, as `.sarif`."""
    stem = self.finding.stem if self.finding is not None else _STDIN_SARIF_NAME
    return f"{stem}.sarif"


def config_from_args(args: argparse.Namespace) -> VerifyConfig:
  """Builds a VerifyConfig from the parsed command line."""
  return VerifyConfig(finding=args.finding, repo=args.repo, out=args.out)


def run(
    cfg: VerifyConfig,
    adapter: CmAdapter,
    emitter: EventEmitter,
) -> int:
  """Verifies one finding and writes the updated SARIF 2.1.0 to `--out` and stdout.

  Args:
    cfg: What to verify.
    adapter: The cm found and checked by `main`.
    emitter: Holds the real stdout, which receives the compact SARIF JSON line.

  Returns:
    `exit_codes.OK` when verification completed and the new SARIF was emitted,
    `exit_codes.USAGE` for a bad command line or invalid SARIF finding, and
    `exit_codes.FAILED` for anything else.
  """
  err = cfg.validate()
  if err != exit_codes.OK:
    return err
  finding_text = fix._read_finding(cfg, command="verify")  # pylint: disable=protected-access
  if finding_text is None:
    return exit_codes.USAGE

  if not fix._check_repository(cfg.repo, command="verify"):  # pylint: disable=protected-access
    return exit_codes.FAILED
  finding = fix._import(cfg, finding_text, adapter)  # pylint: disable=protected-access
  if finding is None:
    return exit_codes.FAILED
  if not _run_verify(cfg.repo, finding.finding_id, adapter):
    return exit_codes.FAILED

  verified = adapter.get_finding(
      finding.finding_id,
      timeout_sec=fix._CM_REPORT_TIMEOUT_SEC,  # pylint: disable=protected-access
  )
  if verified is None:
    return exit_codes.FAILED

  sarif_doc = sarif.SarifDocument.from_json(finding_text)
  _apply_verification_result(sarif_doc, verified)

  if cfg.out is not None and not _write_out_sarif(cfg, sarif_doc):
    return exit_codes.FAILED

  emitter.stream.write(sarif_doc.to_json() + "\n")
  emitter.stream.flush()
  return exit_codes.OK


def _run_verify(repo: Path, finding_id: str, adapter: CmAdapter) -> bool:
  """Runs `cm verify` once on `finding_id`. Retrying is left to the caller."""
  logger.info(
      "Running 'cm verify' on finding %s; cm's output is logged when it"
      " finishes.",
      finding_id,
  )
  verify_ok = False
  try:
    result = adapter.run(
        ["verify", "-y", "--bypass-warning", finding_id],
        cwd=repo.as_posix(),
        timeout_sec=_VERIFY_TIMEOUT_SEC,
    )
    logger.info("cm verify stdout:\n%s", result.stdout.rstrip())
    logger.info("cm verify stderr:\n%s", result.stderr.rstrip())
    if not result.ok:
      logger.error(
          "'cm verify %s' failed (exit %s, error %s).",
          finding_id,
          result.exit_code,
          result.error,
      )
    else:
      verify_ok = True
  finally:
    if not git.reset_working_tree(repo.as_posix(), exclude=fix._CM_OWN_PATHS):
      logger.error("Could not reset the working tree in %s with git.", repo)
      verify_ok = False
  return verify_ok


def _apply_verification_result(
    sarif_doc: sarif.SarifDocument, verified: Finding
) -> None:
  """Updates the SARIF result's `properties` based on the `Finding` status."""
  if verified.is_dismissed:
    reason = verified.dismiss_reason or _DEFAULT_DISMISS_REASON
    _update_sarif_status(sarif_doc, _DISMISSED, dismiss_reason=reason)
    logger.info(
        "Finding %s was dismissed by cm verify; marking %s (reason: %s).",
        verified.finding_id,
        _DISMISSED,
        reason,
    )
  elif verified.is_verified:
    _update_sarif_status(sarif_doc, _VERIFIED)
    logger.info(
        "Finding %s verified as a true positive (%s).",
        verified.finding_id,
        _VERIFIED,
    )
  else:
    status = verified.status or _OPEN
    _update_sarif_status(sarif_doc, status)
    logger.info(
        "Finding %s verification finished with status %s.",
        verified.finding_id,
        status,
    )


def _update_sarif_status(
    sarif_doc: sarif.SarifDocument,
    status: str,
    dismiss_reason: str = "",
    updated_at: Optional[str] = None,
) -> None:
  """Updates the SARIF result's `properties` and `suppressions` in place."""
  ts = updated_at or datetime.datetime.now(datetime.timezone.utc).strftime(
      "%Y-%m-%dT%H:%M:%SZ"
  )
  for result in sarif_doc.results:
    props = result.get("properties")
    if not isinstance(props, dict):
      props = {}
      result["properties"] = props
    props["status"] = status
    props["updated_at"] = ts
    if status == _DISMISSED:
      reason = dismiss_reason or _DEFAULT_DISMISS_REASON
      props["dismiss_reason"] = reason
      suppression_entry = {
          "kind": "external",
          "status": "accepted",
          "justification": reason,
      }
      suppressions = result.get("suppressions")
      if not isinstance(suppressions, list):
        result["suppressions"] = [suppression_entry]
      else:
        suppressions.append(suppression_entry)


def _write_out_sarif(cfg: VerifyConfig, sarif_doc: sarif.SarifDocument) -> bool:
  """Writes the new SARIF document to `--out`, before stdout emission."""
  assert cfg.out is not None
  target = cfg.out / cfg.sarif_file_name
  try:
    cfg.out.mkdir(parents=True, exist_ok=True)
    target.write_text(sarif_doc.to_json() + "\n", encoding="utf-8")
  except OSError as exc:
    logger.error("Could not write the SARIF report to %s: %s", target, exc)
    return False
  logger.info("Wrote the SARIF report to %s.", target)
  return True
