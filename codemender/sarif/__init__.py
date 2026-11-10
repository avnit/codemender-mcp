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

"""SARIF 2.1.0 document abstraction for `cm-runner` CLI commands."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import posixpath
from typing import Any, Dict, List, Optional, Tuple

from codemender.cm import Finding

FINGERPRINT_LENGTH = 12


class SarifError(ValueError):
  """Base error for invalid SARIF input."""


class SarifJsonError(SarifError):
  """Raised when SARIF text is not valid JSON."""


class SarifSchemaError(SarifError):
  """Raised when parsed JSON does not match the expected SARIF structure."""


@dataclasses.dataclass(frozen=True)
class SarifDocument:
  """Wraps a parsed OASIS SARIF 2.1.0 JSON document.

  Provides a single abstraction layer for validating, inspecting, splitting,
  and serializing SARIF reports across `find-diff`, `fix`, `verify`, and CI
  integrations without coupling callers to raw dictionary traversal.

  Attributes:
    data: The underlying SARIF JSON object (`dict`).
  """

  data: Dict[str, Any]

  @classmethod
  def from_json(cls, text: str) -> "SarifDocument":
    """Parses and validates a SARIF document from a JSON string.

    Args:
      text: Raw JSON string.

    Returns:
      A validated `SarifDocument`.

    Raises:
      SarifJsonError: If `text` is not valid JSON.
      SarifSchemaError: If the parsed JSON is not a dict with a `'runs'` list.
    """
    try:
      raw = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
      raise SarifJsonError(str(exc)) from exc
    return cls.from_dict(raw)

  @classmethod
  def from_dict(cls, raw: Any) -> "SarifDocument":
    """Validates an already-parsed JSON value as a `SarifDocument`.

    Args:
      raw: Parsed JSON value.

    Returns:
      A validated `SarifDocument`.

    Raises:
      SarifSchemaError: If `raw` is not a dict with a `'runs'` list.
    """
    if not isinstance(raw, dict) or not isinstance(raw.get("runs"), list):
      raise SarifSchemaError(
          "expected a JSON object with a 'runs' list (no 'runs' list found)."
      )
    return cls(data=raw)

  @property
  def runs(self) -> List[Dict[str, Any]]:
    """Returns all dict entries in the top-level `'runs'` list."""
    return [
        run_entry
        for run_entry in self.data.get("runs", [])
        if isinstance(run_entry, dict)
    ]

  @property
  def results(self) -> List[Dict[str, Any]]:
    """Returns all finding result objects across all `runs`."""
    items: List[Dict[str, Any]] = []
    for run_entry in self.runs:
      run_results = run_entry.get("results")
      if isinstance(run_results, list):
        items.extend(r for r in run_results if isinstance(r, dict))
    return items

  @property
  def result_count(self) -> int:
    """Returns the total number of finding entries across all `runs`."""
    return sum(
        len(run_entry["results"])
        for run_entry in self.runs
        if isinstance(run_entry.get("results"), list)
    )

  @property
  def active_result_count(self) -> int:
    """Returns the number of non-dismissed finding entries across `runs`."""
    return sum(
        1 for item in self.results if not _is_result_dismissed(item)
    )

  def to_json(self, indent: Optional[int] = None) -> str:
    """Serializes the SARIF document to JSON (compact 1-line by default).

    Args:
      indent: Optional JSON indentation width. `None` emits compact 1-line JSON.

    Returns:
      Serialized JSON string.
    """
    return json.dumps(self.data, indent=indent)

  def to_findings(self) -> List[Finding]:
    """Converts the SARIF report into one `Finding` per result.

    Each returned `Finding` carries a single-result SARIF `document` that keeps
    its enclosing run's metadata (`tool`, `rules`, `artifacts`, etc.) intact.

    Returns:
      List of `Finding` instances in report order (1-based `index`).
    """
    findings: List[Finding] = []
    for run_entry in self.runs:
      run_results = run_entry.get("results")
      if not isinstance(run_results, list):
        continue
      for result in run_results:
        if not isinstance(result, dict):
          continue
        path, start_line, end_line = _primary_location(result)
        rule_id = _resolve_rule_id(run_entry, result)
        msg_obj = result.get("message")
        msg_text = msg_obj.get("text") if isinstance(msg_obj, dict) else ""
        message = msg_text.strip() if isinstance(msg_text, str) else ""
        level = str(result.get("level") or "warning").strip().lower()
        finding_id = _extract_or_compute_fingerprint(
            result, path, rule_id, message, start_line
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                file_path=path,
                index=len(findings) + 1,
                start_line=start_line,
                end_line=end_line,
                rule_id=rule_id,
                level=level,
                severity=level.upper(),
                message=message,
                document=_single_result_doc(self.data, run_entry, result),
            )
        )
    return findings


def normalize_sarif_path(uri: str) -> str:
  """Normalizes a SARIF `artifactLocation.uri` to a safe repo-relative path.

  Args:
    uri: Raw `artifactLocation.uri` string from a SARIF result.

  Returns:
    Normalized forward-slash relative path, or `""` if empty or outside the
    repository root (`..`).
  """
  text = (uri or "").strip().replace("\\", "/").lstrip("/")
  if not text:
    return ""
  text = posixpath.normpath(text)
  if text in (".", "..") or text.startswith("../"):
    return ""
  return text


def _is_result_dismissed(result: Dict[str, Any]) -> bool:
  """Returns whether `result` is marked dismissed or suppressed."""
  props = result.get("properties")
  if isinstance(props, dict) and props.get("status") in (
      "DISMISSED",
      "FALSE_POSITIVE",
  ):
    return True
  suppressions = result.get("suppressions")
  return isinstance(suppressions, list) and bool(suppressions)


def _primary_location(result: Dict[str, Any]) -> Tuple[str, int, int]:
  """Extracts `(path, start_line, end_line)` from a SARIF result's first location."""
  locations = result.get("locations")
  if not isinstance(locations, list) or not locations:
    return ("", 0, 0)
  first = locations[0] if isinstance(locations[0], dict) else {}
  phys = first.get("physicalLocation")
  phys = phys if isinstance(phys, dict) else {}
  artifact = phys.get("artifactLocation")
  uri = artifact.get("uri") if isinstance(artifact, dict) else ""
  path = normalize_sarif_path(uri) if isinstance(uri, str) else ""

  region = phys.get("region")
  region = region if isinstance(region, dict) else {}
  start = region.get("startLine")
  if not (isinstance(start, int) and not isinstance(start, bool) and start > 0):
    return (path, 0, 0)
  end = region.get("endLine")
  if not (isinstance(end, int) and not isinstance(end, bool) and end >= start):
    end = start
  return (path, start, end)


def _resolve_rule_id(run_entry: Dict[str, Any], result: Dict[str, Any]) -> str:
  """Resolves the rule ID for `result` within `run_entry`."""
  for candidate in (
      result.get("ruleId"),
      (result.get("rule") or {}).get("id")
      if isinstance(result.get("rule"), dict)
      else None,
  ):
    if isinstance(candidate, str) and candidate.strip():
      return candidate.strip()

  idx = result.get("ruleIndex")
  if not (isinstance(idx, int) and not isinstance(idx, bool) and idx >= 0):
    rule = result.get("rule")
    idx = rule.get("index") if isinstance(rule, dict) else None
  driver = ((run_entry.get("tool") or {}).get("driver") or {})
  rules = driver.get("rules") if isinstance(driver, dict) else None
  if (
      isinstance(idx, int)
      and not isinstance(idx, bool)
      and 0 <= idx < len(rules or ())
      and isinstance(rules[idx], dict)
  ):
    rule_id = rules[idx].get("id")
    if isinstance(rule_id, str):
      return rule_id.strip()
  return ""


# Governing: docs/openspec/specs/github-actions-fix/spec.md#req-0009
def _extract_or_compute_fingerprint(
    result: Dict[str, Any],
    path: str,
    rule_id: str,
    message: str,
    start_line: int,
) -> str:
  """Returns the finding's ID from SARIF fingerprints, or a deterministic hash.

  The `properties` bag holds shared non-identifier values such as
  `security-severity`, so it is never used.
  """
  for bag_name in ("fingerprints", "partialFingerprints"):
    bag = result.get(bag_name)
    if isinstance(bag, dict):
      for val in bag.values():
        if isinstance(val, str) and val.strip():
          return val.strip()
  key = f"{path}|{rule_id}|{start_line}|{message}"
  return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[
      :FINGERPRINT_LENGTH
  ]


def _single_result_doc(
    report: Dict[str, Any],
    run_entry: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
  """Returns an independent copy of `report` trimmed to `result`."""
  doc = {
      k: (
          [
              {
                  rk: ([result] if rk == "results" else rv)
                  for rk, rv in run_entry.items()
              }
          ]
          if k == "runs"
          else v
      )
      for k, v in report.items()
  }
  return copy.deepcopy(doc)

