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

"""Unit tests for `codemender.sarif`."""

import hashlib
import json
from typing import Any, Dict
import unittest

from codemender import sarif


def _cm_sarif() -> Dict[str, Any]:
  """Returns a SARIF log shaped like `cm report --format sarif` output.

  Like cm, every result has a `security-severity` property and no
  `fingerprints` or `partialFingerprints`. Two results share `"7.5"`.
  """
  rules, results = [], []
  for severity, rule_id, uri, start_line, title in (
      ("9.0", "CWE-89", "routes/login.ts", 34, "SQL injection"),
      ("7.5", "CWE-79", "routes/search.ts", 10, "Reflected XSS"),
      ("7.5", "CWE-22", "routes/fileServer.ts", 52, "Path traversal"),
  ):
    rules.append({
        "id": rule_id,
        "shortDescription": {"text": rule_id},
        "properties": {"security-severity": severity},
    })
    results.append({
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": title, "markdown": f"**{title}**"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": start_line, "endLine": start_line + 2},
            }
        }],
        "properties": {"security-severity": severity},
    })
  driver = {"name": "CodeMender", "version": "dev", "rules": rules}
  return {
      "version": "2.1.0",
      "runs": [{"tool": {"driver": driver}, "results": results}],
  }


def _hash_id(path: str, rule_id: str, start_line: int, message: str) -> str:
  """Returns the 12-hex REQ-0009 hash of path, rule ID, start line, message."""
  key = f"{path}|{rule_id}|{start_line}|{message}"
  return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


class TestSarifDocument(unittest.TestCase):
  """Tests for `SarifDocument` parsing, inspection, and serialization."""

  def test_from_json_valid_sarif(self) -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "cm"}},
                "results": [
                    {"ruleId": "CWE-787", "message": {"text": "oob write"}},
                ],
            }
        ],
    }
    doc = sarif.SarifDocument.from_json(json.dumps(payload, indent=2))
    self.assertEqual(doc.result_count, 1)
    self.assertEqual(len(doc.runs), 1)
    self.assertEqual(len(doc.results), 1)
    self.assertEqual(doc.results[0]["ruleId"], "CWE-787")

  def test_from_json_multiple_runs_and_empty_results(self) -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {"results": [{"ruleId": "R1"}, {"ruleId": "R2"}]},
            {"results": []},
            {"tool": {"driver": {"name": "no-results-key"}}},
            "ignore-non-dict-run",
            {"results": [{"ruleId": "R3"}, "ignore-non-dict-result"]},
        ],
    }
    doc = sarif.SarifDocument.from_dict(payload)
    # `result_count` counts total entries in `results` lists (including non-dict
    # items if any), whereas `.results` filters to dict items.
    self.assertEqual(doc.result_count, 4)
    self.assertEqual([r["ruleId"] for r in doc.results], ["R1", "R2", "R3"])

  def test_from_json_invalid_json_raises_sarif_json_error(self) -> None:
    with self.assertRaises(sarif.SarifJsonError) as ctx:
      sarif.SarifDocument.from_json("{not valid json")
    self.assertIsInstance(ctx.exception, sarif.SarifError)

  def test_from_json_non_dict_or_missing_runs_raises_schema_error(self) -> None:
    for invalid in ["[]", '{"version": "2.1.0"}', '{"runs": "not-a-list"}']:
      with self.subTest(invalid=invalid):
        with self.assertRaises(sarif.SarifSchemaError) as ctx:
          sarif.SarifDocument.from_json(invalid)
        self.assertIsInstance(ctx.exception, sarif.SarifError)
        self.assertIn("runs", str(ctx.exception))

  def test_to_json_is_single_line_by_default(self) -> None:
    doc = sarif.SarifDocument.from_dict({"version": "2.1.0", "runs": []})
    serialized = doc.to_json()
    self.assertNotIn("\n", serialized)
    self.assertEqual(json.loads(serialized), {"version": "2.1.0", "runs": []})
    self.assertEqual(doc.active_result_count, 0)

  def test_active_result_count_excludes_dismissed_and_suppressed(self) -> None:
    doc = sarif.SarifDocument.from_dict({
        "version": "2.1.0",
        "runs": [{
            "results": [
                {"ruleId": "R1"},
                {"ruleId": "R2", "properties": {"status": "DISMISSED"}},
                {"ruleId": "R3", "suppressions": [{"kind": "inSource"}]},
                {"ruleId": "R4", "suppressions": []},
                {"ruleId": "R5", "properties": {"status": "FALSE_POSITIVE"}},
                "non-dict-ignored",
            ]
        }],
    })
    self.assertEqual(doc.active_result_count, 2)


# Governing: docs/openspec/specs/github-actions-fix/spec.md#req-0009
class TestFindingId(unittest.TestCase):
  """Tests how `SarifDocument.to_findings()` picks `Finding.finding_id`."""

  def test_cm_results_sharing_a_severity_get_distinct_hash_ids(self) -> None:
    text = json.dumps(_cm_sarif())
    findings = sarif.SarifDocument.from_json(text).to_findings()
    ids = [finding.finding_id for finding in findings]
    self.assertEqual(len(set(ids)), len(ids), ids)
    for finding_id in ids:
      self.assertNotIn(finding_id, ("9.0", "7.5", "5.0", "2.0"))
    self.assertEqual(
        ids,
        [
            _hash_id("routes/login.ts", "CWE-89", 34, "SQL injection"),
            _hash_id("routes/search.ts", "CWE-79", 10, "Reflected XSS"),
            _hash_id("routes/fileServer.ts", "CWE-22", 52, "Path traversal"),
        ],
    )
    findings_again = sarif.SarifDocument.from_json(text).to_findings()
    self.assertEqual([finding.finding_id for finding in findings_again], ids)

  def test_non_identifier_properties_are_ignored(self) -> None:
    report = _cm_sarif()
    report["runs"][0]["results"][1]["properties"] = {
        "status": "OPEN",
        "updated_at": "2026-10-30T00:00:00Z",
        "dismiss_reason": "not exploitable",
    }
    findings = sarif.SarifDocument.from_dict(report).to_findings()
    self.assertEqual(
        findings[1].finding_id,
        _hash_id("routes/search.ts", "CWE-79", 10, "Reflected XSS"),
    )

  def test_cm_finding_id_property_is_ignored(self) -> None:
    # cm's internal finding IDs change on every run (ADR-0006).
    report = _cm_sarif()
    report["runs"][0]["results"][0]["properties"] = {
        "finding_id": "9f7b066a-0d33-5ced-b834-9ad42e83aa40",
        "confidence": 100,
        "status": "OPEN",
    }
    findings = sarif.SarifDocument.from_dict(report).to_findings()
    self.assertEqual(
        findings[0].finding_id,
        _hash_id("routes/login.ts", "CWE-89", 34, "SQL injection"),
    )

  def test_fingerprints_win_over_partial_fingerprints(self) -> None:
    report = _cm_sarif()
    result = report["runs"][0]["results"][1]
    result["fingerprints"] = {"primary": "abc123"}
    result["partialFingerprints"] = {"primaryLocationLineHash": "def456"}
    findings = sarif.SarifDocument.from_dict(report).to_findings()
    self.assertEqual(findings[1].finding_id, "abc123")

  def test_partial_fingerprints_are_used_without_fingerprints(self) -> None:
    # `@cm-runner verify` stores the finding ID in `partialFingerprints`.
    report = _cm_sarif()
    report["runs"][0]["results"][1]["partialFingerprints"] = {
        "primaryLocationLineHash": "aabbcc112233"
    }
    findings = sarif.SarifDocument.from_dict(report).to_findings()
    self.assertEqual(findings[1].finding_id, "aabbcc112233")


if __name__ == "__main__":
  unittest.main()
