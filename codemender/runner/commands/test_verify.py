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

"""Tests for `cm-runner verify` (SPEC-VERIFY)."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Sequence, Tuple
import unittest
from unittest import mock

_PKG_DIR = str(Path(__file__).resolve().parents[3])
if _PKG_DIR not in sys.path:
  sys.path.insert(0, _PKG_DIR)

from codemender.cm import CmAdapter, CmResult, TokenUsage
from codemender.runner import __main__ as cli_main
from codemender.runner import exit_codes
from codemender.runner.commands import verify
from codemender.runner.events import EventEmitter

_SAMPLE_FINDING_PATH = (
    Path(__file__).resolve().parent / "testdata" / "cm_finding.json"
)
_EMBEDDED_SAMPLE_ID = "9f7b066a-0d33-5ced-b834-9ad42e83aa40"

_APP_PY = (
    "import os\n"
    "import sys\n"
    "\n"
    "\n"
    "def ping(host):\n"
    '    return os.system("ping -c 1 " + host)\n'
)


def _sarif(result_count: int = 1) -> str:
  """Returns a SARIF 2.1.0 document holding `result_count` results."""
  if result_count == 1:
    return _SAMPLE_FINDING_PATH.read_text(encoding="utf-8")
  doc = json.loads(_SAMPLE_FINDING_PATH.read_text(encoding="utf-8"))
  doc["runs"][0]["results"] = doc["runs"][0]["results"] * result_count
  return json.dumps(doc)


def _ok(args: Sequence[str], stdout: str = "", stderr: str = "") -> CmResult:
  return CmResult(
      args=("/fake/bin/cm", *args),
      exit_code=0,
      stdout=stdout,
      stderr=stderr,
      tokens=TokenUsage(),
  )


def _failed(args: Sequence[str], stderr: str, exit_code: int = 1) -> CmResult:
  return CmResult(
      args=("/fake/bin/cm", *args),
      exit_code=exit_code,
      stdout="",
      stderr=stderr,
      tokens=TokenUsage(),
  )


class FakeVerifyCm(CmAdapter):
  """In-process `cm` double supporting `report`, `report import`, and `verify`."""

  def __init__(
      self,
      existing: Optional[Dict[str, str]] = None,
      import_adds: int = 1,
      verify_status: str = "VERIFIED",
      dismiss_reason: str = "",
      overrides: Optional[Dict[Tuple[str, ...], CmResult]] = None,
  ):
    super().__init__(binary="/fake/bin/cm")
    self._version = "0.11.0"
    self.findings: Dict[str, str] = dict(existing or {})
    self.dismiss_reasons: Dict[str, str] = {}
    self.import_adds = import_adds
    self.verify_status = verify_status
    self.dismiss_reason = dismiss_reason
    self.overrides = overrides or {}
    self.calls: List[Dict[str, object]] = []
    self.imported: List[Tuple[str, bool, str]] = []
    self._next_id = 1

  def run(
      self,
      args: Sequence[str],
      cwd: Optional[str] = None,
      env: Optional[Dict[str, str]] = None,
      timeout_sec: Optional[float] = None,
  ) -> CmResult:
    args = list(args)
    self.calls.append(
        {"args": args, "cwd": cwd, "env": env, "timeout_sec": timeout_sec}
    )
    key = tuple(args[:2])
    if key in self.overrides:
      return self.overrides[key]

    if args == ["report", "--format", "json"]:
      listing = [
          {
              "finding_id": fid,
              "status": status,
              "title": "CWE-94",
              "dismiss_reason": self.dismiss_reasons.get(fid, ""),
          }
          for fid, status in self.findings.items()
      ]
      return _ok(args, json.dumps(listing, indent=2), "[INFO] Session log: x\n")

    if args[:2] == ["report", "import"]:
      path = args[args.index("-f") + 1]
      exists = os.path.isfile(path)
      contents = Path(path).read_text(encoding="utf-8") if exists else ""
      self.imported.append((path, exists, contents))
      for _ in range(self.import_adds):
        # Assign a brand-new ID distinct from the embedded finding_id in SARIF.
        self.findings[f"00000000-0000-0000-0000-{self._next_id:012d}"] = "OPEN"
        self._next_id += 1
      return _ok(args, f"Successfully imported {self.import_adds} findings.\n")

    if args[:1] == ["verify"]:
      finding_id = args[-1]
      if finding_id == _EMBEDDED_SAMPLE_ID:
        raise AssertionError(
            "cm verify was called with the raw embedded finding_id from"
            " cm_finding.json instead of the new ID assigned by 'cm report"
            " import'!"
        )
      self.findings[finding_id] = self.verify_status
      if self.dismiss_reason:
        self.dismiss_reasons[finding_id] = self.dismiss_reason
      Path(cwd, ".cm_project").write_text("{}", encoding="utf-8")
      return _ok(
          args,
          "Verification session finished.\n",
          "sandbox: info\n",
      )

    raise AssertionError(f"Unexpected cm call: {args!r}")

  def call_args(self) -> List[List[str]]:
    return [call["args"] for call in self.calls]


def _git(repo: str, *args: str) -> str:
  return subprocess.run(
      ["git", *args],
      cwd=repo,
      check=True,
      capture_output=True,
      text=True,
      timeout=30,
  ).stdout


class VerifyTestBase(unittest.TestCase):
  """A temporary folder holding a committed Git repository and sample finding."""

  def setUp(self):
    super().setUp()
    env_patcher = mock.patch.dict(
        os.environ,
        {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    env_patcher.start()
    self.addCleanup(env_patcher.stop)
    self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cm_runner_verify_"))
    self.addCleanup(shutil.rmtree, self.tmp, True)
    self.repo = os.path.join(self.tmp, "repo")
    os.makedirs(self.repo)
    _git(self.repo, "init", "-q")
    _git(self.repo, "config", "user.name", "Test User")
    _git(self.repo, "config", "user.email", "test@example.com")
    Path(self.repo, "app.py").write_text(_APP_PY, encoding="utf-8")
    _git(self.repo, "add", "app.py")
    _git(self.repo, "commit", "-q", "-m", "init")

    self.finding = os.path.join(self.tmp, "cm_finding.json")
    shutil.copy(_SAMPLE_FINDING_PATH, self.finding)

  def cfg(self, **overrides) -> verify.VerifyConfig:
    values = {
        "finding": Path(self.finding),
        "repo": Path(self.repo),
        "out": None,
    }
    values.update(overrides)
    return verify.VerifyConfig(**values)

  def execute(
      self, cfg: verify.VerifyConfig, adapter: CmAdapter, stdin: str = ""
  ) -> Tuple[int, str, str]:
    """Runs `verify.run` with the stream setup `cli/__main__.py` uses."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(
        stderr
    ), mock.patch.object(sys, "stdin", io.StringIO(stdin)):
      cli_main.configure_logging("debug")
      rc = verify.run(cfg, adapter, EventEmitter(stream=stdout))
    cli_main.configure_logging("info")
    return rc, stdout.getvalue(), stderr.getvalue()


class TestConfigFromArgs(VerifyTestBase):
  """REQ-0001: flags and path normalisation."""

  def test_defaults_repo_to_cwd_and_out_to_none(self):
    cfg = verify.config_from_args(
        argparse.Namespace(finding="cm_finding.json", repo=".", out=None)
    )
    self.assertEqual(cfg.repo, Path.cwd().resolve())
    self.assertEqual(cfg.finding, (Path.cwd() / "cm_finding.json").resolve())
    self.assertIsNone(cfg.out)
    self.assertEqual(cfg.sarif_file_name, "cm_finding.sarif")

  def test_dash_means_stdin(self):
    cfg = verify.config_from_args(
        argparse.Namespace(finding="-", repo=".", out=None)
    )
    self.assertIsNone(cfg.finding)
    self.assertEqual(cfg.sarif_file_name, "finding.sarif")

  def test_expands_home_and_removes_dot_dot(self):
    with mock.patch.dict(os.environ, {"HOME": self.tmp}):
      cfg = verify.config_from_args(
          argparse.Namespace(
              finding="~/cm_finding.json", repo="~/repo/../repo", out="~/out"
          )
      )
    self.assertEqual(cfg.finding, Path(self.finding))
    self.assertEqual(cfg.repo, Path(self.repo))
    self.assertEqual(cfg.out, Path(self.tmp, "out"))
    self.assertEqual(cfg.sarif_file_name, "cm_finding.sarif")

  def test_parser_registers_exactly_three_command_flags(self):
    args = cli_main.build_parser().parse_args([
        "verify",
        "--repo",
        "r",
        "--finding",
        "f.sarif",
        "--out",
        "o",
    ])
    self.assertEqual(
        (args.command, args.finding, args.repo, args.out),
        ("verify", "f.sarif", "r", "o"),
    )
    for flag in ("--model", "--context", "--retries"):
      with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
        with self.assertRaises(SystemExit):
          cli_main.build_parser().parse_args(
              ["verify", "--finding", "f.sarif", flag, "x"]
          )


class TestInputValidation(VerifyTestBase):
  """REQ-0002: exit 2, nothing on stdout, nothing run."""

  def assert_usage_error(self, cfg, stdin="", expect_in_log=""):
    adapter = FakeVerifyCm()
    rc, stdout, stderr = self.execute(cfg, adapter, stdin)
    self.assertEqual(rc, exit_codes.USAGE, stderr)
    self.assertEqual(stdout, "")
    self.assertEqual(adapter.calls, [])
    self.assertIn(expect_in_log, stderr)
    return stderr

  def test_repo_not_a_directory(self):
    self.assert_usage_error(
        self.cfg(repo=Path(self.tmp, "missing")), expect_in_log="--repo"
    )

  def test_finding_not_a_file(self):
    self.assert_usage_error(
        self.cfg(finding=Path(self.tmp, "missing.sarif")),
        expect_in_log="--finding",
    )

  def test_out_is_an_existing_file(self):
    out = Path(self.tmp, "out_file")
    out.write_text("x", encoding="utf-8")
    self.assert_usage_error(self.cfg(out=out), expect_in_log="--out")

  def test_not_valid_json(self):
    Path(self.finding).write_text("not json", encoding="utf-8")
    self.assert_usage_error(self.cfg(), expect_in_log="not valid JSON")

  def test_without_runs_list(self):
    Path(self.finding).write_text('{"findings": []}', encoding="utf-8")
    self.assert_usage_error(self.cfg(), expect_in_log="no 'runs' list")

  def test_two_results_rejected(self):
    Path(self.finding).write_text(_sarif(2), encoding="utf-8")
    self.assert_usage_error(
        self.cfg(), expect_in_log="verify takes exactly one"
    )

  def test_zero_results_rejected(self):
    Path(self.finding).write_text(_sarif(0), encoding="utf-8")
    self.assert_usage_error(
        self.cfg(), expect_in_log="verify takes exactly one"
    )

  def test_empty_stdin(self):
    self.assert_usage_error(
        self.cfg(finding=None), stdin="", expect_in_log="stdin"
    )


class TestPreflight(VerifyTestBase):
  """REQ-0003: repository pre-flight checks reused from `fix.py`."""

  def test_not_a_git_repository(self):
    plain = Path(self.tmp, "plain")
    plain.mkdir()
    adapter = FakeVerifyCm()
    rc, stdout, stderr = self.execute(self.cfg(repo=plain), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertEqual(adapter.calls, [])
    self.assertIn("not inside a Git working tree", stderr)

  def test_refuses_uncommitted_work(self):
    Path(self.repo, "app.py").write_text(_APP_PY + "# dirty\n", encoding="utf-8")
    adapter = FakeVerifyCm()
    rc, stdout, stderr = self.execute(self.cfg(), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertEqual(adapter.calls, [])
    self.assertIn("app.py", stderr)
    self.assertIn("'cm verify' would discard it", stderr)

  def test_cm_own_files_do_not_block(self):
    Path(self.repo, ".cm_project").write_text("{}", encoding="utf-8")
    Path(self.repo, ".exploit").mkdir()
    Path(self.repo, ".exploit", "poc.sh").write_text("#!/bin/sh\n", "utf-8")
    rc, stdout, stderr = self.execute(self.cfg(), FakeVerifyCm())
    self.assertEqual(rc, exit_codes.OK, stderr)
    doc = json.loads(stdout)
    self.assertEqual(
        doc["runs"][0]["results"][0]["properties"]["status"], "VERIFIED"
    )


class TestVerifyWorkflow(VerifyTestBase):
  """REQ-0004 to REQ-0006 with `testdata/cm_finding.json`."""

  def test_imports_sample_finding_and_uses_new_id_not_embedded_id(self):
    adapter = FakeVerifyCm(
        existing={"preexisting-id": "OPEN"}, verify_status="VERIFIED"
    )
    out_dir = Path(self.tmp, "verified_out")

    rc, stdout, stderr = self.execute(self.cfg(out=out_dir), adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    assigned_id = "00000000-0000-0000-0000-000000000001"
    self.assertNotEqual(assigned_id, _EMBEDDED_SAMPLE_ID)

    self.assertEqual(
        adapter.call_args(),
        [
            ["report", "--format", "json"],
            ["report", "import", "-f", self.finding, "-p", self.repo],
            ["report", "--format", "json"],
            ["verify", "-y", "--bypass-warning", assigned_id],
            ["report", "--format", "json"],
        ],
    )
    for call in adapter.calls:
      self.assertIsNone(call["env"])
    self.assertEqual(adapter.calls[3]["cwd"], self.repo)
    self.assertEqual(adapter.calls[3]["timeout_sec"], 3000.0)
    self.assertEqual(adapter.calls[0]["timeout_sec"], 60.0)

    # Output on stdout is a single-line compact SARIF JSON with status VERIFIED.
    lines = stdout.splitlines()
    self.assertEqual(len(lines), 1)
    out_doc = json.loads(lines[0])
    props = out_doc["runs"][0]["results"][0]["properties"]
    self.assertEqual(props["status"], "VERIFIED")
    self.assertTrue(bool(props.get("updated_at")))
    self.assertNotIn("dismiss_reason", props)
    self.assertNotIn("suppressions", out_doc["runs"][0]["results"][0])
    self.assertEqual(props["finding_id"], _EMBEDDED_SAMPLE_ID)

    # New SARIF file is generated in --out, and original finding file is untouched.
    new_sarif = out_dir / "cm_finding.sarif"
    self.assertTrue(new_sarif.is_file())
    self.assertEqual(json.loads(new_sarif.read_text(encoding="utf-8")), out_doc)

    original_doc = json.loads(Path(self.finding).read_text(encoding="utf-8"))
    self.assertEqual(
        original_doc["runs"][0]["results"][0]["properties"]["status"], "OPEN"
    )

  def test_dismissed_finding_generates_new_sarif_with_status_and_reason_without_overwriting_input(self):
    adapter = FakeVerifyCm(
        verify_status="DISMISSED",
        dismiss_reason="Safe eval sandbox cannot be escaped in this config",
    )
    out_dir = Path(self.tmp, "artifacts")
    original_bytes = Path(self.finding).read_bytes()

    rc, stdout, stderr = self.execute(self.cfg(out=out_dir), adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    # 1. Check stdout is compact 1-line SARIF JSON with status DISMISSED and dismiss_reason.
    lines = stdout.splitlines()
    self.assertEqual(len(lines), 1)
    stdout_doc = json.loads(lines[0])
    props = stdout_doc["runs"][0]["results"][0]["properties"]
    self.assertEqual(props["status"], "DISMISSED")
    self.assertTrue(bool(props.get("updated_at")))
    self.assertEqual(
        props["dismiss_reason"],
        "Safe eval sandbox cannot be escaped in this config",
    )
    self.assertEqual(
        stdout_doc["runs"][0]["results"][0].get("suppressions"),
        [
            {
                "kind": "external",
                "status": "accepted",
                "justification": "Safe eval sandbox cannot be escaped in this config",
            }
        ],
    )

    # 2. Check new SARIF file was generated in --out.
    out_file = out_dir / "cm_finding.sarif"
    self.assertTrue(out_file.is_file())
    self.assertEqual(
        json.loads(out_file.read_text(encoding="utf-8")), stdout_doc
    )

    # 3. Check original input finding file was NOT overwritten.
    self.assertEqual(Path(self.finding).read_bytes(), original_bytes)

  def test_dismissed_without_cm_reason_uses_default_dismiss_reason(self):
    adapter = FakeVerifyCm(verify_status="DISMISSED", dismiss_reason="")

    rc, stdout, stderr = self.execute(self.cfg(), adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    doc = json.loads(stdout)
    props = doc["runs"][0]["results"][0]["properties"]
    self.assertEqual(props["status"], "DISMISSED")
    self.assertTrue(bool(props.get("dismiss_reason")))
    self.assertTrue(bool(props.get("updated_at")))
    suppressions = doc["runs"][0]["results"][0].get("suppressions")
    self.assertEqual(len(suppressions), 1)
    self.assertEqual(suppressions[0]["status"], "accepted")
    self.assertEqual(suppressions[0]["justification"], props["dismiss_reason"])

  def test_inconclusive_open_status_preserved_as_open(self):
    adapter = FakeVerifyCm(verify_status="OPEN")

    rc, stdout, stderr = self.execute(self.cfg(), adapter)

    self.assertEqual(rc, exit_codes.OK, stderr)
    doc = json.loads(stdout)
    props = doc["runs"][0]["results"][0]["properties"]
    self.assertEqual(props["status"], "OPEN")
    self.assertTrue(bool(props.get("updated_at")))
    self.assertNotIn("dismiss_reason", props)
    self.assertNotIn("suppressions", doc["runs"][0]["results"][0])

  def test_verify_resets_working_tree_and_preserves_cm_paths(self):
    class ModifyingVerifyCm(FakeVerifyCm):

      def run(self, args, cwd=None, env=None, timeout_sec=None):
        res = super().run(args, cwd=cwd, env=env, timeout_sec=timeout_sec)
        if args[:1] == ["verify"]:
          Path(cwd, "app.py").write_text(
              _APP_PY + "# modified by verify\n", encoding="utf-8"
          )
          Path(cwd, "repro.py").write_text("# untracked repro\n", encoding="utf-8")
          Path(cwd, ".cm_project").write_text("{\"project\": true}", encoding="utf-8")
          os.makedirs(Path(cwd, ".exploit"), exist_ok=True)
          Path(cwd, ".exploit", "payload.bin").write_text(
              "evil", encoding="utf-8"
          )
        return res

    adapter = ModifyingVerifyCm(verify_status="VERIFIED")
    rc, stdout, stderr = self.execute(self.cfg(), adapter)
    self.assertEqual(rc, exit_codes.OK, stderr)
    self.assertEqual(
        Path(self.repo, "app.py").read_text(encoding="utf-8"), _APP_PY
    )
    self.assertFalse(Path(self.repo, "repro.py").exists())
    self.assertTrue(Path(self.repo, ".cm_project").exists())
    self.assertTrue(Path(self.repo, ".exploit", "payload.bin").exists())

  def test_verify_failure_resets_working_tree(self):
    class FailingModifyingVerifyCm(FakeVerifyCm):

      def run(self, args, cwd=None, env=None, timeout_sec=None):
        if args[:1] == ["verify"]:
          self.calls.append({
              "args": list(args),
              "cwd": cwd,
              "env": env,
              "timeout_sec": timeout_sec,
          })
          Path(cwd, "app.py").write_text(
              _APP_PY + "# modified by verify\n", encoding="utf-8"
          )
          Path(cwd, "artifact.tmp").write_text("temp\n", encoding="utf-8")
          return _failed(["verify"], "verify crashed\n")
        return super().run(args, cwd=cwd, env=env, timeout_sec=timeout_sec)

    adapter = FailingModifyingVerifyCm()
    rc, stdout, stderr = self.execute(self.cfg(), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(
        Path(self.repo, "app.py").read_text(encoding="utf-8"), _APP_PY
    )
    self.assertFalse(Path(self.repo, "artifact.tmp").exists())

  def test_stdin_finding_writes_temp_file_outside_repo_and_generates_out_sarif(self):
    adapter = FakeVerifyCm(
        verify_status="DISMISSED", dismiss_reason="Not reachable"
    )
    out_dir = Path(self.tmp, "out")

    rc, stdout, stderr = self.execute(
        self.cfg(finding=None, out=out_dir), adapter, stdin=_sarif()
    )

    self.assertEqual(rc, exit_codes.OK, stderr)
    [(path, existed, contents)] = adapter.imported
    self.assertTrue(existed)
    self.assertEqual(contents, _sarif())
    self.assertFalse(Path(path).resolve().is_relative_to(Path(self.repo)))
    self.assertFalse(os.path.exists(path))
    self.assertTrue((out_dir / "finding.sarif").is_file())
    doc = json.loads(stdout)
    self.assertEqual(
        doc["runs"][0]["results"][0]["properties"]["status"], "DISMISSED"
    )
    self.assertEqual(
        doc["runs"][0]["results"][0]["properties"]["dismiss_reason"],
        "Not reachable",
    )


class TestFailures(VerifyTestBase):
  """Every execution/infrastructure failure exits 3 with 0 bytes on stdout."""

  def assert_failed(self, adapter, cfg=None, expect_in_log=""):
    rc, stdout, stderr = self.execute(cfg or self.cfg(), adapter)
    self.assertEqual(rc, exit_codes.FAILED, stderr)
    self.assertEqual(stdout, "")
    self.assertIn(expect_in_log, stderr)
    return stderr

  def test_cm_not_initialised(self):
    args = ["report", "--format", "json"]
    adapter = FakeVerifyCm(
        overrides={
            ("report", "--format"): _failed(
                args, "Error: CodeMender has not been initialized.\n"
            )
        }
    )
    self.assert_failed(adapter, expect_in_log="has not been initialized")
    self.assertEqual(adapter.call_args(), [args])

  def test_import_fails(self):
    adapter = FakeVerifyCm(
        overrides={
            ("report", "import"): _failed(
                ["report", "import"], "Error: no valid findings to import\n"
            )
        }
    )
    self.assert_failed(adapter, expect_in_log="no valid findings to import")
    self.assertNotIn("verify", [a[0] for a in adapter.call_args()])

  def test_import_adds_zero_or_two_findings(self):
    for count in (0, 2):
      with self.subTest(count=count):
        adapter = FakeVerifyCm(import_adds=count)
        self.assert_failed(adapter, expect_in_log=f"added {count}")
        self.assertNotIn("verify", [a[0] for a in adapter.call_args()])

  def test_verify_exits_non_zero(self):
    adapter = FakeVerifyCm(
        overrides={("verify", "-y"): _failed(["verify"], "verify boom\n")}
    )
    self.assert_failed(adapter, expect_in_log="verify boom")

  def test_verify_times_out(self):
    timeout = CmResult(
        args=("/fake/bin/cm", "verify"),
        exit_code=None,
        stdout="partial verify\n",
        stderr="",
        tokens=TokenUsage(),
        error="timed out after 3000.0 s",
    )
    adapter = FakeVerifyCm(overrides={("verify", "-y"): timeout})
    self.assert_failed(adapter, expect_in_log="timed out after 3000.0 s")

  def test_out_write_failure_exits_three_with_empty_stdout(self):
    blocker = Path(self.tmp, "blocker")
    blocker.write_text("file not dir", encoding="utf-8")
    self.assert_failed(
        FakeVerifyCm(verify_status="VERIFIED"),
        cfg=self.cfg(out=blocker / "nested"),
        expect_in_log="Could not write",
    )


class TestVerifyThroughTheCli(unittest.TestCase):
  """End-to-end tests invoking `bin/cm-runner verify` against a fake `cm`."""

  _FAKE_CM = r'''
import json, os, sys
state = os.environ["FAKE_CM_STATE"]
target_status = os.environ.get("FAKE_CM_VERIFY_STATUS", "DISMISSED")
dismiss_reason = os.environ.get("FAKE_CM_DISMISS_REASON", "Sanitized input")
embedded_id = "9f7b066a-0d33-5ced-b834-9ad42e83aa40"

def load():
    if not os.path.exists(state):
        return []
    with open(state) as handle:
        return json.load(handle)

def save(findings):
    with open(state, "w") as handle:
        json.dump(findings, handle)

args = sys.argv[1:]
if args == ["--version"]:
    print("cm version 0.11.0")
elif args == ["init"]:
    cfg_dir = os.path.join(os.environ["HOME"], ".codemender")
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, "config.yaml"), "w") as handle:
        handle.write("stock_default: true\n")
elif args == ["init", "--verify"]:
    print("  Results: 4 passed, 4 warnings")
elif args == ["report", "--format", "json"]:
    print("[INFO] Session log: x", file=sys.stderr)
    print(json.dumps(load(), indent=2))
elif args[:2] == ["report", "import"]:
    findings = load()
    findings.append({"finding_id": "imported-id-%d" % len(findings), "status": "OPEN"})
    save(findings)
    print("Successfully imported 1 findings.")
elif args[:1] == ["verify"]:
    finding_id = args[-1]
    if finding_id == embedded_id:
        print("ERROR: used embedded finding_id directly!", file=sys.stderr)
        sys.exit(2)
    print("progress banner that must not reach stdout")
    findings = load()
    for finding in findings:
        if finding["finding_id"] == finding_id:
            finding["status"] = target_status
            if target_status == "DISMISSED":
                finding["dismiss_reason"] = dismiss_reason
    save(findings)
else:
    sys.exit(1)
'''

  def setUp(self):
    super().setUp()
    env_patcher = mock.patch.dict(
        os.environ,
        {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    env_patcher.start()
    self.addCleanup(env_patcher.stop)
    self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cm_runner_verify_cli_"))
    self.addCleanup(shutil.rmtree, self.tmp, True)
    self.home = os.path.join(self.tmp, "home")
    os.makedirs(self.home, exist_ok=True)
    self.cm = os.path.join(self.tmp, "cm")
    with open(self.cm, "w", encoding="utf-8") as handle:
      handle.write(f"#!{sys.executable}\n{self._FAKE_CM}")
    os.chmod(self.cm, 0o755)

    self.repo = os.path.join(self.tmp, "repo")
    os.makedirs(self.repo)
    _git(self.repo, "init", "-q")
    _git(self.repo, "config", "user.name", "Test User")
    _git(self.repo, "config", "user.email", "test@example.com")
    Path(self.repo, "app.py").write_text(_APP_PY, encoding="utf-8")
    _git(self.repo, "add", "app.py")
    _git(self.repo, "commit", "-q", "-m", "init")

    self.finding = os.path.join(self.tmp, "cm_finding.json")
    shutil.copy(_SAMPLE_FINDING_PATH, self.finding)
    self.out_dir = os.path.join(self.tmp, "verified_out")

  def run_verify(self, *args, verify_status: str = "DISMISSED"):
    env = dict(os.environ)
    env["HOME"] = self.home
    env["CM_RUNNER_PYTHON"] = sys.executable
    env["FAKE_CM_STATE"] = os.path.join(self.tmp, "state.json")
    env["FAKE_CM_VERIFY_STATUS"] = verify_status
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "codemender.runner",
            "verify",
            "--cm-binary",
            self.cm,
            *args,
        ],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

  def test_bin_cm_runner_verify_dismissed_generates_new_sarif_without_overwriting_input(self):
    result = self.run_verify(
        "--repo",
        self.repo,
        "--finding",
        self.finding,
        "--out",
        self.out_dir,
        verify_status="DISMISSED",
    )

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    lines = result.stdout.splitlines()
    self.assertEqual(len(lines), 1)
    self.assertNotIn("progress banner", result.stdout)
    self.assertIn("progress banner", result.stderr)

    stdout_doc = json.loads(lines[0])
    props = stdout_doc["runs"][0]["results"][0]["properties"]
    self.assertEqual(props["status"], "DISMISSED")
    self.assertEqual(props["dismiss_reason"], "Sanitized input")
    self.assertTrue(bool(props.get("updated_at")))
    self.assertEqual(
        stdout_doc["runs"][0]["results"][0].get("suppressions"),
        [
            {
                "kind": "external",
                "status": "accepted",
                "justification": "Sanitized input",
            }
        ],
    )

    # New SARIF file written to --out.
    new_sarif = Path(self.out_dir, "cm_finding.sarif")
    self.assertTrue(new_sarif.is_file())
    self.assertEqual(json.loads(new_sarif.read_text(encoding="utf-8")), stdout_doc)

    # Original input file is untouched.
    orig_doc = json.loads(Path(self.finding).read_text(encoding="utf-8"))
    self.assertEqual(
        orig_doc["runs"][0]["results"][0]["properties"]["status"], "OPEN"
    )

  def test_bin_cm_runner_verify_verified_emits_verified_sarif(self):
    result = self.run_verify(
        "--repo",
        self.repo,
        "--finding",
        self.finding,
        "--out",
        self.out_dir,
        verify_status="VERIFIED",
    )

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    lines = result.stdout.splitlines()
    self.assertEqual(len(lines), 1)
    stdout_doc = json.loads(lines[0])
    props = stdout_doc["runs"][0]["results"][0]["properties"]
    self.assertEqual(props["status"], "VERIFIED")
    self.assertTrue(bool(props.get("updated_at")))
    self.assertNotIn("suppressions", stdout_doc["runs"][0]["results"][0])
    new_sarif = Path(self.out_dir, "cm_finding.sarif")
    self.assertTrue(new_sarif.is_file())
    self.assertEqual(json.loads(new_sarif.read_text(encoding="utf-8")), stdout_doc)


if __name__ == "__main__":
  unittest.main()
