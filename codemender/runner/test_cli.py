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

"""Unit tests for the cm-runner command-line interface.

Most of these tests assert the *output contract* rather than any particular
command's behaviour:

  1. stdout carries NDJSON and nothing else.
  2. Everything human-readable goes to stderr.
  3. Exit codes are 0 / 2 / 3.

The contract is the part other workstreams depend on, and it is the part most
easily broken by an innocent-looking change elsewhere in the repo -- see
`test_importing_cli_does_not_import_main` for the specific hazard.

The contract tests run the CLI in a subprocess rather than calling `main()`
in-process. That is deliberate: an in-process test cannot see output written
by a child process or by a C-level write to fd 1, and both of those are
exactly how the contract has been broken before.
"""

import ast
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
import setuptools

# Directory containing the `codemender` package, used as cwd so `python -m codemender.runner` works.
_PKG_DIR = str(Path(__file__).resolve().parents[2])
_REPO_ROOT = Path(__file__).resolve().parents[5]
if _PKG_DIR not in sys.path:
  sys.path.insert(0, _PKG_DIR)

from codemender.runner import exit_codes
from codemender.runner.events import EventEmitter

# A stub cm that only answers `--version`, which is all `main` needs from it.
_WORKING_CM_BODY = '#!/bin/sh\necho "cm version 0.9.0"\n'


def _write_stub_cm(directory, body=_WORKING_CM_BODY):
  """Writes an executable `cm` stub into `directory` and returns its path."""
  path = os.path.join(directory, "cm")
  with open(path, "w", encoding="utf-8") as handle:
    handle.write(body)
  os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)
  return path


def _temp_dir(test):
  """Makes a temporary folder that is removed when `test` finishes."""
  directory = tempfile.mkdtemp(prefix="cm_runner_test_")
  test.addCleanup(shutil.rmtree, directory, True)
  return directory


class CLIContractTestBase(unittest.TestCase):
  """Runs the CLI in a subprocess with a controlled PATH."""

  def setUp(self):
    super().setUp()
    # PATH only ever holds folders made here, so a real `cm` installed on the
    # developer's machine can never leak into a test result. Without this,
    # these tests would pass or fail depending on whose laptop they run on.
    self._empty_dir = tempfile.mkdtemp(prefix="cm_runner_test_")
    self.addCleanup(shutil.rmtree, self._empty_dir, True)
    # Every command needs a `cm` that runs, so by default PATH holds a stub.
    self._stub_dir = tempfile.mkdtemp(prefix="cm_runner_stub_")
    self.addCleanup(shutil.rmtree, self._stub_dir, True)
    _write_stub_cm(self._stub_dir)

  def run_cli(self, *args, path=None):
    """Invokes `python -m codemender.runner` and captures both streams separately.

    Args:
      *args: Arguments passed after `-m codemender.runner`.
      path: Value for PATH in the child. Defaults to a folder holding only a
        working stub `cm`.

    Returns:
      The completed process, with text-mode stdout and stderr.
    """
    env = dict(os.environ)
    env["PATH"] = self._stub_dir if path is None else path
    # Keep the child from writing .pyc files into the source tree, and stop
    # any inherited PYTHONPATH from changing what `codemender.runner` resolves to.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)

    return subprocess.run(
        [sys.executable, "-m", "codemender.runner", *args],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

  def assert_stdout_is_one_json_object(self, completed):
    """Asserts stdout is exactly one line and that line is a JSON object."""
    lines = completed.stdout.splitlines()
    self.assertEqual(
        len(lines),
        1,
        f"stdout must be exactly one line, got {len(lines)}:\n"
        f"{completed.stdout}",
    )
    payload = json.loads(lines[0])
    self.assertIsInstance(payload, dict)
    return payload


class TestStdoutPurity(CLIContractTestBase):
  """The output contract: stdout is machine-readable and nothing else."""

  def test_version_emits_exactly_one_json_object(self):
    """The happy path writes one NDJSON line and exits 0."""
    result = self.run_cli("version")

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    payload = self.assert_stdout_is_one_json_object(result)
    self.assertEqual(payload["event"], "version")
    self.assertIn("ts", payload)
    self.assertIn("orchestrator", payload)
    self.assertIn("cm", payload)
    self.assertNotIn("contract", payload)

  def test_missing_cm_fails_with_empty_stdout(self):
    """With no cm, main exits 3 before any command runs; stdout stays empty.

    The reason goes to stderr, so a failed run never leaves a line on stdout
    that a caller could mistake for a result.
    """
    commands = (
        ["version"],
        ["init"],
        ["find-diff"],
        ["fix", "--finding", "f.sarif"],
    )
    for command in commands:
      with self.subTest(command=command[0]):
        result = self.run_cli(*command, path=self._empty_dir)

        self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("cm not found", result.stderr)

  def test_usage_error_exits_two_and_leaves_stdout_empty(self):
    """argparse must never write to stdout, on any error path."""
    cases = {
        "no subcommand": [],
        "unknown subcommand": ["nonsuch"],
        "unknown flag": ["version", "--nonsuch"],
        "invalid flag value": ["version", "--log-level", "loud"],
        # Removed: stdout is always JSON.
        "--output flag": ["version", "--output", "text"],
    }

    for label, argv in cases.items():
      with self.subTest(case=label):
        result = self.run_cli(*argv)

        self.assertEqual(result.returncode, exit_codes.USAGE)
        self.assertEqual(
            result.stdout,
            "",
            f"{label}: stdout must stay empty, got: {result.stdout!r}",
        )
        self.assertNotEqual(result.stderr.strip(), "")

  def test_debug_logging_goes_to_stderr_not_stdout(self):
    """Raising log verbosity must not add anything to stdout.

    This is the regression test for the hazard described in
    `cli/__main__.configure_logging`: a stdout log handler installed anywhere
    in the process would surface here.
    """
    result = self.run_cli("--log-level", "debug", "version")

    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    self.assert_stdout_is_one_json_object(result)

  def test_global_flags_accepted_before_and_after_subcommand(self):
    """Both orderings must behave identically.

    argparse silently ignores the pre-subcommand form unless the shared flags
    use SUPPRESS, which is a failure mode that looks like success.
    """
    stub = _write_stub_cm(
        _temp_dir(self), '#!/bin/sh\necho "cm version 7.7.7"\n'
    )

    before = self.run_cli("--cm-binary", stub, "version")
    after = self.run_cli("version", "--cm-binary", stub)

    for result in (before, after):
      self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
      payload = self.assert_stdout_is_one_json_object(result)
      self.assertEqual(payload["cm"]["version"], "7.7.7")

  def test_no_init_sets_auto_init_false_before_and_after_subcommand(self):
    """`--no-init` populates `args.auto_init = False` in both positions; default is True."""
    from codemender.runner import __main__ as cli_main

    parser = cli_main.build_parser()
    default_args = cli_main._apply_defaults(parser.parse_args(["find-diff"]))
    self.assertTrue(default_args.auto_init)

    before_args = cli_main._apply_defaults(
        parser.parse_args(["--no-init", "find-diff"])
    )
    self.assertFalse(before_args.auto_init)

    after_args = cli_main._apply_defaults(
        parser.parse_args(["find-diff", "--no-init"])
    )
    self.assertFalse(after_args.auto_init)


class TestCmDetection(CLIContractTestBase):
  """Locating cm and reading its version."""

  def _write_fake_cm(self, body):
    """Creates an executable stub and returns its path."""
    directory = tempfile.mkdtemp(prefix="cm_runner_fake_")
    self.addCleanup(shutil.rmtree, directory, True)

    path = os.path.join(directory, "cm")
    with open(path, "w", encoding="utf-8") as handle:
      handle.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return path

  def test_reports_version_from_explicit_binary(self):
    """`--cm-binary` is honoured and the bare version is extracted."""
    fake = self._write_fake_cm('#!/bin/bash\necho "cm version 1.2.3"\n')

    result = self.run_cli("version", "--cm-binary", fake)

    payload = self.assert_stdout_is_one_json_object(result)
    self.assertTrue(payload["cm"]["found"])
    self.assertEqual(payload["cm"]["version"], "1.2.3")
    self.assertEqual(payload["cm"]["path"], fake)

  def test_finds_cm_on_path(self):
    """With no explicit path, cm is discovered via PATH."""
    fake = self._write_fake_cm('#!/bin/bash\necho "cm version 4.5.6"\n')

    result = self.run_cli("version", path=os.path.dirname(fake))

    payload = self.assert_stdout_is_one_json_object(result)
    self.assertTrue(payload["cm"]["found"])
    self.assertEqual(payload["cm"]["version"], "4.5.6")

  def test_binary_present_but_version_unreadable_fails(self):
    """A cm that fails `--version` is found but does not run: exit 3.

    Uses an inline stub cm that rejects `--version`. Stdout
    stays empty, and the child's error text does not leak onto it.
    """
    fake = self._write_fake_cm(
        "#!/bin/sh\necho 'unrecognized option' >&2\nexit 1\n"
    )
    result = self.run_cli("version", "--cm-binary", fake)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(result.stdout, "")
    self.assertIn("did not run 'cm --version'", result.stderr)

  def test_cm_binary_that_does_not_exist_fails(self):
    """`locate` accepts any --cm-binary path; running it is what fails."""
    missing = os.path.join(self._empty_dir, "no_such_cm")

    result = self.run_cli("version", "--cm-binary", missing)

    self.assertEqual(result.returncode, exit_codes.FAILED, result.stderr)
    self.assertEqual(result.stdout, "")

  def test_noisy_cm_cannot_pollute_stdout(self):
    """Child process chatter is captured, never forwarded to our stdout.

    This is the failure that `detect_cm` exists to avoid: the first
    implementation reused a helper that streams child output to sys.stdout,
    producing six lines where the contract allows one.
    """
    fake = self._write_fake_cm(
        "#!/bin/bash\n"
        'echo "banner line one"\n'
        'echo "banner line two"\n'
        'echo "cm version 9.9.9"\n'
    )

    result = self.run_cli("version", "--cm-binary", fake)

    payload = self.assert_stdout_is_one_json_object(result)
    self.assertEqual(payload["cm"]["version"], "9.9.9")


class TestImportIsolation(unittest.TestCase):
  """The codemender.runner package must stay independent of the env-var pipeline."""

  def test_importing_cli_does_not_import_main(self):
    """Importing codemender.runner must not pull in main.py."""
    probe = (
        "import sys;"
        "import codemender.runner, codemender.runner.__main__,"
        " codemender.runner.events, codemender.runner.exit_codes,"
        " codemender.runner.commands.version,"
        " codemender.runner.commands.find_diff,"
        " codemender.runner.commands.fix;"
        "print('main' in sys.modules)"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(
        result.stdout.strip(),
        "False",
        "codemender.runner must not import main.py; it configures logging on "
        "stdout at import time.",
    )

  def test_version_command_needs_no_utils_or_third_party_packages(self):
    """`codemender.runner.commands.version` and `__main__` must not load `utils`, `requests`, `yaml`, or `google`."""
    probe = (
        "import sys;"
        "before = set(sys.modules);"
        "import codemender.runner, codemender.runner.__main__,"
        " codemender.runner.events, codemender.runner.exit_codes,"
        " codemender.runner.commands.version;"
        "loaded = set(sys.modules) - before;"
        "print(sorted(m for m in loaded"
        " if m.split('.')[0] in ('utils', 'requests', 'yaml', 'google')))"
    )
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    self.assertEqual(result.returncode, 0, result.stderr)
    self.assertEqual(result.stdout.strip(), "[]")


class TestEventEmitter(unittest.TestCase):
  """The emitter itself, exercised in-process against a StringIO."""

  def test_emit_writes_one_json_line_per_event(self):
    """Each event is a single self-contained line of JSON."""
    stream = StringIO()
    emitter = EventEmitter(stream=stream)

    emitter.emit("first", value=1)
    emitter.emit("second", value=2)

    lines = stream.getvalue().splitlines()
    self.assertEqual(len(lines), 2)
    self.assertEqual(json.loads(lines[0])["event"], "first")
    self.assertEqual(json.loads(lines[1])["value"], 2)

  def test_emit_returns_payload_including_timestamp(self):
    """The returned payload is what was written, so callers can inspect it."""
    emitter = EventEmitter(stream=StringIO())

    payload = emitter.emit("version", orchestrator="0.1.0")

    self.assertEqual(payload["event"], "version")
    self.assertEqual(payload["orchestrator"], "0.1.0")
    self.assertRegex(payload["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestExitCodes(unittest.TestCase):
  """The exit codes are a published contract; pin their values."""

  def test_values_are_stable(self):
    """These may be added to, but never changed: CI configs depend on them."""
    self.assertEqual(exit_codes.OK, 0)
    self.assertEqual(exit_codes.USAGE, 2)
    self.assertEqual(exit_codes.FAILED, 3)


# Governing: docs/adr/ADR-0008-repository-layout-and-package-structure.md#decision-1
class TestLegacyRunnerDirectoryRemoved(unittest.TestCase):
  """Verifies legacy codemender-runner/ directory is removed and module execution works."""

  def test_legacy_runner_directory_does_not_exist(self):
    self.assertFalse(
        (_REPO_ROOT / "codemender-runner").exists(),
        "Legacy codemender-runner/ directory must be removed per ADR-0008",
    )

  def test_module_execution_runs_version(self):
    stub = _write_stub_cm(_temp_dir(self))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "codemender.runner",
            "version",
            "--cm-binary",
            stub,
        ],
        cwd=_PKG_DIR,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, exit_codes.OK, result.stderr)
    payload = json.loads(result.stdout.strip())
    self.assertEqual(payload["event"], "version")

  def test_module_execution_usage_on_missing_command(self):
    result = subprocess.run(
        [sys.executable, "-m", "codemender.runner"],
        cwd=_PKG_DIR,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(result.returncode, exit_codes.USAGE)


class TestCliArchitectureRules(unittest.TestCase):
  """ADR-0008 & ADR-0003 Confirmation: architectural boundary enforcement via AST inspection."""

  # Governing: ADR-0008, SPEC-0003
  def _get_cli_python_files(self):
    runner_dir = os.path.join(_PKG_DIR, "codemender", "runner")
    py_files = []
    for root, _, files in os.walk(runner_dir):
      for f in files:
        if (
            f.endswith(".py")
            and not f.startswith("test_")
            and not f.endswith("_test.py")
        ):
          py_files.append(os.path.join(root, f))
    return py_files

  def _get_codemender_python_files(self):
    codemender_dir = os.path.join(_PKG_DIR, "codemender")
    py_files = []
    for root, _, files in os.walk(codemender_dir):
      for f in files:
        if (
            f.endswith(".py")
            and not f.startswith("test_")
            and not f.endswith("_test.py")
        ):
          py_files.append(os.path.join(root, f))
    return py_files

  def _assert_no_env_scrubbing_in_tree(self, tree, source_label):
    banned_symbols = {"get_scrubbed_env", "SENSITIVE_ENV_VARS"}
    for node in ast.walk(tree):
      if isinstance(node, ast.ImportFrom):
        for alias in node.names:
          self.assertNotIn(
              alias.name,
              banned_symbols,
              f"{source_label}:{node.lineno} imports banned symbol"
              f" '{alias.name}'",
          )
      elif isinstance(node, ast.Attribute):
        self.assertNotIn(
            node.attr,
            banned_symbols,
            f"{source_label}:{node.lineno} accesses banned attribute"
            f" '{node.attr}'",
        )
      elif isinstance(node, ast.Name):
        self.assertNotIn(
            node.id,
            banned_symbols,
            f"{source_label}:{node.lineno} references banned symbol"
            f" '{node.id}'",
        )

  def test_cli_and_codemender_do_not_reference_env_scrubbing(self):
    """ADR-0003 Confirmation: codemender/ must never reference get_scrubbed_env or SENSITIVE_ENV_VARS."""
    target_files = self._get_codemender_python_files()
    self.assertGreater(len(target_files), 0)
    for py_file in target_files:
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        self._assert_no_env_scrubbing_in_tree(tree, py_file)

    synthetic_violations = {
        "import_from": (
            "from config import get_scrubbed_env, SENSITIVE_ENV_VARS\n"
        ),
        "attribute_access": "config.get_scrubbed_env(repo)\n",
        "name_reference": " _ = SENSITIVE_ENV_VARS\n".lstrip(),
    }
    for label, snippet in synthetic_violations.items():
      with self.subTest(synthetic=label):
        with self.assertRaises(AssertionError):
          self._assert_no_env_scrubbing_in_tree(
              ast.parse(snippet, filename="<synthetic>"), "<synthetic>"
          )

  def test_cli_modules_do_not_import_subprocess(self):
    """CLI modules must never import subprocess directly; cm runs through codemender.cm.CmAdapter, git through codemender.vcs.git."""
    for py_file in self._get_cli_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Import):
            for alias in node.names:
              self.assertNotEqual(
                  alias.name,
                  "subprocess",
                  f"{py_file}:{node.lineno} imports banned module 'subprocess'",
              )
          elif isinstance(node, ast.ImportFrom):
            self.assertNotEqual(
                node.module,
                "subprocess",
                f"{py_file}:{node.lineno} imports from banned module 'subprocess'",
            )

  def test_cli_modules_do_not_import_vcs_github(self):
    """ADR-0008 Confirmation: codemender modules must never import launcher, repohost, or vcs.github."""
    banned_roots = {"launcher", "repohost"}
    for py_file in self._get_codemender_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Import):
            for alias in node.names:
              self.assertNotIn(
                  "vcs.github",
                  alias.name,
                  f"{py_file}:{node.lineno} imports banned module 'vcs.github'",
              )
              self.assertNotIn(
                  alias.name.split(".")[0],
                  banned_roots,
                  f"{py_file}:{node.lineno} imports banned package"
                  f" '{alias.name}'",
              )
          elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            self.assertFalse(
                mod == "vcs.github" or mod.startswith("vcs.github"),
                f"{py_file}:{node.lineno} imports from banned module 'vcs.github'",
            )
            self.assertNotIn(
                mod.split(".")[0],
                banned_roots,
                f"{py_file}:{node.lineno} imports from banned package '{mod}'",
            )
            if mod in ("vcs", "codemender.vcs"):
              for alias in node.names:
                self.assertNotEqual(
                    alias.name,
                    "github",
                    f"{py_file}:{node.lineno} imports 'github' from '{mod}'",
                )

  def test_cli_modules_do_not_call_banned_functions_directly(self):
    """CLI modules must not directly call run_command, build_cm_command, or push_branch_to_remote."""
    banned_calls = {"run_command", "build_cm_command", "push_branch_to_remote"}
    for py_file in self._get_cli_python_files():
      with self.subTest(file=os.path.relpath(py_file, _PKG_DIR)):
        with open(py_file, "r", encoding="utf-8") as handle:
          tree = ast.parse(handle.read(), filename=py_file)
        for node in ast.walk(tree):
          if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
              func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
              func_name = node.func.attr
            self.assertNotIn(
                func_name,
                banned_calls,
                f"{py_file}:{node.lineno} directly calls banned function '{func_name}'",
            )


class TestStdoutRedirectDuringCommand(unittest.TestCase):
  """ADR-0008 Confirmation: while a command runs, stray stdout writes land on stderr."""

  def test_git_helper_inside_command_leaves_stdout_clean(self):
    """A bare print() inside a command reaches stderr only.

    The probe goes through the real `codemender.runner.__main__.main`, with the
    `version` command's `detect_cm` swapped for a helper that prints to
    `sys.stdout`. This fails if `main` ever stops sending stray stdout writes to
    stderr, or leaves them redirected after it returns.
    """
    temp_dir = tempfile.mkdtemp(prefix="fake_cm_")
    self.addCleanup(shutil.rmtree, temp_dir, True)
    _write_stub_cm(temp_dir)

    probe = (
        "import sys\n"
        "import codemender.runner.commands.version as version_cmd\n"
        "from codemender.runner.__main__ import main\n"
        "def noisy_detect_cm(adapter):\n"
        "  print('stray print from a helper')\n"
        "  return {'found': True, 'version': '0.9.0', 'path': adapter.binary}\n"
        "version_cmd.detect_cm = noisy_detect_cm\n"
        "rc = main(['version'])\n"
        "sys.stderr.write(f'restored={sys.stdout is sys.__stdout__}\\n')\n"
        "sys.exit(rc)\n"
    )

    env = dict(os.environ)
    env["PATH"] = temp_dir
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)

    res = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=_PKG_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    self.assertEqual(res.returncode, exit_codes.OK, res.stderr)
    lines = res.stdout.splitlines()
    self.assertEqual(
        len(lines), 1, f"stdout must hold only the version event, got:\n{res.stdout}"
    )
    self.assertEqual(json.loads(lines[0])["event"], "version")
    self.assertIn("stray print from a helper", res.stderr)
    self.assertIn("restored=True", res.stderr)


# Governing: ADR-0008, SPEC-0003
@unittest.skipUnless(
    (_REPO_ROOT / "packages" / "codemender" / "pyproject.toml").is_file(),
    "Only applies in codemender-runner-mcp repository layout",
)
class TestPackagingAndDockerContract(unittest.TestCase):
  """ADR-0008 & SPEC-0003 packaging, .dockerignore, and runner.Dockerfile contracts."""

  def test_pyproject_toml_package_exclusions_and_entrypoint(self):
    """packages/codemender/pyproject.toml defines cm-runner script and excludes tests/testdata."""
    pyproject_path = _REPO_ROOT / "packages" / "codemender" / "pyproject.toml"
    self.assertTrue(pyproject_path.is_file(), f"Missing {pyproject_path}")
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    self.assertEqual(
        data["project"]["scripts"].get("cm-runner"),
        "codemender.runner.__main__:main",
    )
    find_cfg = data["tool"]["setuptools"]["packages"]["find"]
    self.assertEqual(find_cfg.get("where"), ["src"])
    self.assertEqual(find_cfg.get("include"), ["codemender*"])
    for pattern in ("test_*", "*_test", "testdata*"):
      self.assertIn(pattern, find_cfg.get("exclude", []))

    exclude_pkg_data = data["tool"]["setuptools"]["exclude-package-data"].get(
        "*", []
    )
    for pattern in ("**/test_*.py", "**/*_test.py", "**/testdata/**"):
      self.assertIn(pattern, exclude_pkg_data)

  def test_setuptools_package_finder_discovers_only_codemender_subpackages(self):
    """setuptools.PackageFinder.find discovers only the 5 expected codemender packages."""
    discovered = setuptools.PackageFinder.find(
        where=_PKG_DIR,
        include=["codemender*"],
        exclude=["test_*", "*_test", "testdata*"],
    )
    self.assertEqual(
        set(discovered),
        {
            "codemender",
            "codemender.runner",
            "codemender.runner.commands",
            "codemender.sarif",
            "codemender.vcs",
        },
    )

  def test_root_dockerignore_excludes_non_runner_dirs_and_tests(self):
    """Root .dockerignore excludes non-package directories, caches, tests, and testdata."""
    dockerignore_path = _REPO_ROOT / ".dockerignore"
    self.assertTrue(dockerignore_path.is_file(), f"Missing {dockerignore_path}")
    entries = {
        line.strip()
        for line in dockerignore_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    expected_entries = {
        ".git/",
        "docs/",
        "cloud-run-jobs/",
        "!cloud-run-jobs/entrypoint.py",
        "scripts/",
        "dist/",
        ".venv/",
        "**/__pycache__/",
        "**/*.pyc",
        "**/test_*.py",
        "**/testdata/",
    }
    for entry in expected_entries:
      self.assertIn(entry, entries, f"Missing {entry!r} in root .dockerignore")
    self.assertNotIn("codemender-runner/", entries)
    self.assertNotIn("github-actions/", entries)
    self.assertFalse(
        (_REPO_ROOT / "codemender-runner").exists(),
        "Legacy codemender-runner/ directory must not exist",
    )

  def test_runner_dockerfile_contract(self):
    """docker/runner.Dockerfile installs packages/codemender into /opt/codemender/venv after cm binary."""
    dockerfile_path = _REPO_ROOT / "docker" / "runner.Dockerfile"
    self.assertTrue(dockerfile_path.is_file(), f"Missing {dockerfile_path}")
    content = dockerfile_path.read_text(encoding="utf-8")

    self.assertIn("VIRTUAL_ENV=/opt/codemender/venv", content)
    self.assertIn("/opt/codemender/venv/bin", content)
    self.assertIn("ARG CM_VERSION", content)
    self.assertIn(
        "/opt/codemender/venv/bin/pip install --no-cache-dir ./packages/codemender",
        content,
    )
    self.assertIn('ENTRYPOINT ["cm-runner"]', content)
    self.assertIn('CMD ["version"]', content)

    cm_install_idx = content.index("/usr/local/bin/cm")
    copy_pkg_idx = content.index("COPY packages/codemender")
    self.assertLess(
        cm_install_idx,
        copy_pkg_idx,
        "cm binary installation must precede COPY packages/codemender to preserve layer caching",
    )

  def test_cloudbuild_yaml_and_makefile_targets(self):
    """Root cloudbuild.yaml and Makefile define two-stage Cloud Build and deploy-cloudrun/build-cloudrun targets."""
    cloudbuild_path = _REPO_ROOT / "cloudbuild.yaml"
    self.assertTrue(cloudbuild_path.is_file(), f"Missing {cloudbuild_path}")
    cb_content = cloudbuild_path.read_text(encoding="utf-8")
    self.assertIn("docker/runner.Dockerfile", cb_content)
    self.assertIn("docker/cloudrun.Dockerfile", cb_content)
    self.assertIn("BASE_IMAGE=codemender-runner:base", cb_content)
    self.assertIn("--all-tags", cb_content)
    self.assertIn("logging: CLOUD_LOGGING_ONLY", cb_content)
    self.assertNotIn("substitutions:", cb_content)
    self.assertIn(
        "${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPO_NAME}/codemender-runner:${_IMAGE_TAG}",
        cb_content,
    )
    self.assertIn(
        "${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPO_NAME}/codemender-runner:latest",
        cb_content,
    )

    makefile_path = _REPO_ROOT / "Makefile"
    self.assertTrue(makefile_path.is_file(), f"Missing {makefile_path}")

    clean_env = os.environ.copy()
    for var in (
        "GCP_PROJECT_ID",
        "GCP_REGION",
        "RESOURCE_PREFIX",
        "CLOUDRUN_JOB",
        "IMAGE_TAG",
        "RUNNER_IMAGE",
        "CLOUDRUN_IMAGE",
        "GITLAB_IMAGE",
        "TFVARS_FILE",
    ):
      clean_env.pop(var, None)

    static_files = [
        "docker/runner.Dockerfile",
        "docker/cloudrun.Dockerfile",
        "cloud-run-jobs/entrypoint.py",
        "cloudbuild.yaml",
    ]
    pkg_dir = _REPO_ROOT / "packages" / "codemender"
    codemender_files = sorted(
        rel
        for p in pkg_dir.rglob("*")
        if p.is_file()
        for rel in [p.relative_to(pkg_dir).as_posix()]
        if "__pycache__/" not in rel
        and ".egg-info/" not in rel
        and not rel.startswith("build/")
        and "/testdata/" not in rel
        and not p.name.endswith(".pyc")
        and not p.name.startswith("test_")
        and not p.name.endswith("_test.py")
    )
    sha256_file = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    expected_hash = hashlib.sha256(
        "".join([
            *(sha256_file(_REPO_ROOT / f) for f in static_files),
            *(f"{f}:{sha256_file(pkg_dir / f)}" for f in codemender_files),
        ]).encode("utf-8")
    ).hexdigest()[:12]

    with tempfile.TemporaryDirectory() as tmp:
      tfvars = Path(tmp) / "terraform.tfvars"
      tfvars.write_text(
          '# comment\ngcp_project_id = "my-gcp-proj" # inline\n'
          'gcp_region = "us-west1"\n'
          '# resource_prefix = "ignored"\n'
          'resource_prefix = "custom-prefix"\n',
          encoding="utf-8",
      )
      res_deploy = subprocess.run(
          ["make", "-n", "deploy-cloudrun", f"TFVARS_FILE={tfvars}"],
          cwd=str(_REPO_ROOT),
          env=clean_env,
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(res_deploy.returncode, 0, msg=res_deploy.stderr)
      self.assertIn(
          f"gcloud builds submit --config=cloudbuild.yaml --project=my-gcp-proj --substitutions=_REGION=us-west1,_REPO_NAME=custom-prefix-runner,_IMAGE_TAG={expected_hash} .",
          res_deploy.stdout,
      )
      self.assertIn(
          f"gcloud run jobs update custom-prefix-runner --image us-west1-docker.pkg.dev/my-gcp-proj/custom-prefix-runner/codemender-runner:{expected_hash}",
          res_deploy.stdout,
      )
      self.assertNotIn("custom-prefix-worker", res_deploy.stdout)

      tfvars_missing_region = Path(tmp) / "missing_region.tfvars"
      tfvars_missing_region.write_text(
          'gcp_project_id = "my-gcp-proj"\n',
          encoding="utf-8",
      )
      res_missing_region = subprocess.run(
          [
              "make",
              "check-gcp-project",
              f"TFVARS_FILE={tfvars_missing_region}",
          ],
          cwd=str(_REPO_ROOT),
          env=clean_env,
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertNotEqual(res_missing_region.returncode, 0)
      self.assertIn("Error: GCP_REGION is not set", res_missing_region.stderr)

      res_build = subprocess.run(
          ["make", "-n", "build-cloudrun"],
          cwd=str(_REPO_ROOT),
          env=clean_env,
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(res_build.returncode, 0, msg=res_build.stderr)
      self.assertIn(
          "docker build -f docker/runner.Dockerfile -t codemender-runner:local .",
          res_build.stdout,
      )
      self.assertIn(
          "docker build -f docker/cloudrun.Dockerfile --build-arg BASE_IMAGE=codemender-runner:local -t codemender-cloudrun:local .",
          res_build.stdout,
      )

      res_gitlab = subprocess.run(
          ["make", "-n", "build-gitlab"],
          cwd=str(_REPO_ROOT),
          env=clean_env,
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(res_gitlab.returncode, 0, msg=res_gitlab.stderr)
      self.assertIn(
          "docker build -f docker/gitlab.Dockerfile -t codemender-gitlab:local .",
          res_gitlab.stdout,
      )


if __name__ == "__main__":
  unittest.main()
