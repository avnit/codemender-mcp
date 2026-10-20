"""End-to-end and unit tests for sandbox/runner/runner.py.

Run from sandbox/:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

No network, no pip, no pytest needed. Fixture PoC/unit commands use
`python3 -m unittest` through the POC_CMD / UNIT_TEST_CMD overrides.
"""

import difflib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.dirname(HERE)
RUNNER_PATH = os.path.join(SANDBOX_DIR, "runner", "runner.py")

_spec = importlib.util.spec_from_file_location("sandbox_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

# Field list copied from NAMING.md (Sandbox results).
NAMING_FIELDS = [
    "severity", "message", "event_type", "run_id", "execution_name", "repository",
    "commit_sha", "patch_ref", "issue_id", "poc_test", "started_at", "finished_at",
    "poc_before", "poc_after", "patch_applied", "unit_tests_passed", "tests_total",
    "tests_failed", "verdict", "log_excerpt", "logging.googleapis.com/labels",
]

COMMIT = "0123456789abcdef0123456789abcdef01234567"

VULNERABLE = '''"""Filename validation."""


def is_safe_filename(name):
    # VULNERABLE: accepts any name, including ../ traversal
    return True
'''

FIXED = '''"""Filename validation."""


def is_safe_filename(name):
    if name.startswith("/") or ".." in name.split("/"):
        return False
    return True
'''

COMMENT_ONLY = VULNERABLE.replace("# VULNERABLE: accepts any name", "# TODO: validate")

BREAKS_UNIT_TESTS = '''"""Filename validation."""


def is_safe_filename(name):
    # Rejects everything: blocks the PoC but breaks normal use
    return False
'''

POC_TEST = '''import unittest

from app.validators import is_safe_filename


class PocTraversal(unittest.TestCase):
    def test_traversal_accepted(self):
        # Passes (exit 0) while the code is vulnerable.
        self.assertTrue(is_safe_filename("../../etc/passwd"))
'''

UNIT_TEST = '''import unittest

from app.validators import is_safe_filename


class UnitValidators(unittest.TestCase):
    def test_plain_name(self):
        self.assertTrue(is_safe_filename("receipt.txt"))

    def test_nested_name(self):
        self.assertTrue(is_safe_filename("2026/receipt.txt"))
'''

POC_CMD = "python3 -m unittest discover -s {poc_test} -t ."
UNIT_CMD = "python3 -m unittest discover -s tests/unit -t ."


def make_patch(old, new, path="app/validators.py"):
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


class Fixture:
    """Builds a fake repo tarball + patch in a temp dir."""

    def __init__(self, tmp):
        self.tmp = tmp

    def repo_tarball(self, validators=VULNERABLE, prefix="", name="source.tar.gz"):
        repo = os.path.join(self.tmp, "repo-" + name)
        files = {
            "app/__init__.py": "",
            "app/validators.py": validators,
            "tests/__init__.py": "",
            "tests/poc/__init__.py": "",
            "tests/poc/test_poc_traversal.py": POC_TEST,
            "tests/unit/__init__.py": "",
            "tests/unit/test_validators.py": UNIT_TEST,
        }
        for rel, content in files.items():
            full = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write(content)
        tar_path = os.path.join(self.tmp, name)
        with tarfile.open(tar_path, "w:gz") as tar:
            for rel in sorted(files):
                tar.add(os.path.join(repo, rel), arcname=prefix + rel)
        return tar_path

    def write(self, name, content):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            fh.write(content)
        return path


def base_env(source, patch, **extra):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TMPDIR": os.environ.get("TMPDIR", tempfile.gettempdir()),
        "RUN_ID": "run-test-0001",
        "REPOSITORY": "example-org/sample-app",
        "COMMIT_SHA": COMMIT,
        "SOURCE_URI": "file://" + source if source.startswith("/") else source,
        "PATCH_URI": ("file://" + patch) if patch and patch.startswith("/") else (patch or "none"),
        "ISSUE_ID": "CM-0001",
        "POC_TEST": "tests/poc",
        "POC_CMD": POC_CMD,
        "UNIT_TEST_CMD": UNIT_CMD,
        "TIMEOUT_SECONDS": "120",
        "CLOUD_RUN_EXECUTION": "codemender-sandbox-abc12",
    }
    env.update(extra)
    return env


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-test-", ignore_cleanup_errors=True)
        self.tmp = self._tmp.name
        self.fx = Fixture(self.tmp)
        quiet = mock.patch.object(runner, "log_progress")  # keep test output readable
        quiet.start()
        self.addCleanup(quiet.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def run_inprocess(self, env):
        return runner.run(env)

    def run_subprocess(self, env):
        proc = subprocess.run(
            [sys.executable, RUNNER_PATH],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        lines = proc.stdout.splitlines()
        self.assertEqual(len(lines), 1, f"stdout must be one line, got: {proc.stdout!r}\nstderr: {proc.stderr}")
        return proc.returncode, json.loads(lines[0])


class TestVerdicts(RunnerTestCase):
    def test_patch_verified_end_to_end(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("fix.patch", make_patch(VULNERABLE, FIXED))
        code, result = self.run_subprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "PATCH_VERIFIED", result["log_excerpt"])
        self.assertEqual(code, 0)
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["poc_before"], "EXPLOITABLE")
        self.assertEqual(result["poc_after"], "NOT_EXPLOITABLE")
        self.assertTrue(result["patch_applied"])
        self.assertTrue(result["unit_tests_passed"])
        self.assertEqual(result["tests_total"], 2)
        self.assertEqual(result["tests_failed"], 0)
        self.assertEqual(result["execution_name"], "codemender-sandbox-abc12")
        self.assertEqual(result["patch_ref"], "file://" + patch)

    def test_patch_verified_with_patch_fallback(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("fix.patch", make_patch(VULNERABLE, FIXED))
        real_which = runner.shutil.which

        def no_git(cmd, *a, **kw):
            return None if cmd == "git" else real_which(cmd, *a, **kw)

        if not real_which("patch"):
            self.skipTest("patch not installed")
        with mock.patch.object(runner.shutil, "which", side_effect=no_git):
            code, result = self.run_inprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "PATCH_VERIFIED", result["log_excerpt"])
        self.assertIn("patch -p1", result["log_excerpt"])
        self.assertEqual(code, 0)

    def test_patch_failed_when_patch_does_not_fix(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("noop.patch", make_patch(VULNERABLE, COMMENT_ONLY))
        code, result = self.run_inprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "PATCH_FAILED", result["log_excerpt"])
        self.assertEqual(code, 0)
        self.assertTrue(result["patch_applied"])
        self.assertEqual(result["poc_before"], "EXPLOITABLE")
        self.assertEqual(result["poc_after"], "EXPLOITABLE")
        self.assertTrue(result["unit_tests_passed"])

    def test_patch_failed_when_unit_tests_break(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("break.patch", make_patch(VULNERABLE, BREAKS_UNIT_TESTS))
        code, result = self.run_inprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "PATCH_FAILED", result["log_excerpt"])
        self.assertEqual(result["poc_after"], "NOT_EXPLOITABLE")
        self.assertFalse(result["unit_tests_passed"])
        self.assertEqual(result["tests_total"], 2)
        self.assertEqual(result["tests_failed"], 2)
        self.assertEqual(code, 0)

    def test_patch_failed_when_patch_does_not_apply(self):
        src = self.fx.repo_tarball()
        other = VULNERABLE.replace("Filename validation.", "Something else entirely.")
        patch = self.fx.write("stale.patch", make_patch(other.replace("return True", "return 1"), FIXED))
        code, result = self.run_inprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "PATCH_FAILED", result["log_excerpt"])
        self.assertFalse(result["patch_applied"])
        self.assertIsNone(result["poc_after"])
        self.assertEqual(code, 0)

    def test_poc_not_reproduced(self):
        src = self.fx.repo_tarball(validators=FIXED)
        patch = self.fx.write("fix.patch", make_patch(FIXED, FIXED.replace("return False", "return False  # ok")))
        code, result = self.run_inprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "POC_NOT_REPRODUCED", result["log_excerpt"])
        self.assertEqual(result["poc_before"], "NOT_EXPLOITABLE")
        self.assertEqual(code, 0)

    def test_reproduce_only_without_patch(self):
        src = self.fx.repo_tarball()
        code, result = self.run_inprocess(base_env(src, None))
        self.assertEqual(result["patch_ref"], "none")
        self.assertEqual(result["poc_before"], "EXPLOITABLE")
        self.assertFalse(result["patch_applied"])
        self.assertEqual(result["verdict"], "PATCH_FAILED")
        self.assertEqual(code, 0)

    def test_single_top_level_directory_tarball(self):
        src = self.fx.repo_tarball(prefix="sample-app-0123456/")
        patch = self.fx.write("fix.patch", make_patch(VULNERABLE, FIXED))
        code, result = self.run_inprocess(base_env(src, patch))
        self.assertEqual(result["verdict"], "PATCH_VERIFIED", result["log_excerpt"])

    def test_plain_local_path_uri(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("fix.patch", make_patch(VULNERABLE, FIXED))
        env = base_env(src, patch, SOURCE_URI=src, PATCH_URI=patch)
        code, result = self.run_inprocess(env)
        self.assertEqual(result["verdict"], "PATCH_VERIFIED", result["log_excerpt"])

    def test_poc_timeout_is_error(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("fix.patch", make_patch(VULNERABLE, FIXED))
        env = base_env(src, patch, POC_CMD="python3 -c 'import time; time.sleep(30)'", TIMEOUT_SECONDS="2")
        code, result = self.run_inprocess(env)
        self.assertEqual(result["poc_before"], "ERROR")
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("timeout", result["log_excerpt"])
        self.assertEqual(code, 1)

    def test_default_pytest_command_missing_is_error(self):
        if importlib.util.find_spec("pytest") is not None:
            self.skipTest("pytest is installed; this test covers the missing-module path")
        src = self.fx.repo_tarball()
        env = base_env(src, None)
        del env["POC_CMD"]
        code, result = self.run_inprocess(env)
        self.assertEqual(result["poc_before"], "ERROR")
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("pytest", result["log_excerpt"])


class TestErrors(RunnerTestCase):
    def assert_error(self, env, fragment=None):
        code, result = self.run_inprocess(env)
        self.assertEqual(result["verdict"], "ERROR", result["log_excerpt"])
        self.assertEqual(result["severity"], "ERROR")
        self.assertEqual(code, 1)
        self.assertIsNone(result["poc_before"])
        if fragment:
            self.assertIn(fragment, result["message"] + result["log_excerpt"])
        return result

    def evil_tar(self, add):
        path = os.path.join(self.tmp, "evil.tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo("app/__init__.py")
            tar.addfile(info, io.BytesIO(b""))
            add(tar)
        return path

    def test_https_uri_rejected(self):
        env = base_env("https://example.com/source.tar.gz", None)
        self.assert_error(env, "gs:// URI")

    def test_http_patch_uri_rejected(self):
        src = self.fx.repo_tarball()
        env = base_env(src, None, PATCH_URI="http://example.com/fix.patch")
        self.assert_error(env, "PATCH_URI")

    def test_invalid_gs_uri_rejected(self):
        env = base_env("gs://Bad_Bucket/sources/x.tar.gz", None)
        self.assert_error(env, "bucket")

    def test_missing_local_source(self):
        env = base_env(os.path.join(self.tmp, "nope.tar.gz"), None)
        self.assert_error(env, "not found")

    def test_tar_path_traversal_rejected(self):
        def add(tar):
            info = tarfile.TarInfo("../escaped.txt")
            data = b"owned"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        src = self.evil_tar(add)
        self.assert_error(base_env(src, None), "'..'")
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), "escaped.txt")))

    def test_tar_absolute_path_rejected(self):
        def add(tar):
            info = tarfile.TarInfo("/tmp/absolute-owned.txt")
            tar.addfile(info, io.BytesIO(b""))

        self.assert_error(base_env(self.evil_tar(add), None), "absolute")

    def test_tar_symlink_escape_rejected(self):
        def add(tar):
            info = tarfile.TarInfo("app/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../etc/passwd"
            tar.addfile(info)

        self.assert_error(base_env(self.evil_tar(add), None), "escapes")

    def test_tar_absolute_symlink_rejected(self):
        def add(tar):
            info = tarfile.TarInfo("app/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)

        self.assert_error(base_env(self.evil_tar(add), None), "absolute")

    def test_not_a_tarball(self):
        src = self.fx.write("junk.tar.gz", "this is not a tarball")
        self.assert_error(base_env(src, None), "tarball")

    def test_patch_with_traversal_rejected(self):
        src = self.fx.repo_tarball()
        patch = self.fx.write("evil.patch", make_patch("x\n", "y\n", path="../outside.py"))
        self.assert_error(base_env(src, patch), "'..'")

    def test_patch_with_absolute_path_rejected(self):
        src = self.fx.repo_tarball()
        text = "--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
        patch = self.fx.write("abs.patch", text)
        self.assert_error(base_env(src, patch), "absolute")

    def test_patch_creating_symlink_rejected(self):
        src = self.fx.repo_tarball()
        text = (
            "diff --git a/link b/link\nnew file mode 120000\nindex 0000000..1111111\n"
            "--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/etc/passwd\n\\ No newline at end of file\n"
        )
        patch = self.fx.write("link.patch", text)
        self.assert_error(base_env(src, patch), "symlink")

    def test_invalid_commit(self):
        src = self.fx.repo_tarball()
        self.assert_error(base_env(src, None, COMMIT_SHA="main; rm -rf /"), "COMMIT_SHA")

    def test_invalid_repository(self):
        src = self.fx.repo_tarball()
        self.assert_error(base_env(src, None, REPOSITORY="../etc"), "REPOSITORY")

    def test_invalid_timeout(self):
        src = self.fx.repo_tarball()
        self.assert_error(base_env(src, None, TIMEOUT_SECONDS="forever"), "TIMEOUT_SECONDS")

    def test_error_exit_code_from_subprocess(self):
        env = base_env("https://example.com/x.tar.gz", None)
        code, result = self.run_subprocess(env)
        self.assertEqual(code, 1)
        self.assertEqual(result["verdict"], "ERROR")


class TestValidation(unittest.TestCase):
    def test_commit_rules(self):
        self.assertEqual(runner.validate_commit("ABCDEF1"), "abcdef1")
        self.assertEqual(runner.validate_commit("a" * 40), "a" * 40)
        for bad in ("", "abc123", "g" * 7, "a" * 41, "abcdef1 ", "--help"):
            with self.assertRaises(runner.InputError, msg=bad):
                runner.validate_commit(bad)

    def test_repository_rules(self):
        self.assertEqual(runner.validate_repository("example-org/sample-app"), "example-org/sample-app")
        self.assertEqual(runner.validate_repository("a/b.c_d"), "a/b.c_d")
        for bad in ("", "noslash", "a/b/c", "-org/x", "org/..", "org/x y", "/abs"):
            with self.assertRaises(runner.InputError, msg=bad):
                runner.validate_repository(bad)

    def test_uri_rules(self):
        self.assertEqual(
            runner.parse_uri("U", "gs://my-bucket/sources/org/repo/abc1234.tar.gz"),
            ("gs", "my-bucket", "sources/org/repo/abc1234.tar.gz"),
        )
        self.assertEqual(runner.parse_uri("U", "file:///tmp/x.tar.gz"), ("file", "/tmp/x.tar.gz", ""))
        self.assertEqual(runner.parse_uri("U", "/tmp/x.tar.gz"), ("file", "/tmp/x.tar.gz", ""))
        for bad in (
            "", "https://x/y", "http://x/y", "s3://b/o", "gs://b", "gs://bucket/",
            "gs://bucket/a/../b", "file://evil.com/etc/passwd", "ftp://x", "data:text/plain,hi",
            "gs://bucket/a\nb",
        ):
            with self.assertRaises(runner.InputError, msg=bad):
                runner.parse_uri("U", bad)

    def test_poc_test_path_rules(self):
        self.assertEqual(runner.validate_relative_path("P", "tests/poc"), "tests/poc")
        for bad in ("", "/etc", "../x", "tests/../../x", "tests/poc;id", "tests/$(id)"):
            with self.assertRaises(runner.InputError, msg=bad):
                runner.validate_relative_path("P", bad)

    def test_build_command(self):
        cmd = runner.build_command("python -m pytest -q {poc_test}", "tests/poc")
        self.assertEqual(cmd, [sys.executable, "-m", "pytest", "-q", "tests/poc"])
        cmd = runner.build_command("python3 -m pytest -q", "tests/poc")
        self.assertEqual(cmd[-1], "tests/poc")
        cmd = runner.build_command("make test; rm -rf /")
        self.assertEqual(cmd, ["make", "test;", "rm", "-rf", "/"])  # no shell: literal args
        with self.assertRaises(runner.InputError):
            runner.build_command("")

    def test_verdict_rules(self):
        v = runner.compute_verdict
        self.assertEqual(v("EXPLOITABLE", "NOT_EXPLOITABLE", True, False), "PATCH_VERIFIED")
        self.assertEqual(v("EXPLOITABLE", "NOT_EXPLOITABLE", False, False), "PATCH_FAILED")
        self.assertEqual(v("EXPLOITABLE", "EXPLOITABLE", True, False), "PATCH_FAILED")
        self.assertEqual(v("EXPLOITABLE", "ERROR", True, False), "PATCH_FAILED")
        self.assertEqual(v("EXPLOITABLE", None, True, False), "PATCH_FAILED")
        self.assertEqual(v("NOT_EXPLOITABLE", "NOT_EXPLOITABLE", True, False), "POC_NOT_REPRODUCED")
        self.assertEqual(v("ERROR", None, False, False), "ERROR")
        self.assertEqual(v("EXPLOITABLE", "NOT_EXPLOITABLE", True, True), "ERROR")


class TestParsingAndShape(unittest.TestCase):
    def test_parse_pytest_summary(self):
        out = "..F.\n=========== 1 failed, 3 passed, 1 skipped in 0.12s ===========\n"
        self.assertEqual(runner.parse_test_counts(out), (5, 1))
        self.assertEqual(runner.parse_test_counts("4 passed in 0.03s\n"), (4, 0))
        self.assertEqual(runner.parse_test_counts("1 passed, 2 errors in 0.5s"), (3, 2))

    def test_parse_unittest_summary(self):
        out = "..F\n----\nRan 3 tests in 0.001s\n\nFAILED (failures=1, errors=1)\n"
        self.assertEqual(runner.parse_test_counts(out), (3, 2))
        self.assertEqual(runner.parse_test_counts("Ran 2 tests in 0.0s\n\nOK\n"), (2, 0))

    def test_parse_unknown_output(self):
        self.assertEqual(runner.parse_test_counts("all good"), (None, None))

    def test_log_excerpt_truncated(self):
        log = runner.StepLog()
        for i in range(50):
            log.add_output(f"step {i}", "x" * 3000)
        excerpt = log.excerpt()
        self.assertLessEqual(len(excerpt), runner.LOG_EXCERPT_LIMIT)
        self.assertTrue(excerpt.startswith("...[truncated]..."))

    def test_result_shape_matches_naming(self):
        code, result = runner.run({"RUN_ID": "r1", "PATH": os.environ.get("PATH", "")})
        self.assertEqual(list(result.keys()), NAMING_FIELDS)
        self.assertEqual(list(runner.RESULT_FIELDS), NAMING_FIELDS)
        self.assertEqual(result["event_type"], "SANDBOX_RESULT")
        self.assertEqual(result["logging.googleapis.com/labels"], {"component": "codemender-sandbox"})
        self.assertIn(result["severity"], ("INFO", "ERROR"))
        self.assertIsInstance(result["patch_applied"], bool)
        self.assertIsInstance(result["unit_tests_passed"], bool)
        self.assertTrue(result["started_at"].endswith("Z"))
        self.assertTrue(result["finished_at"].endswith("Z"))
        self.assertEqual(code, 1)
        json.dumps(result)  # serialisable


if __name__ == "__main__":
    unittest.main()
