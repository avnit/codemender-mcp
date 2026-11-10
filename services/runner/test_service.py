"""Hermetic tests for the MCP orchestration service (fakes for GCP + git)."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Optional, Sequence
import unittest

from services.runner.repo import GitClient, RepoError, RepoRef, package_snapshot
from services.runner.service import CodeMenderService, ServiceError
from services.runner.settings import Settings
from services.runner.store import InMemoryStore

_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeMender"}},
        "results": [
            {"ruleId": "CWE-78", "level": "error",
             "message": {"text": "Command injection"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "src/app.py"},
                 "region": {"startLine": 10, "endLine": 12}}}]},
            {"ruleId": "CWE-89", "level": "warning",
             "message": {"text": "SQL injection"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "src/db.py"},
                 "region": {"startLine": 4}}}]},
        ],
    }],
}
_PATCH = b"diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x\n+y\n"


class FakeTransit:
  def __init__(self) -> None:
    self.objects: dict[str, bytes] = {}

  def upload_file(self, src: Path, uri: str) -> None:
    self.objects[uri] = Path(src).read_bytes()

  def upload_bytes(self, data: bytes, uri: str, content_type: str = "") -> None:
    self.objects[uri] = data

  def download_bytes(self, uri: str) -> Optional[bytes]:
    return self.objects.get(uri)

  def exists(self, uri: str) -> bool:
    return uri in self.objects


class FakeDispatcher:
  """Simulates the sandbox job by writing outputs + receipt into transit."""

  def __init__(self, transit: FakeTransit) -> None:
    self.transit = transit
    self.calls: list[list[str]] = []
    self.exit_code = 0
    self.verify_status = "VERIFIED"
    self.patch = _PATCH
    self.write_receipt = True

  def start(self, args: Sequence[str]) -> str:
    self.calls.append(list(args))
    command, manifest_uri = args[0], args[1].split("=", 1)[1]
    manifest = json.loads(self.transit.objects[manifest_uri])
    out = manifest["output_uri"]
    artifacts = {"log": f"{out}/runner.log"}
    self.transit.objects[f"{out}/runner.log"] = b"log line\n"
    if self.exit_code == 0:
      if command == "find-full":
        self.transit.objects[f"{out}/report.sarif"] = json.dumps(_SARIF).encode()
        artifacts["sarif"] = f"{out}/report.sarif"
      elif command == "verify":
        doc = json.loads(self.transit.objects[manifest["finding_uri"]])
        doc["runs"][0]["results"][0]["properties"] = {
            "status": self.verify_status, "dismiss_reason": "not reachable"}
        self.transit.objects[f"{out}/finding.sarif"] = json.dumps(doc).encode()
        artifacts["sarif"] = f"{out}/finding.sarif"
      elif command == "fix" and self.patch:
        self.transit.objects[f"{out}/fix.patch"] = self.patch
        artifacts["patch"] = f"{out}/fix.patch"
    if self.write_receipt:
      receipt = {"status": "SUCCESS" if self.exit_code == 0 else "FAILURE",
                 "exit_code": self.exit_code, "command": command,
                 "completed_at": "2026-01-01T00:00:00Z", "artifacts": artifacts,
                 "error": None if self.exit_code == 0 else "boom"}
      self.transit.objects[f"{out}/receipt.json"] = json.dumps(receipt).encode()
    return f"projects/p/locations/r/jobs/j/executions/e{len(self.calls)}"

  def state(self, execution_name: str) -> str:
    return "FAILED"


class FakeGit:
  def __init__(self) -> None:
    self.clones: list[tuple[str, str]] = []
    self.pushes: list[dict] = []
    self.fail_push = False

  def clone(self, repo: RepoRef, dest: Path, ref: str = "") -> str:
    self.clones.append((repo.full_name, ref))
    (dest / ".git").mkdir(parents=True)
    (dest / "src").mkdir()
    (dest / "src" / "app.py").write_text("x\n")
    return ref if len(ref) == 40 else "a" * 40

  def apply_and_push(self, repo, repo_dir, *, base_sha, branch, patch, message):
    if self.fail_push:
      raise RepoError("push rejected")
    self.pushes.append({"repo": repo.full_name, "base_sha": base_sha,
                        "branch": branch, "patch": patch})
    return "b" * 40


class FakeGitHub:
  def __init__(self) -> None:
    self.prs: list[dict] = []

  def default_branch(self, full_name: str) -> str:
    return "main"

  def open_pull_request(self, full_name, *, head, base, title, body) -> str:
    self.prs.append({"repo": full_name, "head": head, "base": base, "title": title})
    return f"https://github.com/{full_name}/pull/1"


class ServiceTestBase(unittest.TestCase):

  def setUp(self) -> None:
    self.tmp = tempfile.mkdtemp(prefix="cm_mcp_test_")
    self.addCleanup(shutil.rmtree, self.tmp, True)
    self.settings = Settings(project="proj", bucket="bkt", work_dir=self.tmp,
                             poll_interval_seconds=0)
    self.store = InMemoryStore()
    self.transit = FakeTransit()
    self.dispatcher = FakeDispatcher(self.transit)
    self.git = FakeGit()
    self.github = FakeGitHub()
    self.service = CodeMenderService(
        self.settings, self.store, self.transit, self.dispatcher,
        self.git, self.github, run_async=False, sleep=lambda _: None)

  def _scan(self, ref: str = "") -> dict:
    return self.service.start_find("acme/widgets", ref)


class TestFind(ServiceTestBase):

  def test_find_stages_snapshot_launches_job_and_ingests_findings(self):
    view = self._scan("main")
    self.assertEqual(view["status"], "SUCCEEDED")
    self.assertEqual(view["finding_count"], 2)
    self.assertEqual(view["result"]["by_severity"], {"ERROR": 1, "WARNING": 1})
    self.assertEqual(self.git.clones, [("acme/widgets", "main")])
    command, manifest_arg = self.dispatcher.calls[0]
    self.assertEqual(command, "find-full")
    manifest = json.loads(self.transit.objects[manifest_arg.split("=", 1)[1]])
    self.assertEqual(manifest["command"], "find-full")
    self.assertTrue(manifest["payload_uri"].startswith(f"gs://bkt/mcp/{view['job_id']}/"))
    self.assertIn(manifest["payload_uri"], self.transit.objects)

    findings = self.service.list_findings("acme/widgets")
    self.assertEqual(len(findings), 2)
    first = self.service.get_finding(findings[0]["finding_id"], include_sarif=True)
    self.assertEqual(first["status"], "OPEN")
    self.assertEqual(first["commit_sha"], "a" * 40)
    self.assertEqual(len(json.loads(first["sarif"])["runs"][0]["results"]), 1)

  def test_find_reingest_is_idempotent(self):
    view = self._scan()
    self.store.update_job(view["job_id"], {"status": "RUNNING"})
    self.service.reconcile(view["job_id"])
    self.assertEqual(len(self.store.findings), 2)

  def test_find_failure_records_error_with_log_tail(self):
    self.dispatcher.exit_code = 3
    view = self._scan()
    self.assertEqual(view["status"], "FAILED")
    self.assertIn("boom", view["error"])
    self.assertIn("log line", view["error"])
    self.assertEqual(self.store.findings, {})

  def test_execution_failed_without_receipt(self):
    self.dispatcher.write_receipt = False
    self.settings = Settings(project="proj", bucket="bkt", work_dir=self.tmp,
                             poll_interval_seconds=0, job_watch_timeout_seconds=0)
    self.service.settings = self.settings
    view = self._scan()
    self.assertEqual(view["status"], "RUNNING")
    self.store.update_job(view["job_id"], {"updated_at": "2000-01-01T00:00:00+00:00"})
    status = self.service.job_status(view["job_id"])
    self.assertEqual(status["status"], "FAILED")
    self.assertIn("without writing a receipt", status["error"])

  def test_receipt_before_artifacts_waits(self):
    view = self._scan()
    job = self.store.get_job(view["job_id"])
    self.store.update_job(view["job_id"], {"status": "RUNNING"})
    del self.transit.objects[f"{job['gcs_prefix']}/output/report.sarif"]
    receipt_uri = f"{job['gcs_prefix']}/output/receipt.json"
    receipt = json.loads(self.transit.objects[receipt_uri])
    receipt["completed_at"] = "2999-01-01T00:00:00+00:00"
    self.transit.objects[receipt_uri] = json.dumps(receipt).encode()
    self.assertEqual(self.service.reconcile(view["job_id"])["status"], "RUNNING")

  def test_rejects_bad_repo(self):
    with self.assertRaises(RepoError):
      self.service.start_find("https://user:secret@example.com/x.git")


class TestValidate(ServiceTestBase):

  def test_validate_verified(self):
    self._scan()
    fid = self.service.list_findings()[0]["finding_id"]
    view = self.service.start_validate(fid)
    self.assertEqual(view["status"], "SUCCEEDED")
    self.assertEqual(self.dispatcher.calls[-1][0], "verify")
    finding = self.service.get_finding(fid, include_sarif=True)
    self.assertEqual(finding["status"], "VERIFIED")
    self.assertEqual(finding["verify_status"], "VERIFIED")
    self.assertTrue(finding["verified_sarif"])
    # Reuses the scan snapshot instead of re-cloning.
    self.assertEqual(len(self.git.clones), 1)

  def test_validate_dismissed_is_false_positive(self):
    self._scan()
    fid = self.service.list_findings()[0]["finding_id"]
    self.dispatcher.verify_status = "DISMISSED"
    self.service.start_validate(fid)
    finding = self.service.get_finding(fid)
    self.assertEqual(finding["status"], "FALSE_POSITIVE")
    self.assertEqual(finding["dismiss_reason"], "not reachable")

  def test_validate_reclones_when_snapshot_expired(self):
    view = self._scan()
    fid = self.service.list_findings()[0]["finding_id"]
    payload = self.store.get_job(view["job_id"])["payload_uri"]
    del self.transit.objects[payload]
    self.service.start_validate(fid)
    self.assertEqual(self.git.clones[-1], ("acme/widgets", "a" * 40))

  def test_unknown_finding(self):
    with self.assertRaises(ServiceError):
      self.service.start_validate("nope")


class TestFix(ServiceTestBase):

  def test_fix_stores_patch_pushes_branch_and_opens_pr(self):
    self._scan("release")
    fid = self.service.list_findings()[0]["finding_id"]
    view = self.service.start_fix(fid)
    self.assertEqual(view["status"], "SUCCEEDED", view)
    finding = self.service.get_finding(fid)
    self.assertEqual(finding["patch"], _PATCH.decode())
    self.assertEqual(finding["status"], "PATCHED")
    self.assertEqual(finding["patch_branch"], f"codemender/fix-{fid}")
    self.assertEqual(finding["pr_url"], "https://github.com/acme/widgets/pull/1")
    self.assertEqual(self.git.pushes[0]["base_sha"], "a" * 40)
    self.assertEqual(self.github.prs[0]["base"], "release")

  def test_fix_patch_mode_none_only_stores_patch(self):
    self._scan()
    fid = self.service.list_findings()[0]["finding_id"]
    view = self.service.start_fix(fid, patch_mode="none")
    self.assertEqual(view["status"], "SUCCEEDED")
    self.assertEqual(self.service.get_finding(fid)["status"], "FIXED")
    self.assertEqual(self.git.pushes, [])

  def test_fix_push_failure_keeps_patch_and_apply_patch_retries(self):
    self._scan()
    fid = self.service.list_findings()[0]["finding_id"]
    self.git.fail_push = True
    view = self.service.start_fix(fid, patch_mode="branch")
    self.assertEqual(view["status"], "FAILED")
    self.assertIn("cm_apply_patch", view["error"])
    self.assertEqual(self.service.get_finding(fid)["status"], "FIXED")
    self.git.fail_push = False
    result = self.service.apply_patch(fid, "branch")
    self.assertEqual(result["patch_branch"], f"codemender/fix-{fid}")
    self.assertNotIn("pr_url", result)

  def test_fix_no_patch(self):
    self._scan()
    fid = self.service.list_findings()[0]["finding_id"]
    self.dispatcher.patch = b""
    view = self.service.start_fix(fid)
    self.assertEqual(view["status"], "FAILED")
    self.assertEqual(self.service.get_finding(fid)["fix_status"], "NO_PATCH")

  def test_invalid_patch_mode(self):
    with self.assertRaises(ServiceError):
      self.service.start_fix("x", patch_mode="direct")


class TestResume(ServiceTestBase):

  def test_resume_reconciles_running_jobs_and_fails_stale_staging(self):
    view = self._scan()
    self.store.update_job(view["job_id"], {"status": "RUNNING"})
    self.store.insert_job({"job_id": "find-stale", "kind": "find", "status": "STAGING",
                           "repo": "acme/widgets", "created_at": "2000-01-01T00:00:00+00:00"})
    self.service.resume()
    self.assertEqual(self.store.get_job(view["job_id"])["status"], "SUCCEEDED")
    self.assertEqual(self.store.get_job("find-stale")["status"], "FAILED")


class TestRepo(unittest.TestCase):

  def test_parse(self):
    self.assertEqual(RepoRef.parse("acme/widgets").clone_url,
                     "https://github.com/acme/widgets.git")
    self.assertEqual(RepoRef.parse("https://github.com/acme/widgets.git").full_name,
                     "acme/widgets")
    self.assertEqual(RepoRef.parse("git@github.com:acme/widgets.git").full_name,
                     "acme/widgets")
    ref = RepoRef.parse("https://gitlab.com/acme/widgets.git")
    self.assertFalse(ref.github)
    for bad in ("", "https://u:p@github.com/a/b", "ftp://x/y", "a/b/c"):
      with self.assertRaises(RepoError):
        RepoRef.parse(bad)

  def test_token_is_not_persisted_in_git_config(self):
    client = GitClient(token="s3cr3t")
    args = client._auth_args(RepoRef.parse("acme/widgets"))
    self.assertTrue(args[1].startswith("http.https://github.com/.extraHeader="))
    self.assertNotIn("s3cr3t", args[1])  # base64-encoded, header only

  def test_package_snapshot_excludes_cm_state(self):
    tmp = Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, tmp, True)
    (tmp / "repo" / ".cm_project").mkdir(parents=True)
    (tmp / "repo" / "a.py").write_text("print(1)\n")
    package_snapshot(tmp / "repo", tmp / "out.tgz")
    import tarfile  # pylint: disable=import-outside-toplevel
    with tarfile.open(tmp / "out.tgz") as tar:
      names = tar.getnames()
    self.assertIn("./a.py", names)
    self.assertFalse(any(".cm_project" in n for n in names))


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class TestGitClientEndToEnd(unittest.TestCase):
  """Clone a local bare repo, apply a patch, push a fix branch."""

  def _run(self, *args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)

  def test_apply_and_push(self):
    tmp = Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, tmp, True)
    origin, seed = tmp / "origin.git", tmp / "seed"
    self._run("init", "--bare", "-b", "main", str(origin))
    self._run("init", "-b", "main", str(seed))
    (seed / "app.py").write_text("x\n")
    self._run("add", ".", cwd=seed)
    self._run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "init", cwd=seed)
    self._run("push", str(origin), "main", cwd=seed)

    repo = RepoRef(clone_url=str(origin), full_name="local/origin", github=False)
    client = GitClient()
    sha = client.clone(repo, tmp / "work", "main")
    patch = (b"diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
             b"@@ -1 +1 @@\n-x\n+y\n")
    commit = client.apply_and_push(repo, tmp / "work", base_sha=sha,
                                   branch="codemender/fix-1", patch=patch, message="fix")
    out = subprocess.run(["git", "--git-dir", str(origin), "show",
                          "codemender/fix-1:app.py"], capture_output=True, check=True)
    self.assertEqual(out.stdout, b"y\n")
    self.assertEqual(len(commit), 40)


if __name__ == "__main__":
  unittest.main()
