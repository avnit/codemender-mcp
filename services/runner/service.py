"""Orchestration for the CodeMender MCP tools.

Every tool call becomes a *job*:

  1. A row is written to the `jobs` table (status `STAGING`).
  2. In a background thread the repository snapshot (and the finding SARIF for
     validate/fix) is staged in GCS together with a manifest, and a **new
     Cloud Run Job execution** of the sandboxed `cm-runner` image is started
     (status `RUNNING`).
  3. A watcher polls GCS for the execution's `receipt.json`; when it appears
     the outputs are ingested into BigQuery (status `SUCCEEDED` / `FAILED`).
     `job_status` runs the same reconciliation on demand, so results are
     picked up even if the server restarted while a job was running.

GCS layout per job: `gs://<bucket>/mcp/<job_id>/{input,output}/...`, matching
the manifest contract of `cloud-run-jobs/entrypoint.py`.
"""

from __future__ import annotations

import collections
import datetime
import json
import logging
from pathlib import Path
import re
import shutil
import threading
import time
from typing import Any, Callable, Optional
import uuid

from codemender import sarif

from services.runner.cloud import JobDispatcher, Transit
from services.runner.repo import GitClient, GitHubClient, RepoError, RepoRef, package_snapshot
from services.runner.settings import PATCH_MODES, Settings
from services.runner.store import Store, utc_now

logger = logging.getLogger(__name__)

TERMINAL = ("SUCCEEDED", "FAILED")
# How long a receipt may point at a not-yet-uploaded artifact before giving up.
_ARTIFACT_GRACE_SECONDS = 300
_VERIFY_STATUS_MAP = {
    "VERIFIED": "VERIFIED",
    "DISMISSED": "FALSE_POSITIVE",
    "OPEN": "INCONCLUSIVE",
}
_SAFE_BRANCH_RE = re.compile(r"[^A-Za-z0-9._/-]+")


class ServiceError(Exception):
  """A user-facing error (bad input, missing finding, ...)."""


def _new_id() -> str:
  return uuid.uuid4().hex[:12]


def _parse_ts(value: Any) -> Optional[datetime.datetime]:
  if isinstance(value, datetime.datetime):
    return value
  if not value:
    return None
  try:
    return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
  except ValueError:
    return None


def _age_seconds(value: Any) -> float:
  ts = _parse_ts(value)
  if ts is None:
    return 0.0
  if ts.tzinfo is None:
    ts = ts.replace(tzinfo=datetime.timezone.utc)
  return (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds()


class CodeMenderService:
  """Implements find / validate / fix / status on top of injected adapters."""

  def __init__(
      self,
      settings: Settings,
      store: Store,
      transit: Transit,
      dispatcher: JobDispatcher,
      git: Optional[GitClient] = None,
      github: Optional[GitHubClient] = None,
      *,
      run_async: bool = True,
      sleep: Callable[[float], None] = time.sleep,
  ) -> None:
    self.settings = settings
    self.store = store
    self.transit = transit
    self.dispatcher = dispatcher
    self.git = git or GitClient(
        settings.github_token, settings.git_author_name, settings.git_author_email
    )
    self.github = github or GitHubClient(settings.github_token, settings.github_api_url)
    self._run_async = run_async
    self._sleep = sleep
    self._locks: dict[str, threading.Lock] = collections.defaultdict(threading.Lock)
    self._locks_guard = threading.Lock()
    self._work_root = Path(settings.work_dir)

  # ------------------------------------------------------------------ public
  def start_find(self, repo: str, ref: str = "") -> dict[str, Any]:
    """Starts a full-repository scan of `repo` at `ref`."""
    repo_ref = RepoRef.parse(repo)
    job_id = f"find-{_new_id()}"
    self._insert_job(job_id, "find", repo=repo_ref.full_name, ref=(ref or "").strip())
    self._spawn(self._stage_and_launch_find, job_id, repo_ref, (ref or "").strip())
    return self._job_view(job_id)

  def start_validate(self, finding_id: str) -> dict[str, Any]:
    """Starts `cm verify` (exploitability check) for one stored finding."""
    finding = self._require_finding(finding_id)
    job_id = f"validate-{_new_id()}"
    self._insert_job(job_id, "validate", repo=finding["repo"], ref=finding.get("ref") or "",
                     commit_sha=finding.get("commit_sha") or "", finding_id=finding_id)
    self.store.update_finding(finding_id, {"last_job_id": job_id, "updated_at": utc_now()})
    self._spawn(self._stage_and_launch_finding_job, job_id, "verify", finding)
    return self._job_view(job_id)

  def start_fix(self, finding_id: str, patch_mode: str = "") -> dict[str, Any]:
    """Starts `cm fix` for one stored finding; applies the patch per `patch_mode`."""
    mode = (patch_mode or self.settings.default_patch_mode).strip().lower()
    if mode not in PATCH_MODES:
      raise ServiceError(f"patch_mode must be one of {PATCH_MODES}, got {patch_mode!r}.")
    finding = self._require_finding(finding_id)
    job_id = f"fix-{_new_id()}"
    self._insert_job(job_id, "fix", repo=finding["repo"], ref=finding.get("ref") or "",
                     commit_sha=finding.get("commit_sha") or "", finding_id=finding_id,
                     patch_mode=mode)
    self.store.update_finding(finding_id, {"last_job_id": job_id, "updated_at": utc_now()})
    self._spawn(self._stage_and_launch_finding_job, job_id, "fix", finding)
    return self._job_view(job_id)

  def apply_patch(self, finding_id: str, patch_mode: str = "pr") -> dict[str, Any]:
    """Pushes an already generated patch (from a previous fix) to the repo."""
    mode = (patch_mode or "pr").strip().lower()
    if mode not in ("pr", "branch"):
      raise ServiceError("patch_mode must be 'pr' or 'branch'.")
    finding = self._require_finding(finding_id)
    if not finding.get("patch"):
      raise ServiceError(f"Finding {finding_id} has no stored patch; run cm_fix first.")
    return self._push_patch(finding, finding["patch"].encode("utf-8"), mode)

  def job_status(self, job_id: str, wait_seconds: int = 0) -> dict[str, Any]:
    """Reconciles and returns a job, optionally waiting for it to finish."""
    job = self.store.get_job(job_id)
    if job is None:
      raise ServiceError(f"Unknown job_id {job_id!r}.")
    deadline = time.monotonic() + max(0, min(int(wait_seconds or 0), 3000))
    while True:
      self.reconcile(job_id)
      view = self._job_view(job_id)
      if view["status"] in TERMINAL or time.monotonic() >= deadline:
        return view
      self._sleep(min(self.settings.poll_interval_seconds,
                      max(1.0, deadline - time.monotonic())))

  def list_findings(self, repo: str = "", status: str = "", scan_job_id: str = "",
                    limit: int = 100) -> list[dict[str, Any]]:
    repo_name = RepoRef.parse(repo).full_name if repo else ""
    return self.store.list_findings(repo=repo_name, status=(status or "").upper(),
                                    scan_job_id=scan_job_id,
                                    limit=max(1, min(int(limit), 1000)))

  def get_finding(self, finding_id: str, include_sarif: bool = False) -> dict[str, Any]:
    finding = self._require_finding(finding_id)
    if not include_sarif:
      finding.pop("sarif", None)
      finding.pop("verified_sarif", None)
    return finding

  def resume(self) -> None:
    """Restarts watchers for jobs left running by a previous server instance."""
    for job in self.store.list_jobs("STAGING"):
      if _age_seconds(job.get("created_at")) > 600:
        self._fail(job["job_id"], "Server restarted while staging this job.")
    for job in self.store.list_jobs("RUNNING"):
      self._spawn(self._watch, job["job_id"])

  # -------------------------------------------------------------- staging
  def _spawn(self, fn: Callable[..., Any], *args: Any) -> None:
    def _run() -> None:
      try:
        fn(*args)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception("Background task %s failed", getattr(fn, "__name__", fn))
        job_id = args[0] if args and isinstance(args[0], str) else ""
        if job_id:
          self._fail(job_id, f"{type(exc).__name__}: {exc}")

    if self._run_async:
      threading.Thread(target=_run, name=f"cm-mcp-{args[0]}", daemon=True).start()
    else:
      _run()

  def _prefix(self, job_id: str) -> str:
    return f"gs://{self.settings.bucket}/mcp/{job_id}"

  def _stage_and_launch_find(self, job_id: str, repo: RepoRef, ref: str) -> None:
    payload_uri, sha = self._stage_snapshot(job_id, repo, ref)
    self.store.update_job(job_id, {"commit_sha": sha, "payload_uri": payload_uri,
                                   "updated_at": utc_now()})
    self._launch(job_id, "find-full", payload_uri)

  def _stage_and_launch_finding_job(self, job_id: str, command: str,
                                    finding: dict[str, Any]) -> None:
    payload_uri = finding.get("payload_uri") or ""
    if not payload_uri or not self._exists(payload_uri):
      # The scan snapshot expired (bucket TTL); re-snapshot the same commit.
      payload_uri, _ = self._stage_snapshot(
          job_id, RepoRef.parse(finding["repo"]),
          finding.get("commit_sha") or finding.get("ref") or "")
    finding_uri = f"{self._prefix(job_id)}/input/finding.sarif"
    self.transit.upload_bytes(finding["sarif"].encode("utf-8"), finding_uri,
                              "application/json")
    self.store.update_job(job_id, {"payload_uri": payload_uri, "updated_at": utc_now()})
    self._launch(job_id, command, payload_uri, finding_uri)

  def _exists(self, uri: str) -> bool:
    return bool(self.transit.exists(uri))

  def _stage_snapshot(self, job_id: str, repo: RepoRef, ref: str) -> tuple[str, str]:
    work = self._work_root / job_id
    shutil.rmtree(work, ignore_errors=True)
    try:
      sha = self.git.clone(repo, work / "repo", ref)
      tarball = work / "code.tar.gz"
      package_snapshot(work / "repo", tarball)
      payload_uri = f"{self._prefix(job_id)}/input/code.tar.gz"
      self.transit.upload_file(tarball, payload_uri)
      return payload_uri, sha
    finally:
      shutil.rmtree(work, ignore_errors=True)

  def _launch(self, job_id: str, command: str, payload_uri: str,
              finding_uri: str = "") -> None:
    prefix = self._prefix(job_id)
    manifest = {
        "command": command,
        "payload_uri": payload_uri,
        "output_uri": f"{prefix}/output",
        "output_prefix": f"{prefix}/output",
        "log_level": "info",
    }
    if finding_uri:
      manifest["finding_uri"] = finding_uri
    manifest_uri = f"{prefix}/input/manifest.json"
    self.transit.upload_bytes(json.dumps(manifest, indent=2).encode("utf-8"),
                              manifest_uri, "application/json")
    execution = self.dispatcher.start([command, f"--manifest={manifest_uri}"])
    self.store.update_job(job_id, {"status": "RUNNING", "execution": execution,
                                   "gcs_prefix": prefix, "updated_at": utc_now()})
    self._watch(job_id)

  # ------------------------------------------------------------ watching
  def _watch(self, job_id: str) -> None:
    started = time.monotonic()
    while time.monotonic() - started < self.settings.job_watch_timeout_seconds:
      if self.reconcile(job_id)["status"] in TERMINAL:
        return
      self._sleep(self.settings.poll_interval_seconds)
    logger.warning("Stopped watching %s after timeout; job_status will reconcile.", job_id)

  def _lock(self, job_id: str) -> threading.Lock:
    with self._locks_guard:
      return self._locks[job_id]

  def reconcile(self, job_id: str) -> dict[str, Any]:
    """Checks a running job for completion and ingests its outputs (idempotent)."""
    with self._lock(job_id):
      job = self.store.get_job(job_id)
      if job is None:
        raise ServiceError(f"Unknown job_id {job_id!r}.")
      if job["status"] != "RUNNING":
        return job
      prefix = job["gcs_prefix"]
      raw = self.transit.download_bytes(f"{prefix}/output/receipt.json")
      if raw is None:
        state = self.dispatcher.state(job.get("execution") or "")
        if state in ("FAILED", "SUCCEEDED") and _age_seconds(job.get("updated_at")) > 120:
          self._fail(job_id, f"Cloud Run execution {state.lower()} without writing a receipt.")
        elif _age_seconds(job.get("created_at")) > self.settings.job_watch_timeout_seconds:
          self._fail(job_id, "Timed out waiting for the Cloud Run execution.")
        return self.store.get_job(job_id) or job
      receipt = json.loads(raw.decode("utf-8"))
      outputs = self._collect_outputs(prefix, receipt)
      if outputs is None:  # receipt uploaded before its artifacts
        if _age_seconds(receipt.get("completed_at")) < _ARTIFACT_GRACE_SECONDS:
          return job
        outputs = {}
      handler = {"find": self._ingest_find, "validate": self._ingest_validate,
                 "fix": self._ingest_fix}[job["kind"]]
      handler(job, receipt, outputs)
      return self.store.get_job(job_id) or job

  def _collect_outputs(self, prefix: str, receipt: dict[str, Any]) -> Optional[dict[str, bytes]]:
    outputs: dict[str, bytes] = {}
    for role, uri in (receipt.get("artifacts") or {}).items():
      if role == "log":
        continue
      data = self.transit.download_bytes(uri)
      if data is None:
        return None
      outputs[role] = data
    log = self.transit.download_bytes(f"{prefix}/output/runner.log")
    if log is not None:
      outputs["log"] = log
    return outputs

  # ------------------------------------------------------------ ingestion
  @staticmethod
  def _receipt_error(receipt: dict[str, Any], outputs: dict[str, bytes]) -> str:
    err = receipt.get("error") or f"cm-runner exited with code {receipt.get('exit_code')}"
    tail = outputs.get("log", b"").decode("utf-8", "replace").strip().splitlines()[-15:]
    return err + ("\n--- runner.log (tail) ---\n" + "\n".join(tail) if tail else "")

  def _ingest_find(self, job: dict[str, Any], receipt: dict[str, Any],
                   outputs: dict[str, bytes]) -> None:
    job_id = job["job_id"]
    if int(receipt.get("exit_code", 1)) != 0 or "sarif" not in outputs:
      self._fail(job_id, self._receipt_error(receipt, outputs))
      return
    doc = sarif.SarifDocument.from_json(outputs["sarif"].decode("utf-8"))
    findings = doc.to_findings()
    if not self.store.list_findings(scan_job_id=job_id, limit=1):  # idempotent
      now = utc_now()
      scan_key = job_id.split("-", 1)[-1]
      rows = [{
          "finding_id": f"{scan_key}-{f.index:03d}",
          "scan_job_id": job_id,
          "repo": job["repo"],
          "ref": job.get("ref") or "",
          "commit_sha": job.get("commit_sha") or "",
          "payload_uri": job.get("payload_uri") or "",
          "fingerprint": f.finding_id,
          "rule_id": f.rule_id,
          "severity": f.severity,
          "message": f.message,
          "file_path": f.file_path,
          "start_line": f.start_line,
          "end_line": f.end_line,
          "status": "OPEN",
          "sarif": json.dumps(f.document),
          "created_at": now,
          "updated_at": now,
      } for f in findings]
      self.store.insert_findings(rows)
    by_severity = collections.Counter(f.severity or "UNKNOWN" for f in findings)
    self._succeed(job_id, {"finding_count": len(findings),
                           "by_severity": dict(by_severity),
                           "report_uri": (receipt.get("artifacts") or {}).get("report", "")},
                  finding_count=len(findings))

  def _ingest_validate(self, job: dict[str, Any], receipt: dict[str, Any],
                       outputs: dict[str, bytes]) -> None:
    job_id, finding_id = job["job_id"], job["finding_id"]
    finding = self.store.get_finding(finding_id) or {}
    if int(receipt.get("exit_code", 1)) != 0 or "sarif" not in outputs:
      self.store.update_finding(finding_id, {"verify_status": "FAILED", "updated_at": utc_now()})
      self._fail(job_id, self._receipt_error(receipt, outputs))
      return
    text = outputs["sarif"].decode("utf-8")
    results = sarif.SarifDocument.from_json(text).results
    props = (results[0].get("properties") or {}) if results else {}
    cm_status = str(props.get("status") or "OPEN").upper()
    fields: dict[str, Any] = {
        "verify_status": cm_status,
        "dismiss_reason": str(props.get("dismiss_reason") or ""),
        "verified_sarif": text,
        "updated_at": utc_now(),
    }
    if finding.get("status") not in ("FIXED", "PATCHED"):
      fields["status"] = _VERIFY_STATUS_MAP.get(cm_status, "INCONCLUSIVE")
    self.store.update_finding(finding_id, fields)
    self._succeed(job_id, {"verify_status": cm_status,
                           "finding_status": fields.get("status", finding.get("status")),
                           "dismiss_reason": fields["dismiss_reason"]})

  def _ingest_fix(self, job: dict[str, Any], receipt: dict[str, Any],
                  outputs: dict[str, bytes]) -> None:
    job_id, finding_id = job["job_id"], job["finding_id"]
    patch = outputs.get("patch", b"")
    if int(receipt.get("exit_code", 1)) != 0 or not patch.strip():
      self.store.update_finding(finding_id, {
          "fix_status": "FAILED" if int(receipt.get("exit_code", 1)) else "NO_PATCH",
          "updated_at": utc_now()})
      self._fail(job_id, self._receipt_error(receipt, outputs)
                 if int(receipt.get("exit_code", 1)) else "cm fix produced no patch.")
      return
    self.store.update_finding(finding_id, {
        "patch": patch.decode("utf-8", "replace"), "fix_status": "FIXED",
        "status": "FIXED", "updated_at": utc_now()})
    result: dict[str, Any] = {"patch_bytes": len(patch), "patch_mode": job.get("patch_mode")}
    mode = job.get("patch_mode") or "none"
    if mode in ("pr", "branch"):
      finding = self.store.get_finding(finding_id) or {}
      try:
        result.update(self._push_patch(finding, patch, mode))
      except (RepoError, ServiceError) as exc:
        self._fail(job_id, f"Patch generated and stored in BigQuery, but applying it to"
                   f" the repository failed: {exc}. Retry with cm_apply_patch.")
        return
    self._succeed(job_id, result)

  def _push_patch(self, finding: dict[str, Any], patch: bytes, mode: str) -> dict[str, Any]:
    repo = RepoRef.parse(finding["repo"])
    finding_id = finding["finding_id"]
    branch = _SAFE_BRANCH_RE.sub("-", f"codemender/fix-{finding_id}")
    base_sha = finding.get("commit_sha") or ""
    work = self._work_root / f"push-{finding_id}-{_new_id()}"
    try:
      sha = self.git.clone(repo, work / "repo", base_sha)
      commit = self.git.apply_and_push(
          repo, work / "repo", base_sha=base_sha or sha, branch=branch, patch=patch,
          message=(f"fix: CodeMender patch for {finding.get('rule_id') or 'finding'}"
                   f" in {finding.get('file_path') or 'repository'}\n\n"
                   f"CodeMender finding {finding_id}: {finding.get('message', '')[:500]}"))
    finally:
      shutil.rmtree(work, ignore_errors=True)
    fields: dict[str, Any] = {"patch_branch": branch, "patch_commit": commit,
                              "fix_status": "PATCHED", "status": "PATCHED",
                              "updated_at": utc_now()}
    if mode == "pr":
      if not repo.github:
        raise ServiceError("Pull requests are only supported for GitHub repositories.")
      ref = finding.get("ref") or ""
      base = ref if ref and not re.fullmatch(r"[0-9a-f]{7,40}", ref) else (
          self.github.default_branch(repo.full_name))
      fields["pr_url"] = self.github.open_pull_request(
          repo.full_name, head=branch, base=base,
          title=f"CodeMender fix: {finding.get('rule_id') or finding_id}"
                f" in {finding.get('file_path') or 'repository'}",
          body=(f"Automated patch generated by CodeMender for finding `{finding_id}`.\n\n"
                f"- **Rule:** {finding.get('rule_id', '')}\n"
                f"- **Severity:** {finding.get('severity', '')}\n"
                f"- **Location:** `{finding.get('file_path', '')}:{finding.get('start_line', '')}`\n"
                f"- **Verification:** {finding.get('verify_status') or 'not run'}\n\n"
                f"> {finding.get('message', '')[:1500]}\n\n"
                "Please review carefully before merging."))
    self.store.update_finding(finding_id, fields)
    return {k: fields[k] for k in ("patch_branch", "patch_commit", "pr_url") if k in fields}

  # -------------------------------------------------------------- helpers
  def _insert_job(self, job_id: str, kind: str, **fields: Any) -> None:
    now = utc_now()
    self.store.insert_job({"job_id": job_id, "kind": kind, "status": "STAGING",
                           "created_at": now, "updated_at": now, **fields})

  def _succeed(self, job_id: str, result: dict[str, Any], finding_count: int = 0) -> None:
    now = utc_now()
    self.store.update_job(job_id, {"status": "SUCCEEDED", "result": json.dumps(result),
                                   "finding_count": finding_count,
                                   "updated_at": now, "completed_at": now})

  def _fail(self, job_id: str, error: str) -> None:
    now = utc_now()
    logger.error("Job %s failed: %s", job_id, error)
    self.store.update_job(job_id, {"status": "FAILED", "error": error[:10000],
                                   "updated_at": now, "completed_at": now})

  def _require_finding(self, finding_id: str) -> dict[str, Any]:
    finding = self.store.get_finding((finding_id or "").strip())
    if finding is None:
      raise ServiceError(f"Unknown finding_id {finding_id!r}. Use cm_list_findings.")
    if not finding.get("sarif"):
      raise ServiceError(f"Finding {finding_id} has no SARIF document stored.")
    return finding

  def _job_view(self, job_id: str) -> dict[str, Any]:
    job = self.store.get_job(job_id) or {}
    view = {k: job.get(k) for k in ("job_id", "kind", "status", "repo", "ref", "commit_sha",
                                    "finding_id", "patch_mode", "execution", "finding_count",
                                    "error", "created_at", "completed_at")}
    if job.get("result"):
      view["result"] = json.loads(job["result"])
    return {k: v for k, v in view.items() if v not in (None, "")}
