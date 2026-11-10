"""Repository access: parse repo specs, clone, snapshot, apply patches, open PRs.

Credentials stay on the MCP server. The GitHub token is passed to git per
command via `http.extraHeader` and is never written to `.git/config`, so the
snapshot tarball sent to the sandbox job contains no secrets (ADR-0002).
"""

from __future__ import annotations

import base64
import dataclasses
import logging
import os
from pathlib import Path
import re
import subprocess
import tarfile
from typing import Optional, Sequence

import requests

logger = logging.getLogger(__name__)

_GIT_TIMEOUT_SECONDS = 900
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_OWNER_REPO_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$")
_TAR_EXCLUDES = ("__pycache__", ".cm_project", ".exploit")


class RepoError(Exception):
  """Raised when a git or repository-host operation fails."""


@dataclasses.dataclass(frozen=True)
class RepoRef:
  """A repository identified by the user.

  Attributes:
    clone_url: HTTPS clone URL without credentials.
    full_name: `owner/repo` for GitHub repositories, else the URL.
    github: Whether the repository is hosted on github.com.
  """

  clone_url: str
  full_name: str
  github: bool

  @classmethod
  def parse(cls, spec: str) -> "RepoRef":
    """Parses `owner/repo`, a github.com URL, or any HTTPS git URL."""
    text = (spec or "").strip()
    if not text:
      raise RepoError("Repository must be a non-empty string.")
    match = _OWNER_REPO_RE.match(text)
    if match:
      owner, name = match.groups()
      return cls(f"https://github.com/{owner}/{name}.git", f"{owner}/{name}", True)
    gh = re.match(
        r"^(?:https://|git@)github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
        text,
    )
    if gh:
      owner, name = gh.groups()
      return cls(f"https://github.com/{owner}/{name}.git", f"{owner}/{name}", True)
    if text.startswith("https://") and "@" not in text.split("/")[2]:
      return cls(text, text, False)
    raise RepoError(
        f"Unsupported repository {spec!r}: use 'owner/repo' or an HTTPS URL"
        " without embedded credentials."
    )


class GitClient:
  """Thin wrapper around the `git` CLI with credential injection."""

  def __init__(
      self,
      token: str = "",
      author_name: str = "CodeMender Bot",
      author_email: str = "codemender-bot@users.noreply.github.com",
  ) -> None:
    self._token = token
    self._author_name = author_name
    self._author_email = author_email

  def _auth_args(self, repo: RepoRef) -> list[str]:
    if not self._token or not repo.github:
      return []
    basic = base64.b64encode(f"x-access-token:{self._token}".encode()).decode()
    return ["-c", f"http.https://github.com/.extraHeader=Authorization: Basic {basic}"]

  def _git(
      self,
      args: Sequence[str],
      *,
      cwd: Optional[Path] = None,
      repo: Optional[RepoRef] = None,
      input_bytes: Optional[bytes] = None,
  ) -> str:
    cmd = ["git", *(self._auth_args(repo) if repo else []), *args]
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": self._author_name,
        "GIT_AUTHOR_EMAIL": self._author_email,
        "GIT_COMMITTER_NAME": self._author_name,
        "GIT_COMMITTER_EMAIL": self._author_email,
    }
    res = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        input=input_bytes,
        capture_output=True,
        timeout=_GIT_TIMEOUT_SECONDS,
        env=env,
        check=False,
        shell=False,
    )
    if res.returncode != 0:
      err = res.stderr.decode("utf-8", "replace")
      if self._token:
        err = err.replace(self._token, "***")
      raise RepoError(f"git {args[0]} failed (exit {res.returncode}): {err.strip()}")
    return res.stdout.decode("utf-8", "replace").strip()

  def clone(self, repo: RepoRef, dest: Path, ref: str = "") -> str:
    """Clones `repo` at `ref` (branch, tag or SHA; default branch if empty).

    Returns:
      The checked-out commit SHA.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    ref = (ref or "").strip()
    if ref and not _SHA_RE.match(ref):
      self._git(
          ["clone", "--depth", "1", "--branch", ref, repo.clone_url, str(dest)],
          repo=repo,
      )
    elif ref and len(ref) == 40:
      # Shallow fetch of an exact commit; fall back to a full clone for hosts
      # that do not allow fetching unadvertised SHAs.
      dest.mkdir(parents=True, exist_ok=True)
      self._git(["init", "-q"], cwd=dest)
      self._git(["remote", "add", "origin", repo.clone_url], cwd=dest)
      try:
        self._git(["fetch", "--depth", "1", "origin", ref], cwd=dest, repo=repo)
      except RepoError:
        self._git(["fetch", "origin"], cwd=dest, repo=repo)
      self._git(["checkout", "-q", "--detach", ref], cwd=dest)
    else:
      self._git(["clone", repo.clone_url, str(dest)], repo=repo)
      if ref:
        self._git(["checkout", "--detach", ref], cwd=dest)
    return self.head_sha(dest)

  def head_sha(self, repo_dir: Path) -> str:
    return self._git(["rev-parse", "HEAD"], cwd=repo_dir)

  def current_branch(self, repo_dir: Path) -> str:
    try:
      return self._git(["symbolic-ref", "--short", "-q", "HEAD"], cwd=repo_dir)
    except RepoError:
      return ""

  def apply_and_push(
      self,
      repo: RepoRef,
      repo_dir: Path,
      *,
      base_sha: str,
      branch: str,
      patch: bytes,
      message: str,
  ) -> str:
    """Creates `branch` at `base_sha`, applies `patch`, commits and pushes.

    The clone must contain `base_sha` (a full clone, or a shallow clone of it).
    `branch` is bot-owned (`codemender/fix-*`), so it is force-pushed to make
    retries idempotent.

    Returns:
      The new commit SHA.
    """
    self._git(["checkout", "-B", branch, base_sha], cwd=repo_dir)
    self._git(["apply", "--index", "--whitespace=nowarn", "-"], cwd=repo_dir,
              input_bytes=patch)
    self._git(["commit", "-m", message], cwd=repo_dir)
    self._git(["push", "--force", "origin", f"HEAD:refs/heads/{branch}"],
              cwd=repo_dir, repo=repo)
    return self.head_sha(repo_dir)


def package_snapshot(repo_dir: Path, tarball: Path) -> None:
  """Writes a `tar.gz` of `repo_dir` (including `.git`) for the sandbox job."""
  tarball.parent.mkdir(parents=True, exist_ok=True)

  def _filter(member: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
    parts = member.name.replace("\\", "/").split("/")
    if any(p in _TAR_EXCLUDES for p in parts):
      return None
    return member

  with tarfile.open(tarball, "w:gz") as tar:
    tar.add(str(repo_dir), arcname=".", filter=_filter)


class GitHubClient:
  """Minimal GitHub REST client for opening fix pull requests."""

  def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
    self._token = token
    self._api = api_url.rstrip("/")

  def default_branch(self, full_name: str) -> str:
    data = self._request("GET", f"/repos/{full_name}")
    return str(data.get("default_branch") or "main")

  def open_pull_request(
      self, full_name: str, *, head: str, base: str, title: str, body: str
  ) -> str:
    """Opens (or returns the existing) PR for `head` -> `base`; returns its URL."""
    owner = full_name.split("/", 1)[0]
    existing = self._request(
        "GET", f"/repos/{full_name}/pulls",
        params={"head": f"{owner}:{head}", "base": base, "state": "open"},
    )
    if isinstance(existing, list) and existing:
      return str(existing[0].get("html_url", ""))
    data = self._request(
        "POST", f"/repos/{full_name}/pulls",
        json={"title": title, "head": head, "base": base, "body": body},
    )
    return str(data.get("html_url", ""))

  def _request(self, method: str, path: str, **kwargs):
    if not self._token:
      raise RepoError("GITHUB_TOKEN is required to open pull requests.")
    resp = requests.request(
        method,
        f"{self._api}{path}",
        headers={
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30,
        **kwargs,
    )
    if resp.status_code >= 300:
      raise RepoError(
          f"GitHub {method} {path} failed ({resp.status_code}): {resp.text[:300]}"
      )
    return resp.json()
