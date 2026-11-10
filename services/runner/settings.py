"""Environment-driven configuration for the CodeMender MCP server."""

from __future__ import annotations

import dataclasses
import os

PATCH_MODES = ("pr", "branch", "none")


def _env(name: str, default: str = "") -> str:
  return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
  raw = _env(name)
  if not raw:
    return default
  try:
    return int(raw)
  except ValueError as exc:
    raise ValueError(f"{name} must be an integer, got {raw!r}.") from exc


@dataclasses.dataclass(frozen=True)
class Settings:
  """Runtime settings, loaded once at startup.

  Attributes:
    project: GCP project hosting the Cloud Run Job, bucket and BigQuery.
    region: Region of the Cloud Run Job.
    job_name: Name of the sandboxed `cm-runner` Cloud Run Job to execute.
    bucket: GCS transit bucket shared with the job (inputs and outputs).
    bq_dataset: BigQuery dataset holding the `jobs` and `findings` tables.
    bq_location: BigQuery dataset location (used when creating the dataset).
    github_token: Token used to clone private repos, push fix branches and
      open pull requests. Never forwarded to the sandbox job.
    github_api_url: GitHub REST API base URL (override for GHES).
    auth_token: Optional static bearer token required on every MCP request.
    default_patch_mode: Default `cm_fix` behaviour: `pr`, `branch` or `none`.
    poll_interval_seconds: How often watchers poll GCS for a job receipt.
    job_watch_timeout_seconds: Give up watching a job after this long.
    work_dir: Scratch directory for clones and tarballs.
    git_author_name / git_author_email: Identity for fix commits.
    port: HTTP port (Cloud Run sets `PORT`).
  """

  project: str
  region: str = "us-central1"
  job_name: str = "codemender-runner"
  bucket: str = ""
  bq_dataset: str = "codemender"
  bq_location: str = "US"
  github_token: str = dataclasses.field(default="", repr=False)
  github_api_url: str = "https://api.github.com"
  auth_token: str = dataclasses.field(default="", repr=False)
  default_patch_mode: str = "pr"
  poll_interval_seconds: int = 20
  job_watch_timeout_seconds: int = 4 * 60 * 60
  work_dir: str = "/tmp/cm-mcp"
  git_author_name: str = "CodeMender Bot"
  git_author_email: str = "codemender-bot@users.noreply.github.com"
  port: int = 8080

  def __post_init__(self) -> None:
    if not self.project:
      raise ValueError("GOOGLE_CLOUD_PROJECT must be set.")
    if self.default_patch_mode not in PATCH_MODES:
      raise ValueError(
          f"CM_MCP_DEFAULT_PATCH_MODE must be one of {PATCH_MODES}, got"
          f" {self.default_patch_mode!r}."
      )
    if not self.bucket:
      # Matches the Terraform default for the reports/transit bucket.
      object.__setattr__(
          self, "bucket", f"codemender-reports-{self.project}"
      )

  @classmethod
  def from_env(cls) -> "Settings":
    """Builds `Settings` from environment variables."""
    return cls(
        project=_env("GOOGLE_CLOUD_PROJECT") or _env("GCP_PROJECT_ID"),
        region=_env("CLOUD_RUN_REGION", "us-central1"),
        job_name=_env("CLOUD_RUN_JOB_NAME", "codemender-runner"),
        bucket=_env("GCS_TRANSIT_BUCKET"),
        bq_dataset=_env("BQ_DATASET", "codemender"),
        bq_location=_env("BQ_LOCATION", "US"),
        github_token=_env("GITHUB_TOKEN"),
        github_api_url=_env("GITHUB_API_URL", "https://api.github.com"),
        auth_token=_env("CM_MCP_AUTH_TOKEN"),
        default_patch_mode=_env("CM_MCP_DEFAULT_PATCH_MODE", "pr"),
        poll_interval_seconds=_env_int("CM_MCP_POLL_INTERVAL_SECONDS", 20),
        job_watch_timeout_seconds=_env_int(
            "CM_MCP_JOB_WATCH_TIMEOUT_SECONDS", 4 * 60 * 60
        ),
        work_dir=_env("CM_MCP_WORK_DIR", "/tmp/cm-mcp"),
        git_author_name=_env("GIT_AUTHOR_NAME", "CodeMender Bot"),
        git_author_email=_env(
            "GIT_AUTHOR_EMAIL", "codemender-bot@users.noreply.github.com"
        ),
        port=_env_int("PORT", 8080),
    )
