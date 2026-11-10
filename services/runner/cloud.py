"""Google Cloud adapters: GCS transit storage and Cloud Run Job dispatch.

Both are small interfaces so the service can be unit tested with fakes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Protocol, Sequence

logger = logging.getLogger(__name__)


class Transit(Protocol):
  """Object storage shared between the MCP server and the sandbox job."""

  def upload_file(self, src: Path, uri: str) -> None: ...

  def upload_bytes(self, data: bytes, uri: str, content_type: str = ...) -> None: ...

  def download_bytes(self, uri: str) -> Optional[bytes]:
    """Returns the object's bytes, or None if it does not exist."""

  def exists(self, uri: str) -> bool: ...


class JobDispatcher(Protocol):
  """Starts and inspects Cloud Run Job executions."""

  def start(self, args: Sequence[str]) -> str:
    """Starts an execution with container `args`; returns its resource name."""

  def state(self, execution_name: str) -> str:
    """Returns `RUNNING`, `SUCCEEDED`, `FAILED` or `UNKNOWN`."""


def _split_gs(uri: str) -> tuple[str, str]:
  if not uri.startswith("gs://"):
    raise ValueError(f"Expected a gs:// URI, got {uri!r}.")
  bucket, _, blob = uri[len("gs://"):].partition("/")
  return bucket, blob


class GcsTransit:
  """`Transit` backed by google-cloud-storage."""

  def __init__(self, project: str) -> None:
    from google.cloud import storage  # pylint: disable=import-outside-toplevel

    self._client = storage.Client(project=project)

  def _blob(self, uri: str):
    bucket, blob = _split_gs(uri)
    return self._client.bucket(bucket).blob(blob)

  def upload_file(self, src: Path, uri: str) -> None:
    self._blob(uri).upload_from_filename(str(src))

  def upload_bytes(
      self, data: bytes, uri: str, content_type: str = "application/octet-stream"
  ) -> None:
    self._blob(uri).upload_from_string(data, content_type=content_type)

  def exists(self, uri: str) -> bool:
    return bool(self._blob(uri).exists())

  def download_bytes(self, uri: str) -> Optional[bytes]:
    from google.api_core import exceptions  # pylint: disable=import-outside-toplevel

    try:
      return self._blob(uri).download_as_bytes()
    except exceptions.NotFound:
      return None


class CloudRunJobDispatcher:
  """`JobDispatcher` that runs the sandbox Cloud Run Job with arg overrides.

  Each call creates a brand-new execution of the same job definition, so
  find/validate/fix calls run in isolated, ephemeral containers and can run in
  parallel.
  """

  def __init__(self, project: str, region: str, job_name: str) -> None:
    from google.cloud import run_v2  # pylint: disable=import-outside-toplevel

    self._run_v2 = run_v2
    self._jobs = run_v2.JobsClient()
    self._executions = run_v2.ExecutionsClient()
    self._job_path = self._jobs.job_path(project, region, job_name)

  def start(self, args: Sequence[str]) -> str:
    overrides = self._run_v2.RunJobRequest.Overrides(
        container_overrides=[
            self._run_v2.RunJobRequest.Overrides.ContainerOverride(args=list(args))
        ]
    )
    operation = self._jobs.run_job(
        request=self._run_v2.RunJobRequest(name=self._job_path, overrides=overrides)
    )
    name = ""
    try:
      name = operation.metadata.name if operation.metadata else ""
    except Exception:  # pylint: disable=broad-exception-caught
      name = ""
    logger.info("Started Cloud Run execution %s (args=%s)", name or "<pending>", args)
    return name

  def state(self, execution_name: str) -> str:
    if not execution_name:
      return "UNKNOWN"
    try:
      execution = self._executions.get_execution(name=execution_name)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning("get_execution(%s) failed: %s", execution_name, exc)
      return "UNKNOWN"
    if not execution.completion_time:
      return "RUNNING"
    if execution.failed_count or execution.cancelled_count:
      return "FAILED"
    return "SUCCEEDED"
