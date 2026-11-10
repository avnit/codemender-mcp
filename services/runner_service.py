"""Runner service factory and integration for CodeMender execution (find, validate, fix).

Connects the FastMCP server in server.py to the CodeMenderService orchestration layer
which dispatches ephemeral Cloud Run Job executions and ingests findings/patches into BigQuery.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from config import settings
from services.runner.service import CodeMenderService, ServiceError
from services.runner.settings import Settings as RunnerSettings
from services.runner.store import Store, InMemoryStore

logger = logging.getLogger("codemender-runner-service")


class RunnerServiceWrapper:
    """Wrapper that manages CodeMenderService lifecycle and fallback logic."""

    def __init__(self) -> None:
        self._service: Optional[CodeMenderService] = None
        self._init_error: Optional[str] = None

    def get_service(self) -> CodeMenderService:
        if self._service is not None:
            return self._service

        project = settings.gcp_project_id
        if not project:
            raise ServiceError("GOOGLE_CLOUD_PROJECT / gcp_project_id is not configured.")

        bucket = settings.cm_reports_bucket or f"codemender-reports-{project}"
        runner_settings = RunnerSettings(
            project=project,
            region=settings.gcp_region,
            job_name=settings.cm_runner_job_name,
            bucket=bucket,
            bq_dataset=settings.bq_dataset,
            bq_location=settings.bq_location,
            github_token=settings.github_token or "",
            github_api_url=settings.github_api_url,
            default_patch_mode=settings.cm_default_patch_mode,
            poll_interval_seconds=settings.cm_poll_interval_seconds,
            job_watch_timeout_seconds=settings.cm_job_watch_timeout_seconds,
            work_dir=settings.cm_work_dir,
            git_author_name=settings.git_author_name,
            git_author_email=settings.git_author_email,
            port=settings.port,
        )

        try:
            from services.runner.cloud import CloudRunJobDispatcher, GcsTransit
            from services.runner.store import BigQueryStore

            store = BigQueryStore(
                project=runner_settings.project,
                dataset=runner_settings.bq_dataset,
                location=runner_settings.bq_location,
            )
            store.ensure_schema()
            transit = GcsTransit(runner_settings.project)
            dispatcher = CloudRunJobDispatcher(
                project=runner_settings.project,
                region=runner_settings.region,
                job_name=runner_settings.job_name,
            )
            self._service = CodeMenderService(
                settings=runner_settings,
                store=store,
                transit=transit,
                dispatcher=dispatcher,
            )
            try:
                self._service.resume()
            except Exception as e:
                logger.warning("CodeMenderService.resume() warning: %s", e)
            return self._service
        except Exception as exc:
            self._init_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Failed to initialize production CodeMenderService: %s", exc)
            raise ServiceError(f"CodeMender execution service unavailable: {self._init_error}") from exc

    def set_service(self, service: CodeMenderService) -> None:
        """Allow injecting test service / fakes."""
        self._service = service


runner_manager = RunnerServiceWrapper()
