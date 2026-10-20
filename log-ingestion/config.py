"""Runtime configuration for security-log-ingestion, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

SERVICE_NAME = "security-log-ingestion"


def _get(env: Mapping[str, str], name: str, default: str = "") -> str:
    value = env.get(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


@dataclass(frozen=True)
class Settings:
    project_id: str = ""
    security_dataset: str = "security_lab"
    security_events_table: str = "security_events"
    sandbox_runs_table: str = "sandbox_runs"
    ingestion_errors_table: str = "ingestion_errors"
    bq_dataset: str = "codemender"
    bq_table: str = "findings"
    # When set, POST /pubsub/push requires a Google-signed OIDC token with this audience.
    push_audience: str = ""
    # Optional extra check: the token's email claim must equal this service account.
    push_service_account: str = ""
    port: int = 8080

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        port_raw = _get(env, "PORT", "8080")
        try:
            port = int(port_raw)
        except ValueError:
            port = 8080
        return cls(
            project_id=_get(env, "GCP_PROJECT_ID"),
            security_dataset=_get(env, "SECURITY_DATASET", "security_lab"),
            security_events_table=_get(env, "SECURITY_EVENTS_TABLE", "security_events"),
            sandbox_runs_table=_get(env, "SANDBOX_RUNS_TABLE", "sandbox_runs"),
            ingestion_errors_table=_get(env, "INGESTION_ERRORS_TABLE", "ingestion_errors"),
            bq_dataset=_get(env, "BQ_DATASET", "codemender"),
            bq_table=_get(env, "BQ_TABLE", "findings"),
            push_audience=_get(env, "PUSH_AUDIENCE"),
            push_service_account=_get(env, "PUSH_SERVICE_ACCOUNT"),
            port=port,
        )

    def _table_id(self, dataset: str, table: str) -> str:
        # Without a project the BigQuery client uses its default project.
        if self.project_id:
            return f"{self.project_id}.{dataset}.{table}"
        return f"{dataset}.{table}"

    @property
    def security_events_table_id(self) -> str:
        return self._table_id(self.security_dataset, self.security_events_table)

    @property
    def sandbox_runs_table_id(self) -> str:
        return self._table_id(self.security_dataset, self.sandbox_runs_table)

    @property
    def ingestion_errors_table_id(self) -> str:
        return self._table_id(self.security_dataset, self.ingestion_errors_table)

    @property
    def findings_table_id(self) -> str:
        return self._table_id(self.bq_dataset, self.bq_table)
