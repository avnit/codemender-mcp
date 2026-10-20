import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for the Code Mender MCP Server.
    
    Reads from environment variables with sensible defaults for GCP Cloud Run.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Google Cloud Project Configuration
    gcp_project_id: Optional[str] = Field(
        default=os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT_ID"),
        description="GCP Project ID. Defaults to GOOGLE_CLOUD_PROJECT env var or ADC."
    )

    # BigQuery Configuration for Code Mender findings
    bq_dataset: str = Field(
        default=os.getenv("BQ_DATASET", "codemender"),
        description="BigQuery dataset containing Code Mender findings."
    )
    bq_table: str = Field(
        default=os.getenv("BQ_TABLE", "findings"),
        description="BigQuery table containing Code Mender findings."
    )

    # Cloud Logging Configuration
    log_name_filter: Optional[str] = Field(
        default=os.getenv("LOG_NAME_FILTER", "codemender"),
        description="Log name filter or prefix for Code Mender logs."
    )

    # Wiz Configuration (service account with read:issues scope)
    wiz_client_id: Optional[str] = Field(
        default=os.getenv("WIZ_CLIENT_ID"),
        description="Wiz service account client ID."
    )
    wiz_client_secret: Optional[str] = Field(
        default=os.getenv("WIZ_CLIENT_SECRET"),
        description="Wiz service account client secret."
    )
    wiz_api_endpoint: Optional[str] = Field(
        default=os.getenv("WIZ_API_ENDPOINT"),
        description="Wiz GraphQL endpoint for your tenant, e.g. https://api.us17.app.wiz.io/graphql."
    )
    wiz_auth_url: str = Field(
        default=os.getenv("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token"),
        description="Wiz OAuth token URL."
    )
    wiz_audience: str = Field(
        default=os.getenv("WIZ_AUDIENCE", "wiz-api"),
        description="Wiz OAuth audience."
    )

    # Region (used as the default region for the sandbox Cloud Run Job)
    region: str = Field(
        default=os.getenv("REGION", "us-central1"),
        description="Default GCP region."
    )

    # Security lab dataset (written by the log ingestion service)
    security_dataset: str = Field(
        default=os.getenv("SECURITY_DATASET", "security_lab"),
        description="BigQuery dataset with security_events, sandbox_runs and code_to_cloud_map."
    )
    security_events_table: str = Field(
        default=os.getenv("SECURITY_EVENTS_TABLE", "security_events"),
        description="Normalized security events table."
    )
    sandbox_runs_table: str = Field(
        default=os.getenv("SANDBOX_RUNS_TABLE", "sandbox_runs"),
        description="Sandbox validation results table."
    )
    code_to_cloud_table: str = Field(
        default=os.getenv("CODE_TO_CLOUD_TABLE", "code_to_cloud_map"),
        description="Resource-to-repository mapping table (fallback for trace_code_to_cloud)."
    )

    # Security Command Center continuous export
    scc_dataset: str = Field(
        default=os.getenv("SCC_DATASET", "scc_export"),
        description="BigQuery dataset for the SCC findings export."
    )
    scc_table: str = Field(
        default=os.getenv("SCC_TABLE", "findings"),
        description="BigQuery table for the SCC findings export."
    )

    # Log sink destination for Model Armor and VPC Service Controls logs
    security_logs_dataset: str = Field(
        default=os.getenv("SECURITY_LOGS_DATASET", "security_logs"),
        description="BigQuery dataset that receives the Model Armor and VPC SC log sinks."
    )
    model_armor_table: str = Field(
        default=os.getenv("MODEL_ARMOR_TABLE", "modelarmor_googleapis_com_sanitize_operations"),
        description="Model Armor sanitize operations log table."
    )
    vpcsc_table: str = Field(
        default=os.getenv("VPCSC_TABLE", "cloudaudit_googleapis_com_policy"),
        description="Cloud Audit policy (VPC SC) log table."
    )

    # Sandbox Cloud Run Job
    sandbox_job_name: str = Field(
        default=os.getenv("SANDBOX_JOB_NAME", "codemender-sandbox"),
        description="Cloud Run Job that runs sandbox validations."
    )
    sandbox_region: Optional[str] = Field(
        default=os.getenv("SANDBOX_REGION") or None,
        description="Region of the sandbox job. Defaults to REGION."
    )
    sandbox_bucket: Optional[str] = Field(
        default=os.getenv("SANDBOX_BUCKET") or None,
        description="Sandbox inputs bucket. Defaults to <GCP_PROJECT_ID>-sandbox-inputs."
    )

    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Host address to bind.")
    port: int = Field(
        default=int(os.getenv("PORT", "8080")),
        description="Port for Cloud Run (Cloud Run sets the PORT env var)."
    )
    
    # Query limits
    default_query_limit: int = Field(default=25, description="Default row limit for queries.")
    max_query_limit: int = Field(default=200, description="Max row limit for queries.")
    max_lookback_days: int = Field(default=90, description="Max lookback window (days) for log/event queries.")

    @property
    def effective_sandbox_region(self) -> str:
        return self.sandbox_region or self.region

    @property
    def effective_sandbox_bucket(self) -> Optional[str]:
        if self.sandbox_bucket:
            return self.sandbox_bucket
        if self.gcp_project_id:
            return f"{self.gcp_project_id}-sandbox-inputs"
        return None


# Global settings singleton
settings = Settings()
