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
    gcp_region: str = Field(
        default=os.getenv("GCP_REGION", "us-central1"),
        description="GCP region for Cloud Run Job dispatch and transit storage."
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
    bq_location: str = Field(
        default=os.getenv("BQ_LOCATION", "US"),
        description="BigQuery dataset location."
    )

    # Cloud Run Job & GCS Transit Runner Configuration
    cm_runner_job_name: str = Field(
        default=os.getenv("CM_RUNNER_JOB_NAME", "codemender-runner"),
        description="Name of the sandboxed cm-runner Cloud Run Job to execute for find/verify/fix."
    )
    cm_reports_bucket: Optional[str] = Field(
        default=os.getenv("CM_REPORTS_BUCKET"),
        description="GCS transit bucket for code snapshots, manifests, and receipts."
    )
    cm_work_dir: str = Field(
        default=os.getenv("CM_WORK_DIR", "/tmp/cm-mcp"),
        description="Local scratch directory for git clones and tarballs."
    )
    cm_default_patch_mode: str = Field(
        default=os.getenv("CM_DEFAULT_PATCH_MODE", "pr"),
        description="Default patch mode for cm_fix ('pr', 'branch', or 'none')."
    )
    cm_poll_interval_seconds: int = Field(
        default=int(os.getenv("CM_POLL_INTERVAL_SECONDS", "20")),
        description="Polling interval in seconds for job completion."
    )
    cm_job_watch_timeout_seconds: int = Field(
        default=int(os.getenv("CM_JOB_WATCH_TIMEOUT_SECONDS", "14400")),
        description="Max seconds to watch a running job (default: 4 hours)."
    )

    # GitHub integration
    github_token: Optional[str] = Field(
        default=os.getenv("GITHUB_TOKEN"),
        description="GitHub token used to clone repos, push fix branches, and open pull requests."
    )
    github_api_url: str = Field(
        default=os.getenv("GITHUB_API_URL", "https://api.github.com"),
        description="GitHub REST API base URL."
    )
    git_author_name: str = Field(
        default=os.getenv("GIT_AUTHOR_NAME", "CodeMender Bot"),
        description="Git author name for patch commits."
    )
    git_author_email: str = Field(
        default=os.getenv("GIT_AUTHOR_EMAIL", "codemender-bot@users.noreply.github.com"),
        description="Git author email for patch commits."
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

    # Server Configuration
    host: str = Field(default="0.0.0.0", description="Host address to bind.")
    port: int = Field(
        default=int(os.getenv("PORT", "8080")),
        description="Port for Cloud Run (Cloud Run sets the PORT env var)."
    )
    
    # Query limits
    default_query_limit: int = Field(default=25, description="Default row limit for queries.")
    max_query_limit: int = Field(default=200, description="Max row limit for queries.")


# Global settings singleton
settings = Settings()
