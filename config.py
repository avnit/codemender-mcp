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
