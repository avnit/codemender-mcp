import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for the Wiz Security MCP Server.

    Reads from environment variables with sensible defaults for GCP Cloud Run.
    Never hardcode WIZ_CLIENT_SECRET; inject via Secret Manager in Cloud Run.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Google Cloud Project / Service Metadata
    gcp_project_id: Optional[str] = Field(
        default=os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT_ID"),
        description="GCP Project ID hosting the Cloud Run service."
    )
    region: str = Field(
        default=os.getenv("REGION", "us-central1"),
        description="Default GCP region."
    )
    service_name: str = Field(
        default=os.getenv("SERVICE_NAME", "wiz-mcp-server"),
        description="Cloud Run service name."
    )

    # Wiz Configuration (read-only service account)
    wiz_client_id: Optional[str] = Field(
        default=os.getenv("WIZ_CLIENT_ID"),
        description="Wiz service account client ID."
    )
    wiz_client_secret: Optional[str] = Field(
        default=os.getenv("WIZ_CLIENT_SECRET"),
        description="Wiz service account client secret (injected via Secret Manager)."
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

    # Server Configuration (0.0.0.0 on Cloud Run when K_SERVICE is set; 127.0.0.1 for local dev/testing)
    host: str = Field(
        default=os.getenv("HOST", "0.0.0.0" if os.getenv("K_SERVICE") else "127.0.0.1"),
        description="Host address to bind."
    )
    port: int = Field(
        default=int(os.getenv("PORT", "8080")),
        description="Port for Cloud Run (Cloud Run sets the PORT env var)."
    )

    # Query limits
    default_query_limit: int = Field(default=25, description="Default row limit for queries.")
    max_query_limit: int = Field(default=200, description="Max row limit for queries.")


# Global settings singleton
settings = Settings()
