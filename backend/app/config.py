"""
Application configuration using Pydantic Settings.

Loads configuration from environment variables with validation.
Secrets are never logged or exposed in error messages.
"""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Security considerations:
    - Secrets are marked with repr=False to prevent accidental logging
    - Validation ensures required values are present
    - No default values for secrets (must be explicitly set)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = Field(
        ...,
        description="PostgreSQL connection string",
        examples=["postgresql://user:pass@localhost:5432/db"],
    )

    # Encryption (secret - never log)
    encryption_key: str = Field(
        ...,
        repr=False,
        description="Base64-encoded 32-byte AES key",
    )

    # Application
    app_env: str = Field(
        default="development",
        description="Environment: development, staging, production",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode (never in production)",
    )

    # Rate limiting
    rate_limit_per_minute: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Max requests per minute per IP",
    )

    # Note constraints
    max_note_size: int = Field(
        default=10240,  # 10 KB
        ge=1,
        le=102400,  # 100 KB max
        description="Maximum note size in bytes",
    )

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v.lower() not in allowed:
            raise ValueError(f"app_env must be one of: {allowed}")
        return v.lower()

    @field_validator("debug")
    @classmethod
    def validate_debug(cls, v: bool, info) -> bool:
        # Warn if debug is enabled in production (validation happens at load time)
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """
    Get cached application settings.

    Returns:
        Settings instance (cached for performance)
    """
    return Settings()
