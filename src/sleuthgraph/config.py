"""Runtime settings loaded from environment variables.

All settings REQUIRED in production (no defaults for secrets) surface
as validation errors at startup, not as surprise failures later.
"""

import json
from typing import Any

from pydantic.fields import FieldInfo
from pydantic import Field
from pydantic_settings import BaseSettings, EnvSettingsSource, SettingsConfigDict
from pydantic_settings.main import BaseSettings as _BS


class _CsvAwareEnvSource(EnvSettingsSource):
    """EnvSettingsSource that accepts comma-separated strings for list fields.

    pydantic-settings 2.x tries json.loads() on any complex (list/dict) field
    before validators fire.  A bare CSV like ``http://a,http://b`` is not valid
    JSON so it raises.  This subclass falls back to CSV splitting instead.
    """

    def decode_complex_value(self, field_name: str, field: FieldInfo, value: Any) -> Any:
        if isinstance(value, str):
            # Try JSON first (handles ["a","b"] style env values)
            try:
                return json.loads(value)
            except (ValueError, TypeError):
                pass
            # Fall back: treat as comma-separated list of strings
            return [item.strip() for item in value.split(",") if item.strip()]
        return super().decode_complex_value(field_name, field, value)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # Database
    database_url: str = Field(..., description="asyncpg URL")

    # Redis
    redis_url: str = Field(...)

    # Object storage (S3-compatible; MinIO in dev)
    s3_endpoint: str = Field(...)
    s3_access_key: str = Field(...)
    s3_secret_key: str = Field(...)
    s3_bucket: str = Field("evidence")
    s3_region: str = Field("us-east-1")

    # Crypto
    secret_key: str = Field(..., min_length=32, description="Used for JWT signing + credential encryption")

    # CORS
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # AI (optional — only required for Phase 10 features)
    anthropic_api_key: str | None = None

    # App
    app_name: str = "Sleuthgraph API"
    debug: bool = False

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[_BS],
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        # Replace the default EnvSettingsSource with our CSV-aware subclass
        return (
            init_settings,
            _CsvAwareEnvSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )


def get_settings() -> Settings:
    """Cached accessor. Overridden in tests via FastAPI dependency overrides."""
    return Settings()
