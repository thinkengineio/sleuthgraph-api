"""Runtime settings loaded from environment variables.

All settings REQUIRED in production (no defaults for secrets) surface
as validation errors at startup, not as surprise failures later.
"""

import json
from functools import lru_cache
from typing import Any

from pydantic import Field, model_validator
from pydantic.fields import FieldInfo
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
    secret_key: str = Field(
        ..., min_length=32, description="Used for JWT signing + credential encryption"
    )

    # Auth
    auth_cookie_name: str = "sleuthgraph_session"
    auth_cookie_secure: bool = True
    auth_session_lifetime_seconds: int = 60 * 60 * 24 * 7
    auth_allow_signup: bool = False
    auth_allow_password_reset: bool = True
    auth_allow_email_verify: bool = False
    auth_frontend_base_url: str = "http://localhost:3000"
    auth_admin_email: str | None = None
    auth_admin_password: str | None = None

    # OIDC (optional)
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    oidc_redirect_url: str | None = Field(
        default=None,
        description="Absolute callback URL override. Leave unset to derive from request.",
    )

    # CORS
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # Evidence uploads
    evidence_max_upload_bytes: int = Field(
        default=50 * 1024 * 1024,
        ge=1,
        description="Max evidence upload size in bytes (default 50 MiB).",
    )

    # AI (optional — only required for Phase 10 features)
    anthropic_api_key: str | None = None

    # Background worker
    arq_redis_url: str | None = Field(
        default=None,
        description="Redis URL for the arq task queue. Defaults to redis_url if unset.",
    )

    # App
    app_name: str = "Sleuthgraph API"
    debug: bool = False

    @property
    def effective_arq_redis_url(self) -> str:
        return self.arq_redis_url or self.redis_url

    @model_validator(mode="after")
    def _require_redirect_url_when_oidc_enabled(self) -> "Settings":
        if self.oidc_issuer and not self.oidc_redirect_url:
            raise ValueError(
                "OIDC_REDIRECT_URL must be set when OIDC_ISSUER is set — see docs/auth-oidc.md"
            )
        return self

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached accessor. Overridden in tests via FastAPI dependency overrides.

    Tests that monkeypatch env must call ``get_settings.cache_clear()`` to
    rebuild the Settings instance.
    """
    return Settings()
