"""Tests for OIDC-related config fields."""

from sleuthgraph.config import Settings


def test_oidc_scopes_default(monkeypatch):
    for k in (
        "DATABASE_URL",
        "REDIS_URL",
        "S3_ENDPOINT",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "SECRET_KEY",
    ):
        monkeypatch.setenv(k, "x" * 40)
    s = Settings()
    assert s.oidc_scopes == ["openid", "email", "profile"]


def test_oidc_redirect_url_defaults_to_none(monkeypatch):
    for k in (
        "DATABASE_URL",
        "REDIS_URL",
        "S3_ENDPOINT",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "SECRET_KEY",
    ):
        monkeypatch.setenv(k, "x" * 40)
    s = Settings()
    assert s.oidc_redirect_url is None


def test_oidc_scopes_env_csv(monkeypatch):
    for k in (
        "DATABASE_URL",
        "REDIS_URL",
        "S3_ENDPOINT",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "SECRET_KEY",
    ):
        monkeypatch.setenv(k, "x" * 40)
    monkeypatch.setenv("OIDC_SCOPES", "openid,email")
    s = Settings()
    assert s.oidc_scopes == ["openid", "email"]
