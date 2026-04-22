"""Tests for OIDC-related config fields."""

import pytest
from pydantic import ValidationError

from sleuthgraph.config import Settings


def _set_required(monkeypatch):
    for k in (
        "DATABASE_URL",
        "REDIS_URL",
        "S3_ENDPOINT",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "SECRET_KEY",
    ):
        monkeypatch.setenv(k, "x" * 40)


def test_oidc_issuer_without_redirect_url_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.delenv("OIDC_REDIRECT_URL", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "OIDC_REDIRECT_URL" in str(exc_info.value)


def test_oidc_issuer_with_redirect_url_ok(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    monkeypatch.setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/oidc/callback")
    s = Settings()
    assert s.oidc_redirect_url == "https://app.example.com/auth/oidc/callback"


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
