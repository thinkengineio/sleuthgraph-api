"""Tests for auth-related settings on Settings."""

from sleuthgraph.config import Settings


def test_auth_settings_defaults(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    s = Settings()
    assert s.auth_cookie_name == "sleuthgraph_session"
    assert s.auth_cookie_secure is True
    assert s.auth_session_lifetime_seconds == 60 * 60 * 24 * 7
    assert s.auth_allow_signup is False
    assert s.auth_admin_email is None
    assert s.auth_admin_password is None
    assert s.oidc_issuer is None
    assert s.oidc_client_id is None
    assert s.oidc_client_secret is None


def test_auth_settings_env_overrides(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)
    monkeypatch.setenv("AUTH_COOKIE_NAME", "custom_cookie")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("AUTH_ALLOW_SIGNUP", "true")
    monkeypatch.setenv("AUTH_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("AUTH_ADMIN_PASSWORD", "secret")
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")
    s = Settings()
    assert s.auth_cookie_name == "custom_cookie"
    assert s.auth_cookie_secure is False
    assert s.auth_allow_signup is True
    assert s.auth_admin_email == "admin@example.com"
    assert s.auth_admin_password == "secret"
    assert s.oidc_issuer == "https://id.example.com"
    assert s.oidc_client_id == "cid"
    assert s.oidc_client_secret == "csec"
