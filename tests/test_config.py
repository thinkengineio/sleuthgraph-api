"""Tests for src/sleuthgraph/config.py."""

import os

from sleuthgraph.config import Settings


def test_settings_loads_defaults(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://test/test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "test")
    monkeypatch.setenv("S3_SECRET_KEY", "test")
    monkeypatch.setenv("SECRET_KEY", "a" * 32)

    s = Settings()
    assert s.database_url.startswith("postgresql+asyncpg://")
    assert s.s3_bucket == "evidence"  # default
    assert s.cors_origins == ["http://localhost:3000"]  # default list


def test_settings_parses_cors_csv(monkeypatch):
    for k, v in [
        ("DATABASE_URL", "postgresql+asyncpg://test/test"),
        ("REDIS_URL", "redis://localhost:6379/0"),
        ("S3_ENDPOINT", "http://minio:9000"),
        ("S3_ACCESS_KEY", "x"),
        ("S3_SECRET_KEY", "x"),
        ("SECRET_KEY", "a" * 32),
        ("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001"),
    ]:
        monkeypatch.setenv(k, v)

    s = Settings()
    assert s.cors_origins == ["http://localhost:3000", "http://localhost:3001"]
