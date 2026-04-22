"""arq WorkerSettings configuration tests."""


def test_worker_settings_exposes_functions():
    from sleuthgraph.queue.arq_settings import WorkerSettings

    assert len(WorkerSettings.functions) >= 1
    names = {f.__name__ for f in WorkerSettings.functions}
    assert "run_plugin_task" in names


def test_worker_settings_uses_configured_redis(monkeypatch):
    monkeypatch.setenv("ARQ_REDIS_URL", "redis://example:6379/3")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 40)
    monkeypatch.delenv("OIDC_ISSUER", raising=False)

    # Clear caches so new env is picked up
    from sleuthgraph.config import get_settings

    get_settings.cache_clear()

    # Import fresh
    import importlib

    import sleuthgraph.queue.arq_settings as mod

    importlib.reload(mod)

    assert mod.WorkerSettings.redis_settings.host == "example"
    assert mod.WorkerSettings.redis_settings.database == 3


def test_effective_arq_redis_url_falls_back_to_redis_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/7")
    monkeypatch.setenv("S3_ENDPOINT", "http://minio:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "x")
    monkeypatch.setenv("S3_SECRET_KEY", "x")
    monkeypatch.setenv("SECRET_KEY", "a" * 40)
    monkeypatch.delenv("ARQ_REDIS_URL", raising=False)
    monkeypatch.delenv("OIDC_ISSUER", raising=False)

    from sleuthgraph.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    assert settings.effective_arq_redis_url == "redis://localhost:6379/7"
