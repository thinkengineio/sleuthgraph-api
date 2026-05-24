"""Rate limiters for auth endpoints.

Two independent limiters guard /auth/forgot-password:

* an IP-keyed slowapi ``Limiter`` enforced on the route handler; and
* an email-keyed ``limits`` strategy applied inside the handler after the
  request body has been parsed (the email isn't available to slowapi's
  ``key_func`` because that runs before FastAPI reads the body).

Storage defaults to in-memory. ``REDIS_URL`` is honored so multi-worker
deployments share counters across processes -- redis is already a hard
dependency, so this isn't gating production on a new package.

The ``reset_limiter`` helper exists so tests can wipe counters between
runs; otherwise the module-level singleton would leak state.
"""

from __future__ import annotations

from contextlib import suppress

from limits import parse
from limits.storage import MemoryStorage, RedisStorage, Storage
from limits.strategies import MovingWindowRateLimiter
from slowapi import Limiter
from slowapi.util import get_remote_address

from sleuthgraph.config import get_settings


def _build_storage_uri() -> str:
    """Pick a storage URI for slowapi / limits.

    Order of precedence:

    1. ``AUTH_RATE_LIMIT_STORAGE`` if set explicitly (used by tests to
       force ``memory://``);
    2. ``REDIS_URL`` -- reused so the counters are shared across uvicorn
       workers in production;
    3. ``memory://`` as a last-resort fallback.
    """
    settings = get_settings()
    override = settings.auth_rate_limit_storage
    if override:
        return override
    redis_url = settings.redis_url
    if redis_url and redis_url.startswith(("redis://", "rediss://")):
        return redis_url
    return "memory://"


def _build_storage() -> Storage:
    uri = _build_storage_uri()
    if uri.startswith(("redis://", "rediss://")):
        return RedisStorage(uri)
    return MemoryStorage()


# IP-keyed limiter for slowapi @limiter.limit() decorators. We don't use
# slowapi's global middleware mode -- only the routes that opt in via the
# decorator are rate-limited, which keeps the blast radius small.
ip_limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_build_storage_uri(),
    # X-RateLimit-* headers would require us to thread a Response object
    # through the handler -- the route returns None for 202, so slowapi
    # has nothing to inject into. Disable to keep the handler simple.
    headers_enabled=False,
)

# Separate strategy + storage for the email-keyed limit. We can't use
# slowapi here because the email lives in the request body and slowapi's
# key_func runs before body parsing.
_email_storage: Storage = _build_storage()
_email_strategy = MovingWindowRateLimiter(_email_storage)


def email_rate_limit_hit(email: str) -> bool:
    """Record an attempt against ``email`` and report whether it's allowed.

    Returns True when the attempt is within the configured cap, False once
    the cap is exhausted.  The key is lowercased so casing variants share
    one bucket.
    """
    limit = parse(get_settings().auth_forgot_password_email_rate)
    return _email_strategy.hit(limit, email.lower())


def reset_limiters() -> None:
    """Drop all counters. Used by test fixtures to isolate runs.

    Best-effort: ``reset`` raises on storage backends that don't support
    it (notably redis, where wiping arbitrary keys would be unsafe), so
    we swallow the exception -- tests use the memory backend where this
    works.
    """
    with suppress(Exception):  # pragma: no cover - defensive
        ip_limiter.reset()
    with suppress(Exception):  # pragma: no cover - defensive
        _email_storage.reset()
