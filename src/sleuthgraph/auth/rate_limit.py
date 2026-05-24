"""Rate limiters for auth endpoints.

Two independent layers guard the auth surface:

* an IP-keyed slowapi ``Limiter`` enforced on route handlers via
  ``@ip_limiter.limit(...)`` decorators; and
* body-keyed ``limits`` strategies applied inside handlers after FastAPI
  has parsed the request body (the body-derived key isn't available to
  slowapi's ``key_func`` because that callback runs before body parsing).

Storage defaults to in-memory. ``REDIS_URL`` is honored so multi-worker
deployments share counters across processes -- redis is already a hard
dependency, so this isn't gating production on a new package.

The ``reset_limiters`` helper exists so tests can wipe counters between
runs; otherwise the module-level singleton would leak state.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress

from fastapi import Request
from limits import parse
from limits.storage import MemoryStorage, RedisStorage, Storage
from limits.strategies import MovingWindowRateLimiter
from slowapi import Limiter

from sleuthgraph.config import get_settings


def get_client_ip(request: Request) -> str:
    """Resolve the source IP for per-IP rate limiting.

    Behavior depends on ``trust_cloudflare_edge``:

    * **True** (hosted CF-Tunnel deployment): prefer ``CF-Connecting-IP``
      because Cloudflare sets it from the TCP source it observed, after
      stripping any client-supplied value. Fall back to the **rightmost**
      ``X-Forwarded-For`` entry, then ``request.client.host`` as a last
      resort. We use the rightmost XFF entry (not the leftmost) because
      the rightmost is what the immediately-upstream proxy observed; the
      leftmost is whatever the original client put there and is fully
      spoofable.

    * **False** (direct-exposure / OSS self-host without CF in front):
      use ``request.client.host`` only. ``CF-Connecting-IP`` and
      ``X-Forwarded-For`` are ignored because an attacker reaching the
      API directly can set them to anything and would bypass per-IP
      buckets.

    Falls back to the literal string ``"unknown"`` if no source can be
    resolved -- this is a single shared bucket, which is conservative
    (rate-limits-everyone) rather than permissive.
    """
    settings = get_settings()
    if settings.trust_cloudflare_edge:
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # Use the rightmost entry: that's the IP the immediately-
            # upstream proxy observed for this connection. The leftmost
            # entry is unauthenticated client-supplied data.
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-1]
    if request.client is not None:
        return request.client.host
    return "unknown"


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
    key_func=get_client_ip,
    storage_uri=_build_storage_uri(),
    # X-RateLimit-* headers would require us to thread a Response object
    # through every rate-limited handler -- some return None (e.g. 202),
    # which trips slowapi's header-injection path. Disable to keep the
    # handlers simple and consistent.
    headers_enabled=False,
)

# Separate strategy + storage for body-keyed limits (email, username,
# reset-password token). We can't use slowapi for these because the keys
# live in the request body and slowapi's key_func runs before body
# parsing.
_body_storage: Storage = _build_storage()
_body_strategy = MovingWindowRateLimiter(_body_storage)


def email_rate_limit_hit(email: str) -> bool:
    """Record an attempt against ``email`` and report whether it's allowed.

    Returns True when the attempt is within the configured cap, False once
    the cap is exhausted. The key is lowercased so casing variants share
    one bucket.
    """
    limit = parse(get_settings().auth_forgot_password_email_rate)
    return _body_strategy.hit(limit, "forgot:" + email.lower())


def username_rate_limit_hit(username: str) -> bool:
    """Record a login attempt against ``username`` and report whether allowed.

    Keyed on the username (lowercased) so credential-stuffing one account
    from many IPs still trips a 429.
    """
    limit = parse(get_settings().auth_login_username_rate)
    return _body_strategy.hit(limit, "login:" + username.lower())


def reset_token_rate_limit_hit(token: str) -> bool:
    """Record a reset attempt for ``token`` and report whether allowed.

    The token value is hashed before keying so storage doesn't hold the
    raw token in the rate-limit bucket name. (Defense in depth -- the
    bucket key shouldn't be a credential.)
    """
    limit = parse(get_settings().auth_reset_password_token_rate)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return _body_strategy.hit(limit, "reset:" + digest)


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
        _body_storage.reset()
