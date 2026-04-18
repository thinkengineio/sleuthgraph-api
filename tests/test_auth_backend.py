"""Tests for cookie transport + JWT strategy auth backend."""

from fastapi_users.authentication import JWTStrategy


def test_cookie_transport_uses_settings():
    from sleuthgraph.auth.backend import cookie_transport
    from sleuthgraph.config import get_settings

    s = get_settings()
    assert cookie_transport.cookie_name == s.auth_cookie_name
    assert cookie_transport.cookie_max_age == s.auth_session_lifetime_seconds
    # cookie_secure / httponly / samesite are private attrs on CookieTransport;
    # we don't assert them directly.


def test_auth_backend_name_and_transport():
    from sleuthgraph.auth.backend import auth_backend, cookie_transport

    assert auth_backend.name == "cookie-jwt"
    assert auth_backend.transport is cookie_transport


def test_get_strategy_returns_jwt_strategy_with_secret():
    from sleuthgraph.auth.backend import auth_backend
    from sleuthgraph.config import get_settings

    strategy = auth_backend.get_strategy()
    assert isinstance(strategy, JWTStrategy)
    assert strategy.secret == get_settings().secret_key
    assert strategy.lifetime_seconds == get_settings().auth_session_lifetime_seconds
