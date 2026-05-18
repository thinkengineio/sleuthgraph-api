"""Tests for cookie transport + database strategy auth backend."""


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

    assert auth_backend.name == "cookie-db"
    assert auth_backend.transport is cookie_transport
