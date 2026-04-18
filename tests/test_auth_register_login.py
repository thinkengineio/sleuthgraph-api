"""End-to-end: register -> login -> /users/me -> logout against ASGI app."""

from importlib import reload

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.db import Base, get_session


@pytest.fixture
async def signup_client(monkeypatch, test_engine):
    """Variant of ``client`` that has AUTH_ALLOW_SIGNUP=true when the app is constructed."""
    monkeypatch.setenv("AUTH_ALLOW_SIGNUP", "true")

    # Force a fresh app so create_app() picks up the env change
    import sleuthgraph.main as main_module
    reload(main_module)
    app = main_module.app

    # Disable Secure flag on the cookie transport so httpx over http://test
    # actually sends the session cookie back on subsequent requests.
    from sleuthgraph.auth.backend import cookie_transport
    cookie_transport.cookie_secure = False

    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_session():
        async with TestSession() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_session] = override_get_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    # Restore the original value so other tests are not affected
    cookie_transport.cookie_secure = True


@pytest.mark.asyncio
async def test_register_login_me_logout(signup_client: AsyncClient):
    # Register
    r = await signup_client.post(
        "/auth/register",
        json={"email": "alice@example.com", "password": "hunter222", "name": "Alice"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["name"] == "Alice"

    # Login (form-encoded, OAuth2 password flow)
    r = await signup_client.post(
        "/auth/login",
        data={"username": "alice@example.com", "password": "hunter222"},
    )
    assert r.status_code in (200, 204), r.text

    # /users/me — should be authenticated via cookie
    r = await signup_client.get("/users/me")
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["email"] == "alice@example.com"
    assert me["name"] == "Alice"

    # Logout
    r = await signup_client.post("/auth/logout")
    assert r.status_code in (200, 204), r.text

    # After logout, /users/me is 401
    r = await signup_client.get("/users/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_with_wrong_password_rejected(signup_client: AsyncClient):
    # Register first
    r = await signup_client.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": "correctpassword", "name": "Bob"},
    )
    assert r.status_code == 201

    # Wrong password
    r = await signup_client.post(
        "/auth/login",
        data={"username": "bob@example.com", "password": "wrongpassword"},
    )
    assert r.status_code == 400

    # /users/me is 401
    r = await signup_client.get("/users/me")
    assert r.status_code == 401
