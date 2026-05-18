"""BYOK credential vault: store, retrieve, list, delete, upsert, runner integration."""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.credentials.models import Credential
from sleuthgraph.credentials.repository import (
    delete_credential,
    get_credential,
    list_credentials,
    store_credential,
)
from sleuthgraph.crypto import _reset_caches
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import OSINTPlugin, QueryResult
from sleuthgraph.plugins.registry import PluginRegistry
from sleuthgraph.plugins.runner import (
    PluginCredentialMissingError,
    PluginRunner,
)


# ---------- fixtures ----------


@pytest.fixture(autouse=True)
def _clear_crypto_caches():
    """Ensure crypto subkey caches reflect the test env's SECRET_KEY."""
    _reset_caches()
    yield
    _reset_caches()


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(monkeypatch, request):
    """Stub out AGE calls so SQLite tests pass."""
    if "postgres_age_session" in request.fixturenames:
        return
    async def _noop(*a, **k):
        return None
    from sleuthgraph.entities import repository as ent_repo
    from sleuthgraph.relationships import repository as rel_repo
    monkeypatch.setattr(ent_repo, "upsert_vertex", _noop)
    monkeypatch.setattr(ent_repo, "delete_vertex", _noop)
    monkeypatch.setattr(rel_repo, "upsert_edge", _noop)
    monkeypatch.setattr(rel_repo, "delete_edge", _noop)


@pytest.fixture
async def db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def user(db):
    u = User(
        id=uuid.uuid4(),
        email="cred-test@example.com",
        hashed_password="x",
        is_active=True,
        is_superuser=False,
        is_verified=False,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


# ---------- repository tests ----------


@pytest.mark.asyncio
async def test_store_and_retrieve_round_trip(db, user):
    """Store a key, retrieve it; the decrypted value must match the original."""
    original = "test-credential-abc123"
    await store_credential(db, user.id, "virustotal", original)
    await db.commit()

    decrypted = await get_credential(db, user.id, "virustotal")
    assert decrypted == original


@pytest.mark.asyncio
async def test_stored_value_is_encrypted_in_db(db, user):
    """The raw row in the DB must NOT contain the plaintext key."""
    original = "super-secret-api-key-12345"
    await store_credential(db, user.id, "shodan", original)
    await db.commit()

    stmt = select(Credential).where(
        Credential.user_id == user.id,
        Credential.plugin_name == "shodan",
    )
    row = (await db.execute(stmt)).scalar_one()
    assert original not in row.encrypted_key
    # Fernet ciphertext starts with "gAAAAA" (base64url of version byte + timestamp)
    assert row.encrypted_key.startswith("gAAAAA")


@pytest.mark.asyncio
async def test_list_returns_plugin_names_without_keys(db, user):
    """List should expose plugin_name + created_at, never the key."""
    await store_credential(db, user.id, "virustotal", "key-a")
    await store_credential(db, user.id, "shodan", "key-b")
    await db.commit()

    items = await list_credentials(db, user.id)
    names = {c.plugin_name for c in items}
    assert names == {"virustotal", "shodan"}
    # Ensure no key attribute leaks
    for item in items:
        assert not hasattr(item, "api_key")
        assert not hasattr(item, "encrypted_key")
        assert item.created_at is not None


@pytest.mark.asyncio
async def test_delete_removes_credential(db, user):
    """After deletion, get should return None."""
    await store_credential(db, user.id, "hibp", "key-c")
    await db.commit()

    deleted = await delete_credential(db, user.id, "hibp")
    assert deleted is True

    assert await get_credential(db, user.id, "hibp") is None


@pytest.mark.asyncio
async def test_delete_nonexistent_returns_false(db, user):
    """Deleting a key that was never stored returns False."""
    deleted = await delete_credential(db, user.id, "nonexistent")
    assert deleted is False


@pytest.mark.asyncio
async def test_upsert_overwrites_existing(db, user):
    """Storing a second key for the same plugin replaces the first."""
    await store_credential(db, user.id, "virustotal", "first-key")
    await db.commit()

    await store_credential(db, user.id, "virustotal", "second-key")
    await db.commit()

    decrypted = await get_credential(db, user.id, "virustotal")
    assert decrypted == "second-key"

    # Only one row should exist
    stmt = select(Credential).where(
        Credential.user_id == user.id,
        Credential.plugin_name == "virustotal",
    )
    rows = (await db.execute(stmt)).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_get_returns_none_for_missing(db, user):
    """Fetching a credential that was never stored returns None."""
    result = await get_credential(db, user.id, "no-such-plugin")
    assert result is None


# ---------- runner integration tests ----------


class _FakeStorage:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    async def put(self, key, data, content_type="application/octet-stream"):
        self._blobs[key] = data

    async def get(self, key):
        return self._blobs[key]

    async def presign_get(self, key, expires_in=300):
        return f"http://fake/{key}"

    async def exists(self, key):
        return key in self._blobs


class _BYOKFakePlugin(OSINTPlugin):
    """A fake BYOK plugin that records the credentials it received."""

    name = "fake_byok"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = []
    requires_credentials = True
    received_credentials = None

    async def query(self, input_entity, credentials, context):
        _BYOKFakePlugin.received_credentials = credentials
        return QueryResult()


@pytest.fixture
async def case_with_domain(db, user):
    """Create a case and a domain entity for runner tests."""
    case = Case(owner_id=user.id, name="BYOK test", tags=[])
    db.add(case)
    await db.commit()
    await db.refresh(case)

    domain = Entity(
        case_id=case.id,
        type=EntityType.DOMAIN.value,
        label="example.com",
        attrs={},
        confidence=1.0,
        created_by=user.id,
    )
    db.add(domain)
    await db.commit()
    await db.refresh(domain)
    return case, domain


@pytest.mark.asyncio
async def test_runner_injects_credential_when_stored(db, user, case_with_domain):
    """Runner should decrypt the stored key and pass it as credentials dict."""
    case, domain = case_with_domain
    _BYOKFakePlugin.received_credentials = None

    # Store a credential for this plugin
    await store_credential(db, user.id, "fake_byok", "my-api-key-xyz")
    await db.commit()

    storage = _FakeStorage()
    registry = PluginRegistry([_BYOKFakePlugin()])
    runner = PluginRunner(db, storage, registry)

    result = await runner.run(
        "fake_byok", case.id, domain, created_by=user.id,
    )
    assert result.run.status == "succeeded"
    assert _BYOKFakePlugin.received_credentials == {"api_key": "my-api-key-xyz"}


@pytest.mark.asyncio
async def test_runner_raises_when_credential_missing(db, user, case_with_domain):
    """Runner should raise PluginCredentialMissingError if no key is stored,
    and the audit row should be marked as failed with the correct taxonomy."""
    case, domain = case_with_domain

    storage = _FakeStorage()
    registry = PluginRegistry([_BYOKFakePlugin()])
    runner = PluginRunner(db, storage, registry)

    with pytest.raises(PluginCredentialMissingError, match="No API key stored"):
        await runner.run(
            "fake_byok", case.id, domain, created_by=user.id,
        )

    # Verify a failed audit row was written with the credentials_missing taxonomy
    from sqlalchemy import select
    from sleuthgraph.plugins.models import PluginRun

    rows = list(
        (await db.execute(select(PluginRun).where(PluginRun.case_id == case.id))).scalars()
    )
    assert len(rows) == 1
    assert rows[0].status == "failed"
    assert rows[0].error_message.startswith("credentials_missing:")
