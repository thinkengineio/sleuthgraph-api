"""PluginRunner: orchestration + dedup + audit."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import (
    EntityProposal,
    EvidenceProposal,
    OSINTPlugin,
    QueryResult,
    RelationshipProposal,
)
from sleuthgraph.plugins.registry import PluginNotFoundError, PluginRegistry
from sleuthgraph.plugins.runner import PluginExecutionError, PluginRunner, PluginTypeError
from sleuthgraph.relationships.types import RelationshipType


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


class _FakeCrtShPlugin(OSINTPlugin):
    """A minimal plugin that emits 2 subdomains + rels + evidence."""

    name = "fake_crtsh"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN]
    requires_credentials = False

    async def query(self, input_entity, credentials, context):
        return QueryResult(
            entities=[
                EntityProposal(ref="sub-0", type=EntityType.DOMAIN, label="a.example.com"),
                EntityProposal(ref="sub-1", type=EntityType.DOMAIN, label="b.example.com"),
            ],
            relationships=[
                RelationshipProposal(
                    src={"ref": "sub-0"},
                    dst={"input": True},
                    rel_type=RelationshipType.SUBDOMAIN_OF,
                ),
                RelationshipProposal(
                    src={"ref": "sub-1"},
                    dst={"input": True},
                    rel_type=RelationshipType.SUBDOMAIN_OF,
                ),
            ],
            evidence=[
                EvidenceProposal(
                    query=f"fake crt.sh lookup for {input_entity.label}",
                    payload=b'{"fake":"response"}',
                    content_type="application/json",
                    reproducibility_spec={"url": "https://crt.sh/?q=x"},
                ),
            ],
        )


class _FailingPlugin(OSINTPlugin):
    name = "failing"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = []

    async def query(self, input_entity, credentials, context):
        raise RuntimeError("boom")


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(monkeypatch, request):
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
async def sqlite_db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def seeded_case_with_domain(sqlite_db):
    u = User(
        id=uuid.uuid4(),
        email="o@x.com",
        hashed_password="x",
        is_active=True,
        is_superuser=False,
        is_verified=False,
    )
    sqlite_db.add(u)
    await sqlite_db.commit()
    case = Case(owner_id=u.id, name="Plugin test", tags=[])
    sqlite_db.add(case)
    await sqlite_db.commit()
    await sqlite_db.refresh(case)
    domain = Entity(
        case_id=case.id,
        type=EntityType.DOMAIN.value,
        label="example.com",
        attrs={},
        confidence=1.0,
        created_by=u.id,
    )
    sqlite_db.add(domain)
    await sqlite_db.commit()
    await sqlite_db.refresh(domain)
    return u, case, domain


# ---- Registry tests ----


def test_registry_register_and_get():
    reg = PluginRegistry([_FakeCrtShPlugin()])
    p = reg.get("fake_crtsh")
    assert p.name == "fake_crtsh"
    assert "fake_crtsh" in reg


def test_registry_duplicate_name_raises():
    reg = PluginRegistry([_FakeCrtShPlugin()])
    with pytest.raises(ValueError, match="duplicate"):
        reg.register(_FakeCrtShPlugin())


def test_registry_unknown_name_raises():
    reg = PluginRegistry([])
    with pytest.raises(PluginNotFoundError):
        reg.get("no-such-plugin")


# ---- Runner tests ----


@pytest.mark.asyncio
async def test_runner_happy_path(sqlite_db, seeded_case_with_domain):
    user, case, domain = seeded_case_with_domain
    storage = _FakeStorage()
    registry = PluginRegistry([_FakeCrtShPlugin()])
    runner = PluginRunner(sqlite_db, storage, registry)

    result = await runner.run(
        "fake_crtsh",
        case.id,
        domain,
        created_by=user.id,
    )

    # Audit row
    assert result.run.status == "succeeded"
    assert result.run.entities_created_count == 2
    assert result.run.relationships_created_count == 2
    assert result.run.evidence_count == 1
    assert result.run.finished_at is not None

    # Output collections
    assert len(result.entities_created) == 2
    assert {e.label for e in result.entities_created} == {"a.example.com", "b.example.com"}
    assert len(result.relationships_created) == 2
    assert len(result.evidence_created) == 1

    # source_plugin on relationships matches
    assert result.relationships_created[0].source_plugin == "fake_crtsh@0.0.1"


@pytest.mark.asyncio
async def test_runner_dedups_on_second_run(sqlite_db, seeded_case_with_domain):
    user, case, domain = seeded_case_with_domain
    storage = _FakeStorage()
    registry = PluginRegistry([_FakeCrtShPlugin()])
    runner = PluginRunner(sqlite_db, storage, registry)

    await runner.run("fake_crtsh", case.id, domain, created_by=user.id)
    second = await runner.run("fake_crtsh", case.id, domain, created_by=user.id)

    # Second run: entities already exist, so was_created=False for all
    assert second.run.entities_created_count == 0
    assert second.run.relationships_created_count == 0
    # Evidence always appends (append-only ledger)
    assert second.run.evidence_count == 1


@pytest.mark.asyncio
async def test_runner_records_failed_status_on_exception(sqlite_db, seeded_case_with_domain):
    user, case, domain = seeded_case_with_domain
    storage = _FakeStorage()
    registry = PluginRegistry([_FailingPlugin()])
    runner = PluginRunner(sqlite_db, storage, registry)

    with pytest.raises(PluginExecutionError, match="boom"):
        await runner.run("failing", case.id, domain, created_by=user.id)

    # Verify a failed audit row was written with taxonomy label (not raw exception text)
    from sqlalchemy import select

    from sleuthgraph.plugins.models import PluginRun

    q = select(PluginRun).where(PluginRun.case_id == case.id)
    rows = list((await sqlite_db.execute(q)).scalars())
    assert len(rows) == 1
    assert rows[0].status == "failed"
    assert "unknown:RuntimeError" in rows[0].error_message
    assert "boom" not in rows[0].error_message


@pytest.mark.asyncio
async def test_runner_rejects_wrong_entity_type(sqlite_db, seeded_case_with_domain):
    """Plugin accepts DOMAIN but input is PERSON → raise before audit row committed as succeeded."""
    user, case, _domain = seeded_case_with_domain
    # Create a PERSON entity instead
    person = Entity(
        case_id=case.id,
        type=EntityType.PERSON.value,
        label="Alice",
        attrs={},
        confidence=1.0,
        created_by=user.id,
    )
    sqlite_db.add(person)
    await sqlite_db.commit()
    await sqlite_db.refresh(person)

    storage = _FakeStorage()
    registry = PluginRegistry([_FakeCrtShPlugin()])
    runner = PluginRunner(sqlite_db, storage, registry)

    with pytest.raises(PluginTypeError, match="does not accept"):
        await runner.run("fake_crtsh", case.id, person, created_by=user.id)


@pytest.mark.asyncio
async def test_runner_unknown_plugin_raises(sqlite_db, seeded_case_with_domain):
    user, case, domain = seeded_case_with_domain
    storage = _FakeStorage()
    registry = PluginRegistry([])
    runner = PluginRunner(sqlite_db, storage, registry)

    with pytest.raises(PluginNotFoundError):
        await runner.run("no-such-plugin", case.id, domain, created_by=user.id)


@pytest.mark.asyncio
async def test_runner_stores_only_taxonomy_label_on_failure(sqlite_db, seeded_case_with_domain):
    """Raw exception str must NOT appear in PluginRun.error_message."""
    user, case, domain = seeded_case_with_domain
    storage = _FakeStorage()

    class _SecretLeakPlugin(OSINTPlugin):
        name = "secret_leak"
        version = "0.0.1"
        entity_types_accepted = [EntityType.DOMAIN]
        entity_types_produced = []

        async def query(self, input_entity, credentials, context):
            raise RuntimeError("API key abcdef123 leaked in exception")

    registry = PluginRegistry([_SecretLeakPlugin()])
    runner = PluginRunner(sqlite_db, storage, registry)

    with pytest.raises(PluginExecutionError):
        await runner.run("secret_leak", case.id, domain, created_by=user.id)

    from sqlalchemy import select

    from sleuthgraph.plugins.models import PluginRun

    q = select(PluginRun).where(PluginRun.case_id == case.id)
    rows = list((await sqlite_db.execute(q)).scalars())
    assert len(rows) == 1
    msg = rows[0].error_message
    assert "abcdef" not in msg
    assert "API key" not in msg
    # Should contain taxonomy label + exception class name
    assert "unknown:RuntimeError" in msg
