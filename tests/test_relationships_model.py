"""Relationship model + RelationshipType enum shape tests."""

# Import related models to ensure metadata is registered
from sleuthgraph.auth.models import User  # noqa: F401
from sleuthgraph.cases.models import Case  # noqa: F401
from sleuthgraph.entities.models import Entity  # noqa: F401
from sleuthgraph.relationships.models import Relationship
from sleuthgraph.relationships.types import RelationshipType


def test_relationship_type_has_9_members():
    assert len(list(RelationshipType)) == 9


def test_relationship_type_values():
    expected = {
        "OWNS",
        "EMPLOYED_BY",
        "REGISTERED_BY",
        "HOSTED_ON",
        "RESOLVES_TO",
        "ASSOCIATED_WITH",
        "COMMUNICATED_WITH",
        "MENTIONS",
        "SUBDOMAIN_OF",
    }
    assert {rt.value for rt in RelationshipType} == expected


def test_relationship_tablename():
    assert Relationship.__tablename__ == "relationships"


def test_relationship_columns():
    cols = {c.name for c in Relationship.__table__.columns}
    required = {
        "id",
        "case_id",
        "src_entity_id",
        "dst_entity_id",
        "rel_type",
        "confidence",
        "source_plugin",
        "attrs",
        "created_by",
        "created_at",
        "deleted_at",
    }
    assert required <= cols, f"missing: {required - cols}"


def test_relationship_no_updated_at():
    cols = {c.name for c in Relationship.__table__.columns}
    assert "updated_at" not in cols, "Relationships are immutable after create"


def test_src_and_dst_fk_cascade():
    for name in ("src_entity_id", "dst_entity_id"):
        col = Relationship.__table__.c[name]
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].column.table.name == "entities"
        assert fks[0].ondelete == "CASCADE"
        assert col.nullable is False


def test_case_id_fk_cascade():
    col = Relationship.__table__.c.case_id
    fks = list(col.foreign_keys)
    assert fks[0].column.table.name == "cases"
    assert fks[0].ondelete == "CASCADE"


def test_created_by_fk_set_null():
    col = Relationship.__table__.c.created_by
    fks = list(col.foreign_keys)
    assert fks[0].column.table.name == "users"
    assert fks[0].ondelete == "SET NULL"
    assert col.nullable is True
