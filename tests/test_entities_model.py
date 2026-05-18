"""Entity model shape + EntityType enum."""

# Import related models to ensure metadata is registered
from sleuthgraph.auth.models import User  # noqa: F401
from sleuthgraph.cases.models import Case  # noqa: F401
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType


def test_entity_type_has_8_members():
    assert len(list(EntityType)) == 8


def test_entity_type_values():
    expected = {
        "PERSON",
        "ORGANIZATION",
        "DOMAIN",
        "IP_ADDRESS",
        "EMAIL",
        "PHONE",
        "URL",
        "CRYPTO_ADDRESS",
    }
    assert {e.value for e in EntityType} == expected


def test_entity_table_name():
    assert Entity.__tablename__ == "entities"


def test_entity_columns():
    cols = {c.name for c in Entity.__table__.columns}
    required = {
        "id",
        "case_id",
        "type",
        "label",
        "attrs",
        "confidence",
        "created_by",
        "created_at",
        "updated_at",
        "deleted_at",
    }
    assert required <= cols, f"missing: {required - cols}"


def test_entity_case_id_fk_cascade():
    col = Entity.__table__.c.case_id
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "cases"
    assert fks[0].ondelete == "CASCADE"
    assert col.nullable is False


def test_entity_created_by_fk_set_null():
    col = Entity.__table__.c.created_by
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "users"
    assert fks[0].ondelete == "SET NULL"
    assert col.nullable is True


def test_entity_confidence_default():
    col = Entity.__table__.c.confidence
    # default is 1.0 at Python or server level
    assert col.default is not None or col.server_default is not None
