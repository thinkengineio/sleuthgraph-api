"""Entity schema tests: types, confidence bounds, label length."""

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sleuthgraph.entities.schemas import EntityCreate, EntityRead, EntityUpdate
from sleuthgraph.entities.types import EntityType


def test_create_accepts_all_entity_types():
    for et in EntityType:
        e = EntityCreate(type=et, label=f"example-{et.value}")
        assert e.type == et


def test_create_rejects_invalid_type():
    with pytest.raises(ValidationError):
        EntityCreate(type="GHOST", label="x")


def test_create_rejects_empty_label():
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.PERSON, label="")


def test_create_rejects_overlong_label():
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.PERSON, label="x" * 600)


def test_create_default_attrs_and_confidence():
    e = EntityCreate(type=EntityType.DOMAIN, label="example.com")
    assert e.attrs == {}
    assert e.confidence == 1.0


def test_create_confidence_bounds():
    EntityCreate(type=EntityType.DOMAIN, label="x", confidence=0.0)
    EntityCreate(type=EntityType.DOMAIN, label="x", confidence=1.0)
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", confidence=-0.01)
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", confidence=1.01)


def test_create_accepts_attrs_dict():
    e = EntityCreate(type=EntityType.DOMAIN, label="example.com",
                     attrs={"registrar": "Namecheap"})
    assert e.attrs == {"registrar": "Namecheap"}


def test_update_all_fields_optional():
    u = EntityUpdate()
    assert u.label is None
    assert u.attrs is None
    assert u.confidence is None


def test_update_partial():
    u = EntityUpdate(label="renamed")
    assert u.label == "renamed"
    assert u.confidence is None


def test_update_confidence_bounds():
    with pytest.raises(ValidationError):
        EntityUpdate(confidence=1.5)


def test_update_rejects_empty_label():
    with pytest.raises(ValidationError):
        EntityUpdate(label="")


def test_read_shape():
    now = datetime.now(timezone.utc)
    er = EntityRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.PERSON,
        label="Alice",
        attrs={"age": 30},
        confidence=0.9,
        created_by=uuid.uuid4(),
        created_at=now,
        updated_at=now,
    )
    assert er.type == EntityType.PERSON
    assert er.confidence == 0.9


def test_read_allows_null_created_by():
    now = datetime.now(timezone.utc)
    er = EntityRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.PERSON,
        label="Alice",
        attrs={},
        confidence=1.0,
        created_by=None,
        created_at=now,
        updated_at=now,
    )
    assert er.created_by is None
