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


# ---------------------------------------------------------------------------
# attrs key validation (HIGH-1 / map-key injection regression tests)
# ---------------------------------------------------------------------------

def test_attrs_accepts_valid_keys():
    e = EntityCreate(
        type=EntityType.DOMAIN,
        label="example.com",
        attrs={"foo": 1, "bar_baz": "x", "_leading_underscore": 2},
    )
    assert e.attrs["foo"] == 1


def test_attrs_accepts_nested_valid():
    """Four levels of nesting with valid keys is allowed."""
    e = EntityCreate(
        type=EntityType.DOMAIN,
        label="example.com",
        attrs={"a": {"b": {"c": {"d": "leaf"}}}},
    )
    assert e.attrs["a"]["b"]["c"]["d"] == "leaf"


def test_attrs_rejects_non_identifier_key():
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", attrs={"bad key": 1})


def test_attrs_rejects_cypher_injection_key():
    with pytest.raises(ValidationError):
        EntityCreate(
            type=EntityType.DOMAIN,
            label="x",
            attrs={"name SET v.admin = true //": 1},
        )


def test_attrs_rejects_long_key():
    """Key longer than 64 chars should be rejected."""
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", attrs={"a" * 65: 1})


def test_attrs_rejects_empty_key():
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", attrs={"": 1})


def test_attrs_rejects_leading_digit_key():
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", attrs={"1foo": 1})


def test_attrs_rejects_depth_over_4():
    """Nesting 5 levels deep should be rejected."""
    deep = {"a": {"b": {"c": {"d": {"e": "too deep"}}}}}
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", attrs=deep)


def test_attrs_rejects_size_over_64kb():
    """Serialized size > 64 KB should be rejected."""
    # Each entry is ~16 bytes; 5000 entries ≈ 80 KB
    big = {f"key_{i:04d}": "v" * 10 for i in range(5000)}
    with pytest.raises(ValidationError):
        EntityCreate(type=EntityType.DOMAIN, label="x", attrs=big)


def test_update_attrs_rejects_non_identifier_key():
    with pytest.raises(ValidationError):
        EntityUpdate(attrs={"bad key": 1})


def test_update_attrs_accepts_none():
    """EntityUpdate with attrs=None must pass (field is optional)."""
    u = EntityUpdate(attrs=None)
    assert u.attrs is None
