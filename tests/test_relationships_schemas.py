"""Relationship schema tests: types, confidence bounds, source_plugin."""

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sleuthgraph.relationships.schemas import RelationshipCreate, RelationshipRead
from sleuthgraph.relationships.types import RelationshipType


def test_create_accepts_all_rel_types():
    src = uuid.uuid4()
    dst = uuid.uuid4()
    for rt in RelationshipType:
        rc = RelationshipCreate(src_entity_id=src, dst_entity_id=dst, rel_type=rt)
        assert rc.rel_type == rt


def test_create_rejects_invalid_rel_type():
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type="DOES_NOT_EXIST",
        )


def test_create_default_confidence_and_attrs():
    rc = RelationshipCreate(
        src_entity_id=uuid.uuid4(),
        dst_entity_id=uuid.uuid4(),
        rel_type=RelationshipType.OWNS,
    )
    assert rc.confidence == 1.0
    assert rc.attrs == {}
    assert rc.source_plugin is None


def test_create_confidence_bounds():
    src, dst = uuid.uuid4(), uuid.uuid4()
    RelationshipCreate(
        src_entity_id=src, dst_entity_id=dst, rel_type=RelationshipType.OWNS, confidence=0.0
    )
    RelationshipCreate(
        src_entity_id=src, dst_entity_id=dst, rel_type=RelationshipType.OWNS, confidence=1.0
    )
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=src, dst_entity_id=dst, rel_type=RelationshipType.OWNS, confidence=-0.01
        )
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=src, dst_entity_id=dst, rel_type=RelationshipType.OWNS, confidence=1.01
        )


def test_create_source_plugin_optional():
    src, dst = uuid.uuid4(), uuid.uuid4()
    rc = RelationshipCreate(
        src_entity_id=src,
        dst_entity_id=dst,
        rel_type=RelationshipType.MENTIONS,
        source_plugin="my-plugin",
    )
    assert rc.source_plugin == "my-plugin"


def test_create_source_plugin_max_128():
    src, dst = uuid.uuid4(), uuid.uuid4()
    # Exactly 128 chars is fine
    RelationshipCreate(
        src_entity_id=src,
        dst_entity_id=dst,
        rel_type=RelationshipType.MENTIONS,
        source_plugin="x" * 128,
    )
    # 129 chars should be rejected
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=src,
            dst_entity_id=dst,
            rel_type=RelationshipType.MENTIONS,
            source_plugin="x" * 129,
        )


def test_read_shape():
    now = datetime.now(UTC)
    rr = RelationshipRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        src_entity_id=uuid.uuid4(),
        dst_entity_id=uuid.uuid4(),
        rel_type=RelationshipType.RESOLVES_TO,
        confidence=0.8,
        source_plugin="nuclei",
        attrs={"note": "test"},
        created_by=uuid.uuid4(),
        created_at=now,
    )
    assert rr.rel_type == RelationshipType.RESOLVES_TO
    assert rr.source_plugin == "nuclei"


def test_read_allows_null_created_by_and_source_plugin():
    now = datetime.now(UTC)
    rr = RelationshipRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        src_entity_id=uuid.uuid4(),
        dst_entity_id=uuid.uuid4(),
        rel_type=RelationshipType.ASSOCIATED_WITH,
        confidence=1.0,
        source_plugin=None,
        attrs={},
        created_by=None,
        created_at=now,
    )
    assert rr.created_by is None
    assert rr.source_plugin is None


def test_no_update_schema_exists():
    """There must be no RelationshipUpdate class — relationships are immutable."""
    import sleuthgraph.relationships.schemas as s

    assert not hasattr(s, "RelationshipUpdate"), (
        "RelationshipUpdate must not exist; use delete+recreate for edits"
    )


# ---------------------------------------------------------------------------
# attrs key validation (HIGH-1 / map-key injection regression tests)
# ---------------------------------------------------------------------------


def test_attrs_accepts_valid_keys():
    src, dst = uuid.uuid4(), uuid.uuid4()
    rc = RelationshipCreate(
        src_entity_id=src,
        dst_entity_id=dst,
        rel_type=RelationshipType.OWNS,
        attrs={"foo": 1, "bar_baz": "x", "_leading_underscore": 2},
    )
    assert rc.attrs["foo"] == 1


def test_attrs_accepts_nested_valid():
    """Four levels of nesting with valid keys is allowed."""
    src, dst = uuid.uuid4(), uuid.uuid4()
    rc = RelationshipCreate(
        src_entity_id=src,
        dst_entity_id=dst,
        rel_type=RelationshipType.OWNS,
        attrs={"a": {"b": {"c": {"d": "leaf"}}}},
    )
    assert rc.attrs["a"]["b"]["c"]["d"] == "leaf"


def test_attrs_rejects_non_identifier_key():
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs={"bad key": 1},
        )


def test_attrs_rejects_cypher_injection_key():
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs={"name SET v.admin = true //": 1},
        )


def test_attrs_rejects_long_key():
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs={"a" * 65: 1},
        )


def test_attrs_rejects_empty_key():
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs={"": 1},
        )


def test_attrs_rejects_leading_digit_key():
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs={"1foo": 1},
        )


def test_attrs_rejects_depth_over_4():
    """Nesting 5 levels deep should be rejected."""
    deep = {"a": {"b": {"c": {"d": {"e": "too deep"}}}}}
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs=deep,
        )


def test_attrs_rejects_size_over_64kb():
    """Serialized size > 64 KB should be rejected."""
    big = {f"key_{i:04d}": "v" * 10 for i in range(5000)}
    with pytest.raises(ValidationError):
        RelationshipCreate(
            src_entity_id=uuid.uuid4(),
            dst_entity_id=uuid.uuid4(),
            rel_type=RelationshipType.OWNS,
            attrs=big,
        )
