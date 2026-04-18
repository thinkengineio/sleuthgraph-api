"""Case schema tests."""

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sleuthgraph.cases.schemas import CaseCreate, CaseRead, CaseUpdate


def test_case_create_requires_name():
    with pytest.raises(ValidationError):
        CaseCreate()


def test_case_create_accepts_name_and_tags():
    c = CaseCreate(name="Target Foo", tags=["bar", "baz"])
    assert c.name == "Target Foo"
    assert c.tags == ["bar", "baz"]


def test_case_create_defaults_empty_tags():
    c = CaseCreate(name="x")
    assert c.tags == []


def test_case_create_rejects_empty_name():
    with pytest.raises(ValidationError):
        CaseCreate(name="")


def test_case_create_rejects_overlong_name():
    with pytest.raises(ValidationError):
        CaseCreate(name="x" * 300)


def test_case_read_shape():
    now = datetime.now(timezone.utc)
    cr = CaseRead(
        id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        name="x",
        status="active",
        tags=["a"],
        created_at=now,
        updated_at=now,
    )
    assert cr.status == "active"
    assert cr.tags == ["a"]


def test_case_read_owner_id_nullable():
    now = datetime.now(timezone.utc)
    cr = CaseRead(
        id=uuid.uuid4(),
        owner_id=None,
        name="x",
        status="active",
        tags=[],
        created_at=now,
        updated_at=now,
    )
    assert cr.owner_id is None


def test_case_update_all_fields_optional():
    cu = CaseUpdate()
    assert cu.name is None
    assert cu.status is None
    assert cu.tags is None


def test_case_update_partial_name():
    cu = CaseUpdate(name="renamed")
    assert cu.name == "renamed"
    assert cu.status is None


def test_case_update_rejects_invalid_status():
    with pytest.raises(ValidationError):
        CaseUpdate(status="nonsense")


def test_case_update_accepts_valid_status():
    for s in ("active", "archived"):
        cu = CaseUpdate(status=s)
        assert cu.status == s
