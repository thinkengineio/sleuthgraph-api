"""EvidenceCreate / EvidenceRead / EvidenceList shape + validator tests."""

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sleuthgraph.evidence.schemas import (
    EvidenceCreate,
    EvidenceList,
    EvidenceRead,
)

# --- EvidenceCreate ---


def test_create_requires_query():
    with pytest.raises(ValidationError):
        EvidenceCreate()


def test_create_defaults_source_plugin_to_manual():
    e = EvidenceCreate(query="Saw this on example.com at 12:00 UTC")
    assert e.source_plugin == "manual"
    assert e.reproducibility_spec == {}
    assert e.entity_id is None


def test_create_accepts_full_shape():
    eid = uuid.uuid4()
    e = EvidenceCreate(
        entity_id=eid,
        source_plugin="crtsh",
        query="lookup example.com",
        reproducibility_spec={"url": "https://crt.sh/...", "method": "GET"},
    )
    assert e.entity_id == eid
    assert e.source_plugin == "crtsh"
    assert e.reproducibility_spec["url"] == "https://crt.sh/..."


def test_create_rejects_empty_query():
    with pytest.raises(ValidationError):
        EvidenceCreate(query="")


def test_create_rejects_overlong_query():
    with pytest.raises(ValidationError):
        EvidenceCreate(query="x" * 2000)


def test_create_rejects_invalid_spec_key():
    """reproducibility_spec uses the same attrs validator — rejects
    injection-style keys."""
    with pytest.raises(ValidationError):
        EvidenceCreate(
            query="x",
            reproducibility_spec={"bad key": "value"},
        )


def test_create_rejects_long_spec_key():
    with pytest.raises(ValidationError):
        EvidenceCreate(
            query="x",
            reproducibility_spec={"x" * 65: 1},
        )


def test_create_rejects_leading_digit_spec_key():
    with pytest.raises(ValidationError):
        EvidenceCreate(
            query="x",
            reproducibility_spec={"1foo": 1},
        )


# --- EvidenceRead ---


def test_read_shape():
    now = datetime.now(UTC)
    er = EvidenceRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        entity_id=None,
        source_plugin="manual",
        query="x",
        response_hash="a" * 64,
        response_uri="case/x/ev/abc",
        response_bytes=42,
        response_content_type="application/json",
        timestamp=now,
        reproducibility_spec={},
        created_by=None,
    )
    assert er.blob_url is None  # optional


def test_read_accepts_blob_url_injection():
    now = datetime.now(UTC)
    er = EvidenceRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        entity_id=None,
        source_plugin="manual",
        query="x",
        response_hash="a" * 64,
        response_uri="case/x/ev/abc",
        response_bytes=42,
        response_content_type=None,
        timestamp=now,
        reproducibility_spec={},
        created_by=None,
        blob_url="https://s3.example.com/signed",
    )
    assert er.blob_url.startswith("https://")


# --- EvidenceList ---


def test_list_shape():
    now = datetime.now(UTC)
    row = EvidenceRead(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        entity_id=None,
        source_plugin="manual",
        query="x",
        response_hash="a" * 64,
        response_uri="k",
        response_bytes=1,
        response_content_type=None,
        timestamp=now,
        reproducibility_spec={},
        created_by=None,
    )
    lst = EvidenceList(items=[row], total=1, limit=50, offset=0)
    assert lst.total == 1
    assert len(lst.items) == 1
