"""Shape tests for Evidence ORM model."""

from sleuthgraph.evidence.models import Evidence


def test_evidence_tablename():
    assert Evidence.__tablename__ == "evidence"


def test_evidence_columns():
    cols = {c.name for c in Evidence.__table__.columns}
    required = {
        "id",
        "case_id",
        "entity_id",
        "source_plugin",
        "query",
        "response_hash",
        "response_uri",
        "response_bytes",
        "response_content_type",
        "timestamp",
        "reproducibility_spec",
        "created_by",
    }
    assert required <= cols, f"missing: {required - cols}"


def test_evidence_no_updated_at_no_deleted_at():
    """Append-only by design."""
    cols = {c.name for c in Evidence.__table__.columns}
    assert "updated_at" not in cols
    assert "deleted_at" not in cols


def test_case_id_fk_cascade():
    col = Evidence.__table__.c.case_id
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "cases"
    assert fks[0].ondelete == "CASCADE"
    assert col.nullable is False


def test_entity_id_fk_set_null():
    col = Evidence.__table__.c.entity_id
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "entities"
    assert fks[0].ondelete == "SET NULL"
    assert col.nullable is True


def test_created_by_fk_set_null():
    col = Evidence.__table__.c.created_by
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "users"
    assert fks[0].ondelete == "SET NULL"
