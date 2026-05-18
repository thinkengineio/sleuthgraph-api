"""Shape tests for Case model."""

from sleuthgraph.cases.models import Case


def test_case_columns():
    cols = {c.name for c in Case.__table__.columns}
    required = {
        "id",
        "owner_id",
        "name",
        "status",
        "tags",
        "created_at",
        "updated_at",
        "deleted_at",
    }
    assert required <= cols, f"Missing: {required - cols}"


def test_case_owner_id_fk_to_users():
    owner = Case.__table__.c.owner_id
    fks = list(owner.foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "users"


def test_case_owner_id_nullable():
    # users may be deleted; set-null rather than cascade (evidence chain)
    assert Case.__table__.c.owner_id.nullable is True


def test_case_name_required():
    assert Case.__table__.c.name.nullable is False


def test_case_tablename():
    assert Case.__tablename__ == "cases"


def test_case_status_has_default():
    # Default value should be present (server_default or Python default)
    col = Case.__table__.c.status
    assert col.default is not None or col.server_default is not None
