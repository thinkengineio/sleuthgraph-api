"""Tests for User SQLAlchemy model shape."""

from sleuthgraph.auth.models import User


def test_user_table_columns():
    cols = {c.name for c in User.__table__.columns}
    required = {
        "id",
        "email",
        "hashed_password",
        "is_active",
        "is_superuser",
        "is_verified",
        "name",
        "oidc_sub",
    }
    assert required <= cols, f"Missing columns: {required - cols}"


def test_user_oidc_sub_nullable_and_unique():
    col = User.__table__.c.oidc_sub
    assert col.nullable is True
    assert col.unique is True


def test_user_name_nullable():
    col = User.__table__.c.name
    assert col.nullable is True


def test_user_tablename():
    assert User.__tablename__ == "users"
