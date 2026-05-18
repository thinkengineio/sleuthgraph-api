"""Tests for User Pydantic schemas."""

import uuid

import pytest
from pydantic import ValidationError

from sleuthgraph.auth.schemas import UserCreate, UserRead, UserUpdate


def test_user_create_accepts_email_password_name():
    uc = UserCreate(email="a@b.com", password="hunter222hunt", name="Alice")
    assert uc.email == "a@b.com"
    assert uc.password == "hunter222hunt"
    assert uc.name == "Alice"


def test_user_create_name_optional():
    uc = UserCreate(email="a@b.com", password="hunter222hunt")
    assert uc.name is None


def test_user_create_requires_email_and_password():
    with pytest.raises(ValidationError):
        UserCreate(email="a@b.com")  # missing password
    with pytest.raises(ValidationError):
        UserCreate(password="hunter222hunt")  # missing email


def test_user_read_has_id_email_name():
    uid = uuid.uuid4()
    ur = UserRead(
        id=uid,
        email="a@b.com",
        is_active=True,
        is_superuser=False,
        is_verified=False,
        name="Alice",
    )
    assert ur.id == uid
    assert ur.email == "a@b.com"
    assert ur.name == "Alice"


def test_user_update_allows_partial():
    uu = UserUpdate(name="Bob")
    assert uu.name == "Bob"
    # Email/password should be optional on update too
    uu2 = UserUpdate()
    assert uu2.name is None
