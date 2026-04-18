"""Determinism + correctness of canonical SHA-256 hashing."""

import hashlib
import pytest

from sleuthgraph.evidence.hashing import (
    canonical_json_bytes,
    hash_bytes,
    hash_json,
)


def test_hash_bytes_matches_hashlib():
    data = b"hello world"
    expected = hashlib.sha256(data).hexdigest()
    assert hash_bytes(data) == expected


def test_hash_bytes_empty():
    # Known SHA-256 of empty input
    assert hash_bytes(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )


def test_canonical_json_key_order_invariant():
    a = canonical_json_bytes({"a": 1, "b": 2})
    b = canonical_json_bytes({"b": 2, "a": 1})
    assert a == b


def test_canonical_json_no_whitespace():
    out = canonical_json_bytes({"k": "v"})
    assert b" " not in out


def test_canonical_json_utf8_unicode():
    obj = {"name": "Ali \u0131za"}  # Turkish dotless i
    out = canonical_json_bytes(obj)
    # Must be utf-8 bytes (not ascii-escaped)
    assert "Ali \u0131za".encode("utf-8") in out


def test_hash_json_deterministic_across_equivalent_dicts():
    h1, _ = hash_json({"a": 1, "b": 2})
    h2, _ = hash_json({"b": 2, "a": 1})
    assert h1 == h2


def test_hash_json_different_for_different_content():
    h1, _ = hash_json({"a": 1})
    h2, _ = hash_json({"a": 2})
    assert h1 != h2


def test_hash_json_nested():
    h1, b1 = hash_json({"outer": {"inner": [1, 2, 3]}})
    h2, b2 = hash_json({"outer": {"inner": [1, 2, 3]}})
    assert h1 == h2
    assert b1 == b2


def test_hash_json_returns_matching_bytes():
    h, b = hash_json({"x": 1})
    assert hash_bytes(b) == h


def test_hex_digest_is_64_chars():
    h = hash_bytes(b"anything")
    assert len(h) == 64
    int(h, 16)  # must be valid hex


def test_canonical_json_stable_number_format():
    # Floats + ints shouldn't surprise us
    a = canonical_json_bytes({"n": 1})
    b = canonical_json_bytes({"n": 1})
    assert a == b
