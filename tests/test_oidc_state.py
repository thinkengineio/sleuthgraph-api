"""Tests for OIDC state JWT encoding/decoding."""

import time

import pytest

from sleuthgraph.auth.oidc_state import StateError, decode_state, encode_state


def test_roundtrip():
    s = encode_state(code_verifier="v" * 64, next_path="/cases", oidc_nonce="n" * 32)
    payload = decode_state(s)
    assert payload.code_verifier == "v" * 64
    assert payload.next_path == "/cases"
    assert payload.csrf  # non-empty, random per-request
    assert payload.oidc_nonce == "n" * 32


def test_csrf_is_random_per_call():
    s1 = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="n1")
    s2 = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="n2")
    p1 = decode_state(s1)
    p2 = decode_state(s2)
    assert p1.csrf != p2.csrf


def test_tampered_state_rejected():
    s = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="n")
    tampered = s[:-4] + "AAAA"
    with pytest.raises(StateError):
        decode_state(tampered)


def test_expired_state_rejected(monkeypatch):
    # Freeze encode time to 10 minutes ago.
    real_time = time.time()
    monkeypatch.setattr(time, "time", lambda: real_time - 600)
    s = encode_state(code_verifier="v" * 64, next_path="/", oidc_nonce="n")
    monkeypatch.setattr(time, "time", lambda: real_time)
    with pytest.raises(StateError):
        decode_state(s)


def test_next_path_sanitized_to_relative():
    # External URLs must not survive a round-trip.
    s = encode_state(
        code_verifier="v" * 64, next_path="https://evil.example.com/phish", oidc_nonce="n"
    )
    payload = decode_state(s)
    assert payload.next_path == "/"  # normalized
