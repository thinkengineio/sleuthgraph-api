"""Tests for OIDC state JWT encoding/decoding."""

import time
import pytest
from sleuthgraph.auth.oidc_state import encode_state, decode_state, StateError


def test_roundtrip():
    s = encode_state(code_verifier="v" * 64, next_path="/cases")
    payload = decode_state(s)
    assert payload.code_verifier == "v" * 64
    assert payload.next_path == "/cases"
    assert payload.nonce  # non-empty


def test_tampered_state_rejected():
    s = encode_state(code_verifier="v" * 64, next_path="/")
    tampered = s[:-4] + "AAAA"
    with pytest.raises(StateError):
        decode_state(tampered)


def test_expired_state_rejected(monkeypatch):
    # Freeze encode time to 10 minutes ago.
    real_time = time.time()
    monkeypatch.setattr(time, "time", lambda: real_time - 600)
    s = encode_state(code_verifier="v" * 64, next_path="/")
    monkeypatch.setattr(time, "time", lambda: real_time)
    with pytest.raises(StateError):
        decode_state(s)


def test_next_path_sanitized_to_relative():
    # External URLs must not survive a round-trip.
    s = encode_state(code_verifier="v" * 64, next_path="https://evil.example.com/phish")
    payload = decode_state(s)
    assert payload.next_path == "/"  # normalized
