"""Integration tests for EvidenceStorage against live MinIO."""

import os
import uuid

import pytest

from sleuthgraph.evidence.hashing import hash_bytes
from sleuthgraph.evidence.storage import EvidenceStorage, build_key


@pytest.fixture
async def storage():
    """Yield an EvidenceStorage pointed at local MinIO, or skip."""
    endpoint = os.environ.get("SLEUTHGRAPH_TEST_S3_ENDPOINT", "http://localhost:9000")
    bucket = os.environ.get("SLEUTHGRAPH_TEST_S3_BUCKET", "evidence")
    s = EvidenceStorage(
        endpoint=endpoint,
        access_key="sleuthgraph",
        secret_key="changeme_local_only",
        bucket=bucket,
    )
    # Probe with a head call on a bogus key — any 404 means reachable, connection errors mean skip
    try:
        await s.exists("__probe__")
    except Exception as e:
        pytest.skip(f"MinIO not reachable at {endpoint}: {e}")
    yield s


def _k():
    return build_key(str(uuid.uuid4()), "a" * 64)


@pytest.mark.asyncio
async def test_put_and_get_roundtrip(storage):
    key = _k()
    payload = b"hello evidence"
    await storage.put(key, payload, content_type="text/plain")
    assert await storage.exists(key) is True
    got = await storage.get(key)
    assert got == payload


@pytest.mark.asyncio
async def test_put_is_idempotent(storage):
    key = _k()
    payload = b"idempotent body"
    await storage.put(key, payload)
    # Second put same payload — should be a head-then-skip, no error
    await storage.put(key, payload)
    got = await storage.get(key)
    assert got == payload


@pytest.mark.asyncio
async def test_exists_returns_false_for_missing(storage):
    key = build_key(str(uuid.uuid4()), "f" * 64)
    assert await storage.exists(key) is False


@pytest.mark.asyncio
async def test_presign_get_returns_url(storage):
    key = _k()
    await storage.put(key, b"presigned body")
    url = await storage.presign_get(key, expires_in=60)
    assert url.startswith("http")
    assert key.replace("/", "%2F") in url or key in url


def test_build_key_shape():
    key = build_key("case123", "abcd")
    assert key == "case/case123/ev/abcd"


@pytest.mark.asyncio
async def test_hash_matches_roundtrip_content(storage):
    """Round-trip: upload payload, retrieve, hash → matches expected."""
    payload = b'{"evidence":"matters"}'
    expected_hash = hash_bytes(payload)
    key = build_key(str(uuid.uuid4()), expected_hash)
    await storage.put(key, payload, content_type="application/json")
    got = await storage.get(key)
    assert hash_bytes(got) == expected_hash
