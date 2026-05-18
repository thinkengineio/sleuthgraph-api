"""Canonical SHA-256 hashing for evidence payloads.

Binary payloads → hash the raw bytes.
JSON payloads   → serialize to canonical JSON (sorted keys, no whitespace,
                  utf-8 bytes) BEFORE hashing. The canonical form is what
                  gets STORED to MinIO, so downstream auditors can recompute
                  the hash byte-for-byte from the stored blob.
"""

import hashlib
import json
from typing import Any


def hash_bytes(data: bytes) -> str:
    """Return hex-encoded SHA-256 of the raw bytes."""
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize obj to canonical UTF-8 JSON (sorted keys, no whitespace).

    The same dict with different key insertion order yields identical bytes.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_json(obj: Any) -> tuple[str, bytes]:
    """Return (hex_digest, canonical_bytes) — bytes is what to upload."""
    canonical = canonical_json_bytes(obj)
    return hash_bytes(canonical), canonical
