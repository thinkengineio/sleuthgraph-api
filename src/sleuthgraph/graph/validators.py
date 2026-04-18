"""Shared Pydantic-layer validators for graph-related fields.

These run at request ingress (schema validation time) and enforce constraints
that are also re-checked at encode time in ``sleuthgraph.graph.age._encode_props``
for defense-in-depth.
"""

import json
import re

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_MAX_DEPTH = 4
_MAX_BYTES = 64 * 1024


def _validate_attrs(value: dict) -> dict:
    """Validate an ``attrs`` dict for safe Cypher map embedding.

    Enforces:
    - All keys (including nested) match ``^[A-Za-z_][A-Za-z0-9_]{0,63}$``
    - Nesting depth does not exceed ``_MAX_DEPTH`` (4)
    - Total serialized JSON size does not exceed ``_MAX_BYTES`` (64 KB)

    Raises ``ValueError`` on any violation so Pydantic surfaces it as a
    ``ValidationError`` to the caller.
    """

    def _walk(obj, depth: int = 0) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError(f"attrs nesting exceeds max depth {_MAX_DEPTH}")
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(k, str):
                    raise ValueError(
                        f"attrs key must be string, got {type(k).__name__}"
                    )
                if not _KEY_RE.match(k):
                    raise ValueError(
                        f"attrs key {k!r} does not match "
                        f"^[A-Za-z_][A-Za-z0-9_]{{0,63}}$"
                    )
                _walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, depth + 1)
        # primitives are fine

    _walk(value)

    size = len(json.dumps(value).encode("utf-8"))
    if size > _MAX_BYTES:
        raise ValueError(
            f"attrs serialized size {size} bytes exceeds limit of {_MAX_BYTES} bytes"
        )

    return value
