"""Apache AGE graph helpers shared by entities + relationships.

All AGE writes go through this module. We always set search_path to include
ag_catalog before running Cypher. User-supplied data is serialized as a Cypher
map literal — never f-strung raw into the query body.

AGE's Cypher parser requires map literals (unquoted keys, single-quoted string
values) rather than JSON (which has double-quoted keys). The ``_encode_props``
helper converts a Python dict to a Cypher map literal with proper escaping.
String values have their embedded single-quotes escaped as ``\\'``. Nested
dicts are encoded recursively.

Security notes
--------------
* Dollar-quote injection (C1): ``run_cypher`` uses a random 12-byte hex tag
  per call so a user-controlled string containing ``$$`` cannot escape the
  outer dollar-quote delimiter.
* Map-key injection (HIGH-1): ``_encode_props`` asserts every key is a safe
  Cypher identifier at encode time; the Pydantic-layer validators in
  ``sleuthgraph.graph.validators`` enforce this at request ingress.
"""

import re
import secrets
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

GRAPH_NAME = "sleuthgraph"

# Safe Cypher identifier: must start with letter or underscore, contain only
# alphanumerics and underscores, max 64 chars.  Matches the Pydantic-layer
# validator in sleuthgraph.graph.validators._KEY_RE.
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _cypher_scalar(value: Any) -> str:
    """Encode a single scalar value as a Cypher literal.

    - str  → single-quoted with internal single-quotes escaped as \\'
    - int / float → numeric literal
    - bool → ``true`` / ``false``
    - None → ``null``
    - dict → recursive Cypher map literal
    - everything else → single-quoted string representation
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        return _encode_props(value)
    # Default: coerce to str and single-quote with escaping
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _encode_props(props: dict[str, Any]) -> str:
    """Encode a property map as a Cypher map literal safe for embedding.

    AGE Cypher map syntax: ``{key: value, ...}`` where keys are unquoted
    identifiers and string values are single-quoted.  This is NOT JSON —
    json.dumps produces double-quoted keys which AGE's parser rejects.

    Defense-in-depth: every key is asserted against _KEY_RE here so even if
    the Pydantic-layer validator is bypassed somehow the encoder fails loudly
    rather than silently producing injectable Cypher.
    """
    parts = []
    for k, v in props.items():
        if not _KEY_RE.match(k):
            raise ValueError(f"invalid Cypher map key: {k!r}")
        parts.append(f"{k}: {_cypher_scalar(v)}")
    return "{" + ", ".join(parts) + "}"


async def set_search_path(session: AsyncSession) -> None:
    """Set search_path so bare ``cypher(...)`` calls resolve without schema prefix."""
    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))


async def run_cypher(
    session: AsyncSession,
    cypher: str,
    return_col: str = "v",
) -> list:
    """Run a Cypher statement and return the raw agtype column rows.

    Uses a random per-call dollar-quote tag so user-controlled strings inside
    the Cypher body cannot terminate the outer dollar-quote delimiter.

    The Cypher body must NOT contain user-controlled strings directly —
    embed user input via ``_encode_props`` and reference as property maps.
    """
    await set_search_path(session)

    # Random tag; retry on the astronomical chance of collision (p ~ 2^-48).
    for _ in range(4):
        tag = "sg_" + secrets.token_hex(12)
        delim = f"${tag}$"
        if delim not in cypher:
            break
    else:
        # Should never happen — 96-bit random collision 4x in a row.
        raise RuntimeError("could not find a safe dollar-quote tag")

    sql = (
        f"SELECT * FROM cypher('{GRAPH_NAME}', {delim} {cypher} {delim}) AS ({return_col} agtype);"
    )
    # Use the underlying asyncpg connection via exec_driver_sql to bypass
    # SQLAlchemy's bind-parameter interpretation. Otherwise any $<digit>
    # sequence inside a user-controlled string literal in the Cypher body
    # (e.g. a URL label "...?$1=foo") gets misread as an asyncpg positional
    # bind placeholder and the statement fails with InvalidRequestError.
    # Dollar-quote tagging still protects us from Postgres-level parsing.
    conn = await session.connection()
    result = await conn.exec_driver_sql(sql)
    return list(result)
