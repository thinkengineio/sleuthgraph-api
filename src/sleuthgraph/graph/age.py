"""Apache AGE graph helpers shared by entities + relationships.

All AGE writes go through this module. We always set search_path to include
ag_catalog before running Cypher. User-supplied data is serialized as a Cypher
map literal — never f-strung raw into the query body.

AGE's Cypher parser requires map literals (unquoted keys, single-quoted string
values) rather than JSON (which has double-quoted keys). The ``_encode_props``
helper converts a Python dict to a Cypher map literal with proper escaping.
String values have their embedded single-quotes escaped as ``\\'``. Nested
dicts are encoded recursively.
"""

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

GRAPH_NAME = "sleuthgraph"


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

    All property keys in our schema are simple alphanumeric identifiers
    (id, case_id, label, confidence, attrs) so they need no quoting.
    """
    pairs = ", ".join(f"{k}: {_cypher_scalar(v)}" for k, v in props.items())
    return "{" + pairs + "}"


async def set_search_path(session: AsyncSession) -> None:
    """Set search_path so bare ``cypher(...)`` calls resolve without schema prefix."""
    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))


async def run_cypher(
    session: AsyncSession, cypher: str, return_col: str = "v"
) -> list:
    """Run a Cypher statement and return the raw agtype column rows.

    The Cypher body must NOT contain user-controlled strings directly —
    embed user input via ``_encode_props`` and reference as property maps.
    """
    await set_search_path(session)
    sql = f"SELECT * FROM cypher('{GRAPH_NAME}', $$ {cypher} $$) AS ({return_col} agtype);"
    result = await session.execute(text(sql))
    return list(result)
