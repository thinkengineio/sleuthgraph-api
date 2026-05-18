"""HIBPPlugin — BYOK breach database lookup for EMAIL entities."""

import json
import uuid
from pathlib import Path

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.hibp import HIBPPlugin


FIXTURE_DIR = Path(__file__).parent / "fixtures"
CREDS = {"api_key": "test-hibp-key-abc123"}


def _entity(label: str) -> Entity:
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.EMAIL.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _transport(
    status: int = 200,
    body: bytes | None = None,
    fixture: str | None = None,
    capture_headers: dict | None = None,
):
    """Build a MockTransport that always validates the HIBP auth header."""
    if body is None and fixture is not None:
        body = (FIXTURE_DIR / fixture).read_bytes()
    if body is None:
        body = b"[]"

    def handler(request: httpx.Request) -> httpx.Response:
        # Always assert the API key header is correctly named and valued.
        assert request.headers.get("hibp-api-key") == CREDS["api_key"]
        assert request.headers.get("user-agent", "").startswith("sleuthgraph/")
        if capture_headers is not None:
            capture_headers["hibp-api-key"] = request.headers.get("hibp-api-key")
            capture_headers["user-agent"] = request.headers.get("user-agent")
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_breaches_found_produces_evidence():
    """200 with breach data → one EvidenceProposal, no entities or relationships."""
    plugin = HIBPPlugin()
    raw = (FIXTURE_DIR / "hibp_breaches.json").read_bytes()
    transport = _transport(body=raw)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1

    ev = result.evidence[0]
    assert ev.payload == raw
    assert ev.content_type == "application/json"
    assert "HIBP breach lookup for test@example.com" in ev.query
    assert ev.link_to_input is True


@pytest.mark.asyncio
async def test_breach_count_in_reproducibility_spec():
    plugin = HIBPPlugin()
    raw = (FIXTURE_DIR / "hibp_breaches.json").read_bytes()
    transport = _transport(body=raw)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    spec = result.evidence[0].reproducibility_spec
    assert spec["breach_count"] == 2
    assert "Adobe" in spec["breach_names"]
    assert "LinkedIn" in spec["breach_names"]
    assert spec["method"] == "GET"
    assert "queried_at" in spec


@pytest.mark.asyncio
async def test_data_classes_deduplicated_in_spec():
    """DataClasses shared across breaches appear only once in spec."""
    plugin = HIBPPlugin()
    raw = (FIXTURE_DIR / "hibp_breaches.json").read_bytes()
    transport = _transport(body=raw)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    data_classes = result.evidence[0].reproducibility_spec["data_classes"]
    # "Email addresses" and "Passwords" appear in both fixtures; must dedup.
    assert data_classes.count("Email addresses") == 1
    assert data_classes.count("Passwords") == 1
    # Unique to Adobe only
    assert "Password hints" in data_classes
    assert "Usernames" in data_classes


# ---------------------------------------------------------------------------
# No breaches (404)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_breaches_returns_empty_result():
    """404 from HIBP means no breaches found — empty QueryResult, no evidence."""
    plugin = HIBPPlugin()

    def handler(request: httpx.Request) -> httpx.Response:
        # 404 does not require the normal header validation to fire (still valid).
        return httpx.Response(404, content=b"")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("clean@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert result.evidence == []


# ---------------------------------------------------------------------------
# Rate limiting (429)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limited_429_not_retried():
    """429 is not retried (retry predicate limited to transport/timeout errors)."""
    plugin = HIBPPlugin()
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(429, content=b"Too Many Requests")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(ent, CREDS, ctx)

    assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# Server errors (5xx)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_server_error_500_not_retried():
    """500 is not retried (retry predicate limited to transport/timeout errors)."""
    plugin = HIBPPlugin()
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(500, content=b"Internal Server Error")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(ent, CREDS, ctx)

    assert call_count["n"] == 1


# ---------------------------------------------------------------------------
# Input validation — empty / blank email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_email_returns_empty_result():
    plugin = HIBPPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_blank_whitespace_email_returns_empty_result():
    plugin = HIBPPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("   ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


# ---------------------------------------------------------------------------
# Input validation — script/path injection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rejects_script_injection_in_email_label():
    """<script>alert(1)</script>@evil.com must be rejected before URL construction."""
    plugin = HIBPPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("<script>alert(1)</script>@evil.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_path_traversal_in_email_label():
    """Emails with '../' must be rejected before URL construction (CWE-74)."""
    plugin = HIBPPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com/../admin")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_query_param_injection_in_email():
    """Email with '?' must be rejected to prevent query-string injection."""
    plugin = HIBPPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com?evil=1")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


# ---------------------------------------------------------------------------
# Credential verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_credentials_api_key_sent_in_hibp_api_key_header():
    """Verify the plugin reads api_key from credentials dict and passes it as hibp-api-key."""
    plugin = HIBPPlugin()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["hibp-api-key"] = request.headers.get("hibp-api-key")
        captured["user-agent"] = request.headers.get("user-agent")
        return httpx.Response(200, content=b"[]")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        await plugin.query(ent, {"api_key": "my-secret-hibp-key"}, ctx)

    assert captured["hibp-api-key"] == "my-secret-hibp-key"
    assert captured["user-agent"].startswith("sleuthgraph/")


# ---------------------------------------------------------------------------
# URL encoding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_email_with_plus_is_url_encoded():
    """Emails with '+' in local part must be percent-encoded in the URL path."""
    plugin = HIBPPlugin()
    captured_url = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_url["url"] = str(request.url)
        return httpx.Response(404, content=b"")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("foo+bar@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        await plugin.query(ent, CREDS, ctx)

    # '+' must be percent-encoded as '%2B' in the path.
    assert "%2B" in captured_url["url"] or "foo%2Bbar" in captured_url["url"]
    # Raw '+' must NOT appear in the URL path portion.
    path_part = captured_url["url"].split("?")[0]
    assert "+" not in path_part


# ---------------------------------------------------------------------------
# Plugin class attributes
# ---------------------------------------------------------------------------


def test_plugin_class_attributes():
    plugin = HIBPPlugin()
    assert plugin.name == "hibp"
    assert plugin.version == "0.1.0"
    assert plugin.requires_credentials is True
    assert plugin.credential_name == "hibp"
    assert plugin.credential_url == "https://haveibeenpwned.com/API/Key"
    assert plugin.entity_types_accepted == [EntityType.EMAIL]
    assert plugin.entity_types_produced == []
    assert plugin.http_timeout_seconds == 15.0


# ---------------------------------------------------------------------------
# Empty breach list on 200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_breach_list_on_200_produces_evidence():
    """200 with an empty JSON array is unusual but valid; we still record evidence.

    Contrast: 404 → None return → QueryResult() with no evidence.
              200 + [] → (b'[]', []) return → evidence row with breach_count=0.
    """
    plugin = HIBPPlugin()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("test@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    # An empty list on 200 still produces evidence (the API said "here is your result").
    # The _fetch returns (b"[]", []) not None, so evidence is created.
    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1
    assert result.evidence[0].reproducibility_spec["breach_count"] == 0
