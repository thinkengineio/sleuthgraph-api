"""CrtShPlugin -- subdomain extraction + proposal shape."""

import json
import uuid
from pathlib import Path

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.crtsh import CrtShPlugin
from sleuthgraph.relationships.types import RelationshipType

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "crtsh_example.json"


def _make_transport(status=200, body=None, use_fixture=True):
    if body is None and use_fixture:
        body = FIXTURE_PATH.read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        content = body if isinstance(body, (bytes, str)) else json.dumps(body).encode()
        return httpx.Response(status, content=content)

    return httpx.MockTransport(handler)


def _make_input_domain(label="example.com"):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.DOMAIN.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


@pytest.mark.asyncio
async def test_extracts_subdomains_from_fixture():
    plugin = CrtShPlugin()
    transport = _make_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    labels = {e.label for e in result.entities}
    assert labels == {
        "www.example.com",
        "api.example.com",
        "dev.example.com",
        "staging.example.com",
    }


@pytest.mark.asyncio
async def test_emits_one_subdomain_of_rel_per_entity():
    plugin = CrtShPlugin()
    transport = _make_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    assert len(result.relationships) == len(result.entities)
    for rp in result.relationships:
        assert rp.rel_type == RelationshipType.SUBDOMAIN_OF
        assert rp.dst == {"input": True}
        assert rp.src["ref"].startswith("sub-")


@pytest.mark.asyncio
async def test_evidence_carries_raw_response():
    plugin = CrtShPlugin()
    raw = FIXTURE_PATH.read_bytes()
    transport = _make_transport(body=raw)
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.payload == raw
    assert ev.content_type == "application/json"
    assert "crt.sh subdomain lookup for example.com" in ev.query
    assert ev.reproducibility_spec["method"] == "GET"
    assert ev.reproducibility_spec["subdomain_count"] == 4


@pytest.mark.asyncio
async def test_drops_wildcards():
    plugin = CrtShPlugin()
    transport = _make_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    for e in result.entities:
        assert not e.label.startswith("*")


@pytest.mark.asyncio
async def test_drops_unrelated_domains():
    plugin = CrtShPlugin()
    transport = _make_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    for e in result.entities:
        assert e.label.endswith(".example.com")


@pytest.mark.asyncio
async def test_drops_input_domain_itself():
    plugin = CrtShPlugin()
    transport = _make_transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    assert "example.com" not in {e.label for e in result.entities}


@pytest.mark.asyncio
async def test_empty_response_produces_no_entities():
    plugin = CrtShPlugin()
    transport = _make_transport(body=b"[]")
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1


@pytest.mark.asyncio
async def test_http_500_not_retried():
    """500 is not retried (retry predicate limited to transport/timeout errors)."""
    plugin = CrtShPlugin()
    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        return httpx.Response(500, content=b"oops")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(_make_input_domain(), None, ctx)

    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_response_body_over_10mb_aborts():
    """A response larger than 10 MiB raises httpx.HTTPError after tenacity retries."""
    plugin = CrtShPlugin()
    huge_body = b"[" + (b'{"name_value":"x.example.com"},' * 500_000) + b"{}" + b"]"
    assert len(huge_body) > 10 * 1024 * 1024

    def handler(request):
        return httpx.Response(200, content=huge_body)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        with pytest.raises(httpx.HTTPError, match="exceeded"):
            await plugin.query(_make_input_domain(), None, ctx)


@pytest.mark.asyncio
async def test_extract_subdomains_caps_at_1000_and_marks_truncated():
    """_extract_subdomains caps the set at MAX_SUBDOMAINS and returns truncated=True."""
    from sleuthgraph.plugins.builtin.crtsh import MAX_SUBDOMAINS

    entries = [{"name_value": f"sub{i}.example.com"} for i in range(MAX_SUBDOMAINS + 50)]
    subs, truncated = CrtShPlugin._extract_subdomains(entries, "example.com")
    assert len(subs) == MAX_SUBDOMAINS
    assert truncated is True


@pytest.mark.asyncio
async def test_extract_subdomains_below_cap_not_truncated():
    entries = [{"name_value": f"sub{i}.example.com"} for i in range(10)]
    subs, truncated = CrtShPlugin._extract_subdomains(entries, "example.com")
    assert len(subs) == 10
    assert truncated is False
