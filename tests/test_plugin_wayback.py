"""wayback_cdx plugin: DOMAIN|URL → URL snapshots via archive.org CDX."""

import json
import uuid

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.wayback_cdx import (
    MAX_SNAPSHOTS,
    WaybackCdxPlugin,
)
from sleuthgraph.relationships.types import RelationshipType


def _make_domain(label="example.com"):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.DOMAIN.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _make_url(label="https://example.com/page"):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.URL.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _cdx_body(rows):
    """Build a CDX JSON response: header row + rows."""
    header = ["timestamp", "original", "statuscode"]
    return json.dumps([header, *rows]).encode()


def _transport(status=200, body=b"[]"):
    def handler(request):
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_domain_with_three_snapshots_produces_three_url_entities():
    body = _cdx_body(
        [
            ["20200101120000", "https://example.com/", "200"],
            ["20210202120000", "https://example.com/a", "200"],
            ["20220303120000", "https://example.com/b", "404"],
        ]
    )
    plugin = WaybackCdxPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_domain(), http_client=client)
        result = await plugin.query(_make_domain(), None, ctx)

    assert {e.type for e in result.entities} == {EntityType.URL}
    assert {e.label for e in result.entities} == {
        "https://example.com/",
        "https://example.com/a",
        "https://example.com/b",
    }
    assert len(result.relationships) == 3
    for r in result.relationships:
        assert r.rel_type == RelationshipType.ASSOCIATED_WITH
        assert r.dst == {"input": True}
        assert r.attrs["role"] == "archived"


@pytest.mark.asyncio
async def test_empty_cdx_is_no_entities_but_evidence_present():
    body = _cdx_body([])
    plugin = WaybackCdxPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_domain(), http_client=client)
        result = await plugin.query(_make_domain(), None, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1


@pytest.mark.asyncio
async def test_truncation_marker_when_cap_hit():
    rows = [
        [f"202001{i:02d}120000", f"https://example.com/p{i}", "200"]
        for i in range(MAX_SNAPSHOTS + 5)
    ]
    body = _cdx_body(rows)
    plugin = WaybackCdxPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_domain(), http_client=client)
        result = await plugin.query(_make_domain(), None, ctx)

    assert len(result.entities) == MAX_SNAPSHOTS
    assert result.evidence[0].reproducibility_spec["truncated"] is True


@pytest.mark.asyncio
async def test_http_503_not_retried_returns_empty_gracefully():
    """503 is not retried (retry predicate limited to transport/timeout errors)."""
    call = {"n": 0}

    def handler(request):
        call["n"] += 1
        return httpx.Response(503, content=b"")

    transport = httpx.MockTransport(handler)
    plugin = WaybackCdxPlugin()
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_domain(), http_client=client)
        result = await plugin.query(_make_domain(), None, ctx)

    # Plugin swallows the error to allow "zero result success"
    assert result.entities == []
    assert call["n"] == 1
    assert result.evidence[0].reproducibility_spec["fetch_status"] == "error"


@pytest.mark.asyncio
async def test_url_input_accepted():
    body = _cdx_body(
        [
            ["20200101120000", "https://example.com/page", "200"],
        ]
    )
    plugin = WaybackCdxPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_url(), http_client=client)
        result = await plugin.query(_make_url(), None, ctx)

    assert len(result.entities) == 1


@pytest.mark.asyncio
async def test_dispatch_mode_is_async():
    assert WaybackCdxPlugin.dispatch_mode == "async"


@pytest.mark.asyncio
async def test_empty_label_returns_empty_result():
    plugin = WaybackCdxPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _make_domain(label="   ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.entities == []
    assert result.evidence == []
