"""urlhaus plugin: URL|DOMAIN → malware hit evidence."""

import json
import uuid

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.urlhaus import UrlhausPlugin


def _entity(type_, label):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=type_.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _transport(status=200, body=b'{"query_status":"no_results"}'):
    def handler(request):
        assert request.method == "POST"
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_url_hit_marks_malicious_true():
    body = json.dumps(
        {
            "query_status": "ok",
            "url_info": {
                "threat": "malware_download",
                "date_added": "2024-01-01",
                "tags": ["emotet"],
            },
        }
    ).encode()
    plugin = UrlhausPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.URL, "http://bad.example.com/bin")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert result.entities == []
    assert len(result.evidence) == 1
    spec = result.evidence[0].reproducibility_spec
    assert spec["malicious"] is True
    assert spec["query_status"] == "ok"


@pytest.mark.asyncio
async def test_domain_no_results_malicious_false():
    plugin = UrlhausPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.evidence[0].reproducibility_spec["malicious"] is False


@pytest.mark.asyncio
async def test_url_endpoint_used_for_url_input():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, content=b'{"query_status":"no_results"}')

    plugin = UrlhausPlugin()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ent = _entity(EntityType.URL, "http://x.test/")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        await plugin.query(ent, None, ctx)
    assert "/url/" in captured["url"]


@pytest.mark.asyncio
async def test_host_endpoint_used_for_domain_input():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, content=b'{"query_status":"no_results"}')

    plugin = UrlhausPlugin()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        await plugin.query(ent, None, ctx)
    assert "/host/" in captured["url"]


@pytest.mark.asyncio
async def test_empty_label_empty_result():
    plugin = UrlhausPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.URL, "  ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.evidence == []
