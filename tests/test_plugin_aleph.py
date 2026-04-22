"""aleph_occrp plugin: PERSON|ORGANIZATION → Aleph hits evidence."""

import json
import uuid

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.aleph_occrp import AlephOccrpPlugin


def _entity(type_, label):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=type_.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _transport(status=200, body=b'{"results":[]}'):
    def handler(request):
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_hit_produces_evidence():
    body = json.dumps(
        {
            "results": [
                {"id": "doc-1", "schema": "Document", "properties": {"title": ["leak"]}},
                {"id": "ent-1", "schema": "Person", "properties": {"name": ["Suspect"]}},
            ],
            "total": 2,
        }
    ).encode()
    plugin = AlephOccrpPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.PERSON, "Suspect")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1
    spec = result.evidence[0].reproducibility_spec
    assert spec["hit_count"] == 2
    assert spec["matched"] is True


@pytest.mark.asyncio
async def test_no_hits_matched_false():
    plugin = AlephOccrpPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.ORGANIZATION, "Clean")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.evidence[0].reproducibility_spec["matched"] is False


@pytest.mark.asyncio
async def test_empty_label_empty_result():
    plugin = AlephOccrpPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.PERSON, "")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.evidence == []


@pytest.mark.asyncio
async def test_url_points_at_aleph_occrp():
    plugin = AlephOccrpPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.PERSON, "X")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert "aleph.occrp.org" in result.evidence[0].reproducibility_spec["url"]
