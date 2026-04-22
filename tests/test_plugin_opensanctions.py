"""opensanctions plugin: PERSON|ORGANIZATION → sanctions evidence."""

import json
import uuid

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.opensanctions import OpenSanctionsPlugin


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
async def test_person_hit_produces_evidence_with_matched_true():
    body = json.dumps(
        {
            "results": [
                {
                    "id": "ofac-1",
                    "caption": "John Doe",
                    "schema": "Person",
                    "datasets": ["us_ofac_sdn"],
                }
            ],
            "total": {"value": 1},
        }
    ).encode()
    plugin = OpenSanctionsPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.PERSON, "John Doe")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    # No new entities (evidence-only plugin)
    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.reproducibility_spec["matched"] is True
    assert ev.reproducibility_spec["hit_count"] == 1


@pytest.mark.asyncio
async def test_no_hits_matched_false():
    body = json.dumps({"results": [], "total": {"value": 0}}).encode()
    plugin = OpenSanctionsPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.ORGANIZATION, "Definitely Clean Co")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.evidence[0].reproducibility_spec["matched"] is False
    assert result.evidence[0].reproducibility_spec["hit_count"] == 0


@pytest.mark.asyncio
async def test_empty_label_returns_empty_result():
    plugin = OpenSanctionsPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.PERSON, "   ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_evidence_reproducibility_has_url_and_method():
    plugin = OpenSanctionsPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.PERSON, "Acme")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    spec = result.evidence[0].reproducibility_spec
    assert "opensanctions.org" in spec["url"]
    assert spec["method"] == "GET"
    assert "queried_at" in spec
