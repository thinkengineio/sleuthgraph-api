"""opencorporates plugin: PERSON|ORGANIZATION → ORGANIZATION matches."""

import json
import uuid

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.opencorporates import (
    MAX_MATCHES,
    OpenCorporatesPlugin,
)


def _entity(type_, label):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=type_.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _body(companies):
    return json.dumps(
        {
            "results": {
                "companies": [{"company": c} for c in companies],
            }
        }
    ).encode()


def _transport(status=200, body=b'{"results":{"companies":[]}}'):
    def handler(request):
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_org_search_yields_organization_entities():
    body = _body(
        [
            {
                "name": "Acme Inc",
                "company_number": "1234",
                "jurisdiction_code": "us_de",
                "current_status": "Active",
                "opencorporates_url": "https://opencorporates.com/companies/us_de/1234",
            },
            {
                "name": "Acme LLC",
                "company_number": "5678",
                "jurisdiction_code": "gb",
                "current_status": "Dissolved",
                "opencorporates_url": "https://opencorporates.com/companies/gb/5678",
            },
        ]
    )
    plugin = OpenCorporatesPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.ORGANIZATION, "Acme")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert len(result.entities) == 2
    assert {e.type for e in result.entities} == {EntityType.ORGANIZATION}
    assert {e.label for e in result.entities} == {"Acme Inc", "Acme LLC"}
    first = next(e for e in result.entities if e.label == "Acme Inc")
    assert first.attrs["jurisdiction"] == "us_de"
    assert first.attrs["company_number"] == "1234"
    assert first.attrs["status"] == "Active"
    assert first.attrs["discovered_via"] == "opencorporates"
    assert first.confidence == 0.6
    # No relationships (plugin proposes entities + evidence only)
    assert result.relationships == []


@pytest.mark.asyncio
async def test_person_input_accepted():
    body = _body(
        [
            {
                "name": "Jane Doe Holdings",
                "company_number": "1",
                "jurisdiction_code": "us_ny",
                "current_status": "Active",
            },
        ]
    )
    plugin = OpenCorporatesPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.PERSON, "Jane Doe")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert len(result.entities) == 1


@pytest.mark.asyncio
async def test_empty_query_returns_empty_result():
    plugin = OpenCorporatesPlugin()
    async with httpx.AsyncClient(transport=_transport()) as client:
        ent = _entity(EntityType.ORGANIZATION, "  ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_cap_at_max_matches():
    body = _body(
        [
            {
                "name": f"Co {i}",
                "company_number": str(i),
                "jurisdiction_code": "us_de",
                "current_status": "Active",
            }
            for i in range(MAX_MATCHES + 5)
        ]
    )
    plugin = OpenCorporatesPlugin()
    async with httpx.AsyncClient(transport=_transport(body=body)) as client:
        ent = _entity(EntityType.ORGANIZATION, "Co")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert len(result.entities) == MAX_MATCHES
    assert result.evidence[0].reproducibility_spec["truncated"] is True


@pytest.mark.asyncio
async def test_malformed_json_empty_entities_but_evidence_present():
    plugin = OpenCorporatesPlugin()
    async with httpx.AsyncClient(transport=_transport(body=b"not json")) as client:
        ent = _entity(EntityType.ORGANIZATION, "Acme")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.entities == []
    assert len(result.evidence) == 1


@pytest.mark.asyncio
async def test_evidence_reproducibility_has_url_and_method():
    plugin = OpenCorporatesPlugin()
    async with httpx.AsyncClient(transport=_transport(body=_body([]))) as client:
        ent = _entity(EntityType.ORGANIZATION, "Acme")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    spec = result.evidence[0].reproducibility_spec
    assert "opencorporates.com" in spec["url"]
    assert spec["method"] == "GET"
