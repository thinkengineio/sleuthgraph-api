"""ShodanPlugin -- BYOK host enrichment for IP_ADDRESS entities."""

import json
import uuid
from pathlib import Path

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.shodan import MAX_ENTITIES, ShodanPlugin
from sleuthgraph.relationships.types import RelationshipType

FIXTURE_DIR = Path(__file__).parent / "fixtures"
CREDS = {"api_key": "test-shodan-key-xyz789"}


def _entity(label: str) -> Entity:
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.IP_ADDRESS.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _transport(status: int = 200, body: bytes | None = None, fixture: str | None = None):
    if body is None and fixture is not None:
        body = (FIXTURE_DIR / fixture).read_bytes()
    if body is None:
        body = b"{}"

    def handler(request: httpx.Request) -> httpx.Response:
        # Verify API key is in query string
        assert "key=" in str(request.url)
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


# -- Happy path --


@pytest.mark.asyncio
async def test_extracts_hostnames_as_domain_entities():
    plugin = ShodanPlugin()
    transport = _transport(fixture="shodan_host.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    domain_entities = [e for e in result.entities if e.type == EntityType.DOMAIN]
    labels = {e.label for e in domain_entities}
    # hostnames: example.com, www.example.com
    # domains: example.com (dedup), example.org
    assert "example.com" in labels
    assert "www.example.com" in labels
    assert "example.org" in labels
    for e in domain_entities:
        assert e.attrs["discovered_via"] == "shodan"


@pytest.mark.asyncio
async def test_resolves_to_relationships_created():
    plugin = ShodanPlugin()
    transport = _transport(fixture="shodan_host.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    for r in result.relationships:
        assert r.rel_type == RelationshipType.RESOLVES_TO
        assert r.dst == {"input": True}
        assert r.src["ref"].startswith("host-")

    # One rel per entity
    assert len(result.relationships) == len(result.entities)


@pytest.mark.asyncio
async def test_deduplicates_hostnames_and_domains():
    """example.com appears in both hostnames and domains; should only produce one entity."""
    plugin = ShodanPlugin()
    transport = _transport(fixture="shodan_host.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    labels = [e.label for e in result.entities]
    assert labels.count("example.com") == 1


@pytest.mark.asyncio
async def test_evidence_carries_raw_response():
    plugin = ShodanPlugin()
    raw = (FIXTURE_DIR / "shodan_host.json").read_bytes()
    transport = _transport(body=raw)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.payload == raw
    assert ev.content_type == "application/json"
    assert "Shodan host lookup for 93.184.216.34" in ev.query
    assert ev.reproducibility_spec["method"] == "GET"


@pytest.mark.asyncio
async def test_evidence_contains_ports_and_vulns():
    plugin = ShodanPlugin()
    transport = _transport(fixture="shodan_host.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    spec = result.evidence[0].reproducibility_spec
    assert 80 in spec["open_ports"]
    assert 443 in spec["open_ports"]
    assert 8080 in spec["open_ports"]
    assert "CVE-2021-44228" in spec["vulns"]
    assert len(spec["services_summary"]) == 3
    assert spec["services_summary"][0]["product"] == "nginx"


# -- Credential leak prevention --


@pytest.mark.asyncio
async def test_evidence_url_does_not_contain_api_key():
    """SECURITY: API key must NOT leak into evidence reproducibility_spec URL."""
    plugin = ShodanPlugin()
    transport = _transport(fixture="shodan_host.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    spec = result.evidence[0].reproducibility_spec
    stored_url = spec["url"]
    assert CREDS["api_key"] not in stored_url
    assert "REDACTED" in stored_url


# -- Error handling --


@pytest.mark.asyncio
async def test_http_error_not_retried():
    """500 is not retried (retry predicate limited to transport/timeout errors)."""
    plugin = ShodanPlugin()
    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        return httpx.Response(500, content=b"server error")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(ent, CREDS, ctx)

    assert call_count["n"] == 1


# -- Empty results --


@pytest.mark.asyncio
async def test_empty_response_produces_no_entities():
    plugin = ShodanPlugin()
    transport = _transport(body=b'{"hostnames":[],"domains":[],"ports":[],"data":[]}')
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("10.0.0.1")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1


@pytest.mark.asyncio
async def test_empty_label_returns_empty_result():
    plugin = ShodanPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("   ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


# -- Credential access --


@pytest.mark.asyncio
async def test_credentials_api_key_used_in_url():
    """Verify the plugin reads api_key from credentials dict and passes it in query string."""
    plugin = ShodanPlugin()
    url_seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        url_seen["url"] = str(request.url)
        return httpx.Response(200, content=b'{"hostnames":[],"domains":[],"ports":[],"data":[]}')

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("1.2.3.4")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        await plugin.query(ent, {"api_key": "my-shodan-key"}, ctx)

    assert "key=my-shodan-key" in url_seen["url"]


# -- Cap at MAX_ENTITIES --


@pytest.mark.asyncio
async def test_cap_at_max_entities():
    """Entities are capped at MAX_ENTITIES and evidence marks truncated."""
    plugin = ShodanPlugin()
    hostnames = [f"host{i}.example.com" for i in range(MAX_ENTITIES + 10)]
    data = {"hostnames": hostnames, "domains": [], "ports": [], "data": []}
    transport = _transport(body=json.dumps(data).encode())
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("10.0.0.1")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert len(result.entities) == MAX_ENTITIES
    assert result.evidence[0].reproducibility_spec["truncated"] is True


# -- Plugin class attributes --

# -- Input validation (path/query injection prevention) --


@pytest.mark.asyncio
async def test_rejects_injected_path():
    """IP labels with '/' must be rejected before URL construction (CWE-74)."""
    plugin = ShodanPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("1.2.3.4/../../admin")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_query_param_injection():
    """IP label '1.2.3.4?key=evil' would inject a duplicate API key param."""
    plugin = ShodanPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("1.2.3.4?key=attacker_key&x=")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_fragment_in_ip():
    """IP with '#' fragment must be rejected."""
    plugin = ShodanPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity("1.2.3.4#frag")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


def test_plugin_class_attributes():
    plugin = ShodanPlugin()
    assert plugin.name == "shodan"
    assert plugin.version == "0.1.0"
    assert plugin.requires_credentials is True
    assert plugin.credential_name == "shodan"
    assert plugin.entity_types_accepted == [EntityType.IP_ADDRESS]
    assert plugin.entity_types_produced == [EntityType.DOMAIN]
